// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package viz

import (
	"strings"
	"time"

	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/graph"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/owasp-amass/open-asset-model/source"
)

// Edge represents an Amass graph edge in the viz package.
type Edge struct {
	From, To int
	Label    string
	Title    string
}

// Node represents an Amass graph node in the viz package.
type Node struct {
	ID    int
	Type  string
	Label string
	Title string
}

// VizData returns the current state of the Graph as viz package Nodes and Edges.
func VizData(domains []string, since time.Time, g *graph.Graph) ([]Node, []Edge) {
	if len(domains) == 0 {
		return []Node{}, []Edge{}
	}

	var fqdns []oam.Asset
	for _, d := range domains {
		fqdns = append(fqdns, &domain.FQDN{Name: d})
	}

	if !since.IsZero() {
		since = since.UTC()
	}

	next, err := g.DB.FindByScope(fqdns, since)
	if err != nil {
		return []Node{}, []Edge{}
	}

	var idx int
	var nodes []Node
	var edges []Edge
	nodeToIdx := make(map[string]int)
	for {
		if len(next) == 0 {
			break
		}

		var assets []*types.Asset
		assets = append(assets, next...)
		next = []*types.Asset{}

		for _, a := range assets {
			n := newNode(g.DB, idx, a, since)
			if n == nil {
				continue
			}
			// Keep track of which indices nodes were assigned to
			id := idx
			if nid, found := nodeToIdx[n.Label]; !found {
				idx++
				nodeToIdx[n.Label] = id
				nodes = append(nodes, *n)
			} else {
				id = nid
			}
			// Determine relationship directions to follow on the graph
			var in, out bool
			var inRels, outRels []string
			switch a.Asset.AssetType() {
			case oam.FQDN:
				out = true
				if domainNameInScope(n.Label, domains) {
					in = true
				}
			case oam.IPAddress:
				in = true
				inRels = append(inRels, "contains")
				out = true
			case oam.Netblock:
				in = true
				inRels = append(inRels, "announces")
			case oam.AutonomousSystem:
				out = true
				outRels = append(outRels, "registration")
			case oam.AutnumRecord:
				out = true
			case oam.SocketAddress:
				out = true
			case oam.NetworkEndpoint:
				out = true
			case oam.ContactRecord:
				out = true
			case oam.EmailAddress:
				out = true
			case oam.Location:
				out = true
			case oam.Phone:
				out = true
			case oam.Fingerprint:
			case oam.Organization:
				out = true
			case oam.Person:
				out = true
			case oam.TLSCertificate:
				out = true
			case oam.URL:
				out = true
			case oam.DomainRecord:
				out = true
			case oam.Source:
			case oam.Service:
				out = true
			default:
			}
			// Obtain relations to additional assets in the graph
			if out {
				if rels, err := g.DB.OutgoingRelations(a, since, outRels...); err == nil && len(rels) > 0 {
					fromID := id
					for _, rel := range rels {
						if to, err := g.DB.FindById(rel.ToAsset.ID, since); err == nil {
							toID := idx
							n2 := newNode(g.DB, toID, to, since)
							if n2 == nil {
								continue
							}

							if id, found := nodeToIdx[n2.Label]; !found {
								idx++
								nodeToIdx[n2.Label] = toID
								nodes = append(nodes, *n2)
								next = append(next, to)
							} else {
								toID = id
							}

							edges = append(edges, Edge{
								From:  fromID,
								To:    toID,
								Label: rel.Type,
								Title: rel.Type,
							})
						}
					}
				}
			}
			if in {
				if rels, err := g.DB.IncomingRelations(a, since, inRels...); err == nil && len(rels) > 0 {
					toID := id
					for _, rel := range rels {
						if from, err := g.DB.FindById(rel.FromAsset.ID, since); err == nil {
							fromID := idx
							n2 := newNode(g.DB, fromID, from, since)
							if n2 == nil {
								continue
							}

							if id, found := nodeToIdx[n2.Label]; !found {
								idx++
								nodeToIdx[n2.Label] = fromID
								nodes = append(nodes, *n2)
								if rel.Type != "ptr_record" {
									next = append(next, from)
								}
							} else {
								fromID = id
							}

							edges = append(edges, Edge{
								From:  fromID,
								To:    toID,
								Label: rel.Type,
								Title: rel.Type,
							})
						}
					}
				}
			}
		}
	}
	return nodes, edges
}

func newNode(db *assetdb.AssetDB, idx int, a *types.Asset, since time.Time) *Node {
	if a == nil || a.Asset == nil {
		return nil
	}
	asset := a.Asset

	key := asset.Key()
	if key == "" {
		return nil
	}

	atype := string(asset.AssetType())
	if atype == string(oam.Source) {
		return nil
	}

	var check bool
	switch v := asset.(type) {
	case *oamreg.AutnumRecord:
		key = v.Handle + " - " + key
	case *contact.ContactRecord:
		key = "Found->" + key
	case *contact.Location:
		parts := []string{v.BuildingNumber, v.StreetName, v.City, v.Province, v.PostalCode}
		key = strings.Join(parts, " ")
	case *oamreg.DomainRecord:
		key = "WHOIS: " + key
	case *oamcert.TLSCertificate:
		key = "x509 Serial Number: " + v.SerialNumber
	case *domain.NetworkEndpoint:
		check = true
	case *network.SocketAddress:
		check = true
	case *source.Source:
		return nil
	}
	title := atype + ": " + key

	if check {
		if rels, err := db.OutgoingRelations(a, since, "service"); err != nil || len(rels) == 0 {
			return nil
		}
	}
	return &Node{
		ID:    idx,
		Type:  atype,
		Label: key,
		Title: title,
	}
}

func domainNameInScope(name string, scope []string) bool {
	var discovered bool

	n := strings.ToLower(strings.TrimSpace(name))
	for _, d := range scope {
		d = strings.ToLower(d)

		if n == d || strings.HasSuffix(n, "."+d) {
			discovered = true
			break
		}
	}

	return discovered
}
