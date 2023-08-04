// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// oam_subs: Analyze collected OAM subdomains
//
//	+----------------------------------------------------------------------------+
//	| ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  OWASP Amass  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ |
//	+----------------------------------------------------------------------------+
//	|      .+++:.            :                             .+++.                 |
//	|    +W@@@@@@8        &+W@#               o8W8:      +W@@@@@@#.   oW@@@W#+   |
//	|   &@#+   .o@##.    .@@@o@W.o@@o       :@@#&W8o    .@#:  .:oW+  .@#+++&#&   |
//	|  +@&        &@&     #@8 +@W@&8@+     :@W.   +@8   +@:          .@8         |
//	|  8@          @@     8@o  8@8  WW    .@W      W@+  .@W.          o@#:       |
//	|  WW          &@o    &@:  o@+  o@+   #@.      8@o   +W@#+.        +W@8:     |
//	|  #@          :@W    &@+  &@+   @8  :@o       o@o     oW@@W+        oW@8    |
//	|  o@+          @@&   &@+  &@+   #@  &@.      .W@W       .+#@&         o@W.  |
//	|   WW         +@W@8. &@+  :&    o@+ #@      :@W&@&         &@:  ..     :@o  |
//	|   :@W:      o@# +Wo &@+        :W: +@W&o++o@W. &@&  8@#o+&@W.  #@:    o@+  |
//	|    :W@@WWWW@@8       +              :&W@@@@&    &W  .o#@@W&.   :W@WWW@@&   |
//	|      +o&&&&+.                                                    +oooo.    |
//	+----------------------------------------------------------------------------+
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/caffix/netmap"
	"github.com/caffix/stringset"
	"github.com/fatih/color"
	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/config/config"
	"github.com/owasp-amass/oam-tools/format"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"
)

const (
	dbUsageMsg = "db [options]"
)

var (
	g = color.New(color.FgHiGreen)
	r = color.New(color.FgHiRed)
)

type dbArgs struct {
	Domains *stringset.Set
	Enum    int
	Options struct {
		DemoMode        bool
		IPs             bool
		IPv4            bool
		IPv6            bool
		ASNTableSummary bool
		DiscoveredNames bool
		NoColor         bool
		ShowAll         bool
		Silent          bool
	}
	Filepaths struct {
		ConfigFile string
		Directory  string
		Domains    string
		TermOut    string
	}
}

func main() {
	var args dbArgs
	var help1, help2 bool
	dbCommand := flag.NewFlagSet("db", flag.ContinueOnError)

	args.Domains = stringset.New()
	defer args.Domains.Close()

	dbBuf := new(bytes.Buffer)
	dbCommand.SetOutput(dbBuf)

	dbCommand.BoolVar(&help1, "h", false, "Show the program usage message")
	dbCommand.BoolVar(&help2, "help", false, "Show the program usage message")
	dbCommand.Var(args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	dbCommand.BoolVar(&args.Options.DemoMode, "demo", false, "Censor output to make it suitable for demonstrations")
	dbCommand.BoolVar(&args.Options.IPs, "ip", false, "Show the IP addresses for discovered names")
	dbCommand.BoolVar(&args.Options.IPv4, "ipv4", false, "Show the IPv4 addresses for discovered names")
	dbCommand.BoolVar(&args.Options.IPv6, "ipv6", false, "Show the IPv6 addresses for discovered names")
	dbCommand.BoolVar(&args.Options.ASNTableSummary, "summary", false, "Print Just ASN Table Summary")
	dbCommand.BoolVar(&args.Options.DiscoveredNames, "names", false, "Print Just Discovered Names")
	dbCommand.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	dbCommand.BoolVar(&args.Options.ShowAll, "show", false, "Print the results for the enumeration index + domains provided")
	dbCommand.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")
	dbCommand.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the YAML configuration file. Additional details below")
	dbCommand.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the graph database")
	dbCommand.StringVar(&args.Filepaths.Domains, "df", "", "Path to a file providing root domain names")
	dbCommand.StringVar(&args.Filepaths.TermOut, "o", "", "Path to the text file containing terminal stdout/stderr")

	var usage = func() {
		g.Fprintf(color.Error, "Usage: %s %s\n\n", path.Base(os.Args[0]), dbUsageMsg)
		dbCommand.PrintDefaults()
		g.Fprintln(color.Error, dbBuf.String())
	}

	if len(os.Args) < 2 {
		usage()
		return
	}
	if err := dbCommand.Parse(os.Args[1:]); err != nil {
		r.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if help1 || help2 {
		usage()
		return
	}
	if args.Options.NoColor {
		color.NoColor = true
	}
	if args.Options.Silent {
		color.Output = io.Discard
		color.Error = io.Discard
	}
	if args.Options.IPs {
		args.Options.IPv4 = true
		args.Options.IPv6 = true
	}
	if args.Filepaths.Domains != "" {
		list, err := config.GetListFromFile(args.Filepaths.Domains)
		if err != nil {
			r.Fprintf(color.Error, "Failed to parse the domain names file: %v\n", err)
			return
		}
		args.Domains.InsertMany(list...)
	}

	cfg := config.NewConfig()
	// Check if a configuration file was provided, and if so, load the settings
	if err := config.AcquireConfig(args.Filepaths.Directory, args.Filepaths.ConfigFile, cfg); err == nil {
		if args.Filepaths.Directory == "" {
			args.Filepaths.Directory = cfg.Dir
		}
		if args.Domains.Len() == 0 {
			args.Domains.InsertMany(cfg.Domains()...)
		}
	} else if args.Filepaths.ConfigFile != "" {
		r.Fprintf(color.Error, "Failed to load the configuration file: %v\n", err)
		os.Exit(1)
	}

	db := openGraphDatabase(args.Filepaths.Directory, cfg)
	if db == nil {
		r.Fprintln(color.Error, "Failed to connect with the database")
		os.Exit(1)
	}

	if args.Options.ShowAll {
		args.Options.DiscoveredNames = true
		args.Options.ASNTableSummary = true
	}
	if !args.Options.DiscoveredNames && !args.Options.ASNTableSummary {
		usage()
		return
	}

	var asninfo bool
	if args.Options.ASNTableSummary {
		asninfo = true
	}

	showEventData(&args, asninfo, db)
}

func showEventData(args *dbArgs, asninfo bool, db *netmap.Graph) {

	var err error
	var outfile *os.File
	subdomainCount := 0

	if args.Filepaths.TermOut != "" {
		outfile, err = os.OpenFile(args.Filepaths.TermOut, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			r.Fprintf(color.Error, "Failed to open the text output file: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			_ = outfile.Sync()
			_ = outfile.Close()
		}()
		_ = outfile.Truncate(0)
		_, _ = outfile.Seek(0, 0)
	}

	// 1. Extract domain names to search for
	domains := args.Domains.Slice()
	var asset *types.Asset

	// 2. Create necessary instances
	ctx := context.Background()

	// Use a map to relate ASN numbers to ASNInfo.
	asnData := make(map[int]*format.ASNInfo)

	// 3. Find the assets
	assetMap, err := EventOutputWithAssets(args, ctx, db, domains, time.Time{}, asninfo)
	if err != nil {
		r.Fprintf(color.Error, "Failed to find assets for domains: %v\n", err)
		return
	}

	// 4. Iterate over assets to get IP addresses, netblocks, and ASNs
	for domain, assets := range assetMap {

		// Ensure that the asset is a FQDN
		if domain != "" {

			subdomainCount++

			ipAddresses := make([]network.IPAddress, 0)
			// If any of the two options are enabled, proceed with the loop
			if args.Options.IPv4 || args.Options.IPv6 {

				for _, asset = range assets {
					ipAddress, ok := asset.Asset.(network.IPAddress)
					if !ok {
						log.Printf("Unexpected asset type here: %T", asset.Asset)
						continue
					}

					ipAddresses = append(ipAddresses, ipAddress)

					// Call handleNetblock
					netblocks, err := handleNetblock(asset, db)
					if err != nil {
						r.Fprintf(color.Error, "Failed to handle Netblock for IP: %v\n", err)
						continue
					}
					for _, netblock := range netblocks {
						asnData, err = handleASN(netblock, db, asnData)
						if err != nil {
							r.Fprintf(color.Error, "Failed to handle ASN for netblock: %v\n", err)
							continue
						}
					}
				}
			}

			if args.Options.DiscoveredNames {
				formattedName, ips := format.OutputLineParts(domain, ipAddresses, args.Options.DemoMode)
				if outfile != nil {
					fmt.Fprintf(outfile, "%s%s\n", formattedName, ips)
					continue
				}
				// Use OutputLineParts to format the domain and related IPs
				// Print the FQDN and related IPs in a single line
				fmt.Fprintf(color.Output, "%s %s\n", format.Green(formattedName), format.Yellow(ips))
			}
		}
	}
	// check if asninfo is true
	if asninfo {
		var out io.Writer

		if outfile != nil {
			out = outfile
			color.NoColor = true
		} else if args.Options.ShowAll {
			out = color.Error
		} else {
			out = color.Output
		}
		// Call the PrintEnumerationSummary function
		format.FprintEnumerationSummary(out, subdomainCount, asnData, args.Options.DemoMode)
	}
}

func openGraphDatabase(dir string, cfg *config.Config) *netmap.Graph {
	// Add the local database settings to the configuration
	cfg.GraphDBs = append(cfg.GraphDBs, cfg.LocalDatabaseSettings(cfg.GraphDBs))

	for _, db := range cfg.GraphDBs {
		if db.Primary {
			var g *netmap.Graph

			if db.System == "local" {
				g = netmap.NewGraph(db.System, filepath.Join(config.OutputDirectory(cfg.Dir), "amass.sqlite"), db.Options)
			} else {
				connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s", db.Host, db.Port, db.Username, db.Password, db.DBName)
				g = netmap.NewGraph(db.System, connStr, db.Options)
			}

			if g != nil {
				return g
			}
			break
		}
	}

	return netmap.NewGraph("memory", "", "")
}

func handleNetblock(ipAsset *types.Asset, db *netmap.Graph) ([]*types.Asset, error) {
	var netblockAssets []*types.Asset

	// Get incoming relations for the IP address asset (to get Netblock)
	netblockRelations, err := db.DB.IncomingRelations(ipAsset, time.Time{}, "contains")
	if err != nil {
		return nil, err
	}

	for _, netblockRelation := range netblockRelations {
		netblockAsset := netblockRelation.FromAsset
		netblockAsset, _ = db.DB.FindById(netblockAsset.ID, time.Time{})
		_, ok := netblockAsset.Asset.(network.Netblock)
		if !ok {
			fmt.Printf("Unexpected type: %T\n", netblockAsset.Asset)
			continue
		}

		netblockAssets = append(netblockAssets, netblockAsset)
	}

	return netblockAssets, nil
}

func handleASN(netblockAsset *types.Asset, db *netmap.Graph, asnData map[int]*format.ASNInfo) (map[int]*format.ASNInfo, error) {
	// Get incoming relations for the Netblock asset (to get ASN)
	asnRelations, err := db.DB.IncomingRelations(netblockAsset, time.Time{}, "announces")
	if err != nil {
		return nil, err
	}

	for _, asnRelation := range asnRelations {
		asnAsset := asnRelation.FromAsset
		asnAsset, _ = db.DB.FindById(asnAsset.ID, time.Time{})
		asn, ok := asnAsset.Asset.(network.AutonomousSystem)
		if !ok {
			fmt.Printf("Unexpected type: %T\n", asnAsset.Asset)
			continue
		}

		asnInfo, ok := asnData[asn.Number]
		if !ok {
			// If the ASN number is not yet in the map, create a new ASNInfo for it.
			asnInfo = &format.ASNInfo{
				CIDRs: make(map[netip.Prefix]int),
			}
		}

		// Add CIDR to the ASNInfo's CIDR map.
		asnInfo.CIDRs[netblockAsset.Asset.(network.Netblock).Cidr]++

		// Get incoming relations for the ASN asset (to get RIROrganization)
		rirRelations, err := db.DB.OutgoingRelations(asnAsset, time.Time{}, "managed_by")
		if err != nil {
			return nil, err
		}

		for _, rirRelation := range rirRelations {
			rirAsset := rirRelation.ToAsset
			rirAsset, err = db.DB.FindById(rirAsset.ID, time.Time{})
			if err != nil {
				return nil, err
			}

			rirOrg, ok := rirAsset.Asset.(network.RIROrganization)
			if !ok {
				fmt.Printf("Unexpected type: %T\n", rirAsset.Asset)
				continue
			}

			// Add RIR name to ASNInfo.
			asnInfo.RIRName = rirOrg.Name

			if asn.Number == 0 {
				break
			}
		}
		// Put the updated ASNInfo back in the map.
		asnData[asn.Number] = asnInfo
	}

	return asnData, nil
}

func EventOutputWithAssets(args *dbArgs, ctx context.Context, g *netmap.Graph, domains []string, since time.Time, asninfo bool) (map[string][]*types.Asset, error) {
	if len(domains) == 0 {
		return nil, nil
	}

	var fqdns []oam.Asset
	for _, d := range domains {
		fqdns = append(fqdns, domain.FQDN{Name: d})
	}

	qtime := time.Time{}
	if !since.IsZero() {
		qtime = since.UTC()
	}

	assets, err := g.DB.FindByScope(fqdns, qtime)
	if err != nil {
		return nil, err
	}

	var names []string
	for _, a := range assets {
		if n, ok := a.Asset.(domain.FQDN); ok {
			names = append(names, n.Name)
		}
	}

	assetMap := make(map[string][]*types.Asset)
	if pairs, err := g.NamesToAddrs(ctx, qtime, names...); err == nil {
		for _, p := range pairs {
			addr := p.Addr.Address.String()

			if p.FQDN.Name == "" || addr == "" {
				continue
			}

			ipAsset := &network.IPAddress{
				Address: p.Addr.Address,
				Type:    p.Addr.Type,
			}

			// If neither IP type is desired, initialize all domains in the map with an empty slice
			if !args.Options.IPv4 && !args.Options.IPv6 {
				if _, found := assetMap[p.FQDN.Name]; !found {
					assetMap[p.FQDN.Name] = []*types.Asset{} // Initialize with an empty slice
				}
				continue // Skip the rest of this iteration since we don't care about the IP type
			}

			// If IP types have been specified, only process matching types
			if ipAsset.Type == "IPv4" && !args.Options.IPv4 || ipAsset.Type == "IPv6" && !args.Options.IPv6 {
				continue
			}

			// Find the Asset ID using FindByContent
			foundAssets, err := g.DB.FindByContent(ipAsset, since)
			if err != nil || len(foundAssets) == 0 {
				// Handle error or case where no asset is found
				continue
			}

			// Add the domain key to the map if it contains at least one matching IP
			if _, found := assetMap[p.FQDN.Name]; !found {
				assetMap[p.FQDN.Name] = []*types.Asset{} // Initialize with an empty slice
			}
			assetMap[p.FQDN.Name] = append(assetMap[p.FQDN.Name], foundAssets...)
		}
	}

	return assetMap, nil
}
