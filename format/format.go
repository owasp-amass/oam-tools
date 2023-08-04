// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package format

import (
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/owasp-amass/open-asset-model/network"
)

const (
	// Version is used to display the current version of Amass.
	Version = "v0.1.0"

	// Author is used to display the Amass Project Team.
	Author = "OWASP Open Asset Model - @owaspamass"

	// Description is the slogan for the Amass Project.
	Description = "In-depth Attack Surface Mapping and Asset Discovery"
)

var (
	Yellow = color.New(color.FgHiYellow).SprintFunc()
	Green  = color.New(color.FgHiGreen).SprintFunc()
	Blue   = color.New(color.FgHiBlue).SprintFunc()
	B      = color.New(color.FgHiBlue)
)

// Define a struct to hold RIR organization name and a slice of CIDRs.
type ASNInfo struct {
	RIRName string
	CIDRs   map[netip.Prefix]int
}

// FprintEnumerationSummary outputs the summary information utilized by the command-line tools.
func FprintEnumerationSummary(out io.Writer, total int, asns map[int]*ASNInfo, demo bool) {
	pad := func(num int, chr string) {
		for i := 0; i < num; i++ {
			B.Fprint(out, chr)
		}
	}

	fmt.Fprintln(out)
	// Print the header information
	title := "OWASP OAM Tool Suite "
	site := "https://github.com/owasp-amass/oam-tools"
	B.Fprint(out, title+Version)
	num := 80 - (len(title) + len(Version) + len(site))
	pad(num, " ")
	B.Fprintf(out, "%s\n", site)
	pad(8, "----------")
	fmt.Fprintf(out, "\n%s%s", Yellow(strconv.Itoa(total)), Green(" names discovered"))
	fmt.Fprintln(out)

	if len(asns) == 0 {
		return
	}
	// Another line gets printed
	pad(8, "----------")
	fmt.Fprintln(out)
	// Print the ASN and netblock information
	for asn, data := range asns {
		asnstr := strconv.Itoa(asn)
		datastr := data.RIRName // Using RIRName instead of Name

		if demo && asn > 0 {
			asnstr = censorString(asnstr, 0, len(asnstr))
			datastr = censorString(datastr, 0, len(datastr))
		}
		fmt.Fprintf(out, "%s%s %s %s\n", Blue("ASN: "), Yellow(asnstr), Green("-"), Green(datastr))

		for cidr, ips := range data.CIDRs { // Using CIDRs instead of Netblocks
			countstr := strconv.Itoa(ips)
			cidrstr := cidr.String() // Assuming netip.Prefix has a String method

			if demo {
				cidrstr = censorNetBlock(cidrstr)
			}

			countstr = fmt.Sprintf("\t%-4s", countstr)
			cidrstr = fmt.Sprintf("\t%-18s", cidrstr)
			fmt.Fprintf(out, "%s%s %s\n", Yellow(cidrstr), Yellow(countstr), Blue("Subdomain Name(s)"))
		}
	}
}

func censorDomain(input string) string {
	return censorString(input, strings.Index(input, "."), len(input))
}

func censorIP(input string) string {
	return censorString(input, 0, strings.LastIndex(input, "."))
}

func censorNetBlock(input string) string {
	return censorString(input, 0, strings.Index(input, "/"))
}

func censorString(input string, start, end int) string {
	runes := []rune(input)
	for i := start; i < end; i++ {
		if runes[i] == '.' ||
			runes[i] == '/' ||
			runes[i] == '-' ||
			runes[i] == ' ' {
			continue
		}
		runes[i] = 'x'
	}
	return string(runes)
}

func OutputLineParts(name string, ipAddrs []network.IPAddress, demo bool) (formattedName, ips string) {
	if len(ipAddrs) > 0 {
		for i, a := range ipAddrs {
			if i != 0 {
				ips += ","
			}
			if demo {
				ips += censorIP(a.Address.String())
			} else {
				ips += a.Address.String()
			}
		}
	}
	formattedName = name
	if demo {
		formattedName = censorDomain(formattedName)
	}
	return
}
