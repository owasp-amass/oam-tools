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
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/caffix/netmap"
	"github.com/caffix/stringset"
	"github.com/fatih/color"
	"github.com/owasp-amass/config/config"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"
)

const (
	dbUsageMsg = "[options]"
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

type outLookup map[string]*Output

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

	db := openGraphDatabase(cfg)
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

	showData(&args, asninfo, db)
}

func showData(args *dbArgs, asninfo bool, db *netmap.Graph) {
	var total int
	var err error
	var outfile *os.File
	domains := args.Domains.Slice()

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

	var cache *ASNCache
	if asninfo {
		cache = NewASNCache()
		if err := fillCache(cache, db); err != nil {
			r.Printf("Failed to populate the ASN cache: %v\n", err)
			return
		}
	}

	names := getNames(context.Background(), domains, asninfo, db)
	if len(names) != 0 && (asninfo || args.Options.IPv4 || args.Options.IPv6) {
		names = addAddresses(context.Background(), db, names, asninfo, cache)
	}

	asns := make(map[int]*ASNSummaryData)
	for _, out := range names {
		if len(domains) > 0 && !domainNameInScope(out.Name, domains) {
			continue
		}

		if args.Options.IPv4 || args.Options.IPv6 {
			out.Addresses = DesiredAddrTypes(out.Addresses, args.Options.IPv4, args.Options.IPv6)
		}

		if l := len(out.Addresses); (args.Options.IPv4 || args.Options.IPv6) && l == 0 {
			continue
		} else if l > 0 {
			UpdateSummaryData(out, asns)
		}

		total++
		name, ips := OutputLineParts(out, args.Options.IPv4 || args.Options.IPv6, args.Options.DemoMode)
		if ips != "" {
			ips = " " + ips
		}

		if args.Options.DiscoveredNames {
			var written bool
			if outfile != nil {
				fmt.Fprintf(outfile, "%s%s\n", name, ips)
				written = true
			}
			if !written {
				fmt.Fprintf(color.Output, "%s%s\n", green(name), yellow(ips))
			}
		}
	}

	if total == 0 {
		r.Println("No names were discovered")
		return
	}
	if args.Options.ASNTableSummary {
		var out io.Writer
		status := color.NoColor

		if outfile != nil {
			out = outfile
			color.NoColor = true
		} else if args.Options.ShowAll {
			out = color.Error
		} else {
			out = color.Output
		}

		FprintEnumerationSummary(out, total, asns, args.Options.DemoMode)
		color.NoColor = status
	}
}

func openGraphDatabase(cfg *config.Config) *netmap.Graph {
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

func getNames(ctx context.Context, domains []string, asninfo bool, g *netmap.Graph) []*Output {
	if len(domains) == 0 {
		return nil
	}

	qtime := time.Time{}
	filter := stringset.New()
	defer filter.Close()

	var fqdns []oam.Asset
	for _, d := range domains {
		fqdns = append(fqdns, domain.FQDN{Name: d})
	}

	assets, err := g.DB.FindByScope(fqdns, qtime)
	if err != nil {
		return nil
	}

	var names []*Output
	for _, a := range assets {
		if n, ok := a.Asset.(domain.FQDN); ok && !filter.Has(n.Name) {
			names = append(names, &Output{Name: n.Name})
			filter.Insert(n.Name)
		}
	}
	return names
}

func addAddresses(ctx context.Context, g *netmap.Graph, names []*Output, asninfo bool, cache *ASNCache) []*Output {
	var namestrs []string
	lookup := make(outLookup, len(names))
	for _, n := range names {
		lookup[n.Name] = n
		namestrs = append(namestrs, n.Name)
	}

	qtime := time.Time{}
	if pairs, err := g.NamesToAddrs(ctx, qtime, namestrs...); err == nil {
		for _, p := range pairs {
			addr := p.Addr.Address.String()

			if p.FQDN.Name == "" || addr == "" {
				continue
			}
			if o, found := lookup[p.FQDN.Name]; found {
				o.Addresses = append(o.Addresses, AddressInfo{Address: net.ParseIP(addr)})
			}
		}
	}

	if !asninfo || cache == nil {
		var output []*Output
		for _, o := range lookup {
			if len(o.Addresses) > 0 {
				output = append(output, o)
			}
		}
		return output
	}
	return addInfrastructureInfo(lookup, cache)
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

func addInfrastructureInfo(lookup outLookup, cache *ASNCache) []*Output {
	output := make([]*Output, 0, len(lookup))

	for _, o := range lookup {
		var newaddrs []AddressInfo

		for _, a := range o.Addresses {
			i := cache.AddrSearch(a.Address.String())
			if i == nil {
				continue
			}

			_, netblock, _ := net.ParseCIDR(i.Prefix)
			newaddrs = append(newaddrs, AddressInfo{
				Address:     a.Address,
				ASN:         i.ASN,
				CIDRStr:     i.Prefix,
				Netblock:    netblock,
				Description: i.Description,
			})
		}

		o.Addresses = newaddrs
		if len(o.Addresses) > 0 {
			output = append(output, o)
		}
	}
	return output
}

func fillCache(cache *ASNCache, db *netmap.Graph) error {
	start := time.Time{}
	assets, err := db.DB.FindByType(oam.ASN, start)
	if err != nil {
		return err
	}

	for _, a := range assets {
		as, ok := a.Asset.(network.AutonomousSystem)
		if !ok {
			continue
		}

		desc := db.ReadASDescription(context.Background(), as.Number, start)
		if desc == "" {
			continue
		}

		for _, prefix := range db.ReadASPrefixes(context.Background(), as.Number, start) {
			first, cidr, err := net.ParseCIDR(prefix)
			if err != nil {
				continue
			}
			if ones, _ := cidr.Mask.Size(); ones == 0 {
				continue
			}

			cache.Update(&ASNRequest{
				Address:     first.String(),
				ASN:         as.Number,
				Prefix:      cidr.String(),
				Description: desc,
			})
		}
	}
	return nil
}
