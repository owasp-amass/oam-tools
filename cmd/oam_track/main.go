// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// oam_track: Analyze collected OAM data to identify newly discovered assets
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
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/caffix/stringset"
	"github.com/fatih/color"
	"github.com/owasp-amass/config/config"
	"github.com/owasp-amass/engine/graph"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
)

const (
	timeFormat = "01/02 15:04:05 2006 MST"
	usageMsg   = "[options] [-since '" + timeFormat + "'] " + "-d domain"
)

var (
	// Colors used to ease the reading of program output
	g = color.New(color.FgHiGreen)
	r = color.New(color.FgHiRed)
)

type trackArgs struct {
	Domains *stringset.Set
	Since   string
	Options struct {
		NoColor bool
		Silent  bool
	}
	Filepaths struct {
		ConfigFile string
		Directory  string
		Domains    string
	}
}

func main() {
	var args trackArgs
	var help1, help2 bool
	trackCommand := flag.NewFlagSet("track", flag.ContinueOnError)

	args.Domains = stringset.New()
	defer args.Domains.Close()

	trackBuf := new(bytes.Buffer)
	trackCommand.SetOutput(trackBuf)

	trackCommand.BoolVar(&help1, "h", false, "Show the program usage message")
	trackCommand.BoolVar(&help2, "help", false, "Show the program usage message")
	trackCommand.Var(args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	trackCommand.StringVar(&args.Since, "since", "", "Exclude all assets discovered before (format: "+timeFormat+")")
	trackCommand.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	trackCommand.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")
	trackCommand.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the YAML configuration file")
	trackCommand.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the graph database")
	trackCommand.StringVar(&args.Filepaths.Domains, "df", "", "Path to a file providing registered domain names")

	var usage = func() {
		g.Fprintf(color.Error, "Usage: %s %s\n\n", path.Base(os.Args[0]), usageMsg)
		trackCommand.PrintDefaults()
		g.Fprintln(color.Error, trackBuf.String())
	}

	if len(os.Args) < 2 {
		usage()
		return
	}
	if err := trackCommand.Parse(os.Args[1:]); err != nil {
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
	if args.Filepaths.Domains != "" {
		list, err := config.GetListFromFile(args.Filepaths.Domains)
		if err != nil {
			r.Fprintf(color.Error, "Failed to parse the domain names file: %v\n", err)
			os.Exit(1)
		}
		args.Domains.InsertMany(list...)
	}
	if args.Domains.Len() == 0 {
		r.Fprintln(color.Error, "No root domain names were provided")
		os.Exit(1)
	}

	var err error
	var start time.Time
	if args.Since != "" {
		start, err = time.Parse(timeFormat, args.Since)
		if err != nil {
			r.Fprintf(color.Error, "%s is not in the correct format: %s\n", args.Since, timeFormat)
			os.Exit(1)
		}
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
	// Connect with the graph database containing the enumeration data
	db := openGraphDatabase(args.Filepaths.Directory, cfg)
	if db == nil {
		r.Fprintln(color.Error, "Failed to connect with the database")
		os.Exit(1)
	}

	for _, name := range getNewNames(args.Domains.Slice(), start, db) {
		g.Fprintln(color.Output, name)
	}
}

func getNewNames(domains []string, since time.Time, g *graph.Graph) []string {
	if len(domains) == 0 {
		return []string{}
	}

	var fqdns []oam.Asset
	for _, d := range domains {
		fqdns = append(fqdns, &domain.FQDN{Name: d})
	}

	if !since.IsZero() {
		since = since.UTC()
	}

	assets, err := g.DB.FindByScope(fqdns, since)
	if err != nil {
		return []string{}
	}

	if since.IsZero() {
		var latest time.Time

		for _, a := range assets {
			if _, ok := a.Asset.(*domain.FQDN); ok && a.LastSeen.After(latest) {
				latest = a.LastSeen
			}
		}

		since = latest.Truncate(24 * time.Hour)
	}

	res := stringset.New()
	defer res.Close()

	for _, a := range assets {
		if n, ok := a.Asset.(*domain.FQDN); ok && !res.Has(n.Name) &&
			(a.CreatedAt.Equal(since) || a.CreatedAt.After(since)) &&
			(a.LastSeen.Equal(since) || a.LastSeen.After(since)) {
			res.Insert(n.Name)
		}
	}

	return res.Slice()
}

func openGraphDatabase(dir string, cfg *config.Config) *graph.Graph {
	// Add the local database settings to the configuration
	cfg.GraphDBs = append(cfg.GraphDBs, cfg.LocalDatabaseSettings(cfg.GraphDBs))

	for _, db := range cfg.GraphDBs {
		if db.Primary {
			var g *graph.Graph

			if db.System == "local" {
				g = graph.NewGraph(db.System, filepath.Join(config.OutputDirectory(cfg.Dir), "amass.sqlite"), db.Options)
			} else {
				connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s", db.Host, db.Port, db.Username, db.Password, db.DBName)
				g = graph.NewGraph(db.System, connStr, db.Options)
			}

			if g != nil {
				return g
			}
			break
		}
	}
	return nil
}
