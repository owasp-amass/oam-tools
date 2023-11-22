# OAM Tools - Users' Guide

![Network graph](./images/network_06092018.png "Amass Network Mapping")

----

## Command-line Usage Information

The OAM Tools serve the purpose of extracting, manipulating, and analyzing data in an OAM database. For a more extensive read that covers possible use cases where the tools would be ideal, check out the [Comprehensive Guide](./comprehensive_guide.md).

**Current tools are:**

| Tool    | Description |
|:-------------|:-------------|
| [oam_subs](#the-oam_subs-command)     | Analyze collected OAM assets|
| [oam_track](#the-oam_track-command)    | Analyze collected OAM data to identify newly discovered assets|
| [oam_viz](#the-oam_viz-command)      | Analyze collected OAM data to generate files renderable as graph visualizations|

All commands have some default global arguments that can be seen below.

| Flag | Description | Example |
|------|-------------|---------|
| -h/-help | Show the program usage message | oam_command -h |
| -config | Path to the YAML configuration file | oam_command -config config.yaml |
| -dir | Path to the directory containing the graph database | oam_command -dir PATH -d example.com |
| -nocolor | Disable colorized output | oam_command -nocolor -d example.com |
| -silent | Disable all output during execution | oam_command -silent -d example.com |

Each command's own arguments are shown in the following sections.

### The 'oam_subs' Command

Performs viewing and manipulation of the graph database. This command leverages either the SQLite file generated from enumerations or the remote graph database settings from the configuration file. Flags for interacting with the enumeration findings in the graph database include:

| Flag | Description | Example |
|------|-------------|---------|
| -d | Domain names separated by commas (can be used multiple times) | oam_subs -names -d example.com |
| -demo | Censor output to make it suitable for demonstrations | oam_subs -names -demo -d example.com |
| -df | Path to a file providing root domain names | oam_subs -df domains.txt |
| -ip | Show the IP addresses for discovered names | oam_subs -show -ip -d example.com |
| -ipv4 | Show the IPv4 addresses for discovered names | oam_subs -show -ipv4 -d example.com |
| -ipv6 | Show the IPv6 addresses for discovered names | oam_subs -show -ipv6 -d example.com |
| -names | Print just discovered names | oam_subs -names -d example.com |
| -o | Path to the text output file | oam_subs -names -o out.txt -d example.com |
| -show | Print the results for the enumeration index + domains provided | oam_subs -show -d example.com|
| -summary | Print just ASN table summary | oam_subs -summary -d example.com |

### The 'oam_track' Command

Shows differences between enumerations that included the same target(s) for monitoring a target's attack surface. This command leverages either the SQLite file generated from enumerations or the remote graph database settings from the configuration file. Flags for performing Internet exposure monitoring across the enumerations in the graph database:

| Flag | Description | Example |
|------|-------------|---------|
| -d | Domain names separated by commas (can be used multiple times) | oam_track -d example.com |
| -df | Path to a file providing root domain names | oam_track -df domains.txt |
| -since | Exclude all enumerations before a specified date (format: 01/02 15:04:05 2006 MST) | oam_track -since DATE |

### The 'oam_viz' Command

Create enlightening network graph visualizations that add structure to the information gathered. This command leverages either the SQLite file generated from enumerations or the remote graph database settings from the configuration file.

The files generated for visualization are created in the current working directory and named amass_TYPE

Switches for outputting the DNS and infrastructure findings as a network graph:

| Flag | Description | Example |
|------|-------------|---------|
| -d | Domain names separated by commas (can be used multiple times) | oam_viz -d3 -d example.com |
| -d3 | Output a D3.js v4 force simulation HTML file | oam_viz -d3 -d example.com |
| -df | Path to a file providing root domain names | oam_viz -d3 -df domains.txt |
| -dot | Generate the DOT output file | oam_viz -dot -d example.com |
| -gexf | Output to Graph Exchange XML Format (GEXF) | oam_viz -gexf -d example.com |
| -o | Path to a pre-existing directory that will hold output files | oam_viz -d3 -o OUTPATH -d example.com |
| -oA | Prefix used for naming all output files | oam_viz -d3 -oA example -d example.com |