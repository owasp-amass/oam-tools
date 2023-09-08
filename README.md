# OAM Tools

<p align="center">
  <img src="https://github.com/owasp-amass/amass/blob/master/images/amass_video.gif">
</p>

[![Follow on Twitter](https://img.shields.io/twitter/follow/owaspamass.svg?logo=twitter)](https://twitter.com/owaspamass)
[![Chat on Discord](https://img.shields.io/discord/433729817918308352.svg?logo=discord)](https://discord.gg/HNePVyX3cp)


The OAM Tools serves the purpose for extracting, manipulating, and analyzing data in an OAM database.

**Current tools are:**

| Tool    | Description |
|:-------------|:-------------|
| oam_i2y      | Convert legacy INI configuration format to the current YAML format|
| oam_subs     | Analyze collected OAM assets|
| oam_track    | Analyze collected OAM data to identify newly discovered assets|
| oam_viz      | Analyze collected OAM data to generate files renderable as graph visualizations|

## Usage
To understand how to use the tools above, check out the [User's Guide](./user_guide.md)!

## Installation [![Go Version](https://img.shields.io/github/go-mod/go-version/owasp-amass/oam-tools)](https://golang.org/dl/) 

### From Source

1. Install [Go](https://golang.org/doc/install) and setup your Go workspace
2. Download all the OAM tools by running `go install -v github.com/owasp-amass/oam-tools/cmd/...@master`
    - If you want to download a specific tool only, run `go install -v github.com/owasp-amass/oam-tools/cmd/TOOL_NAME@master`
        - Example: `go install -v github.com/owasp-amass/oam-tools/cmd/oam_i2y@master`
3. At this point, the binary should be in `$GOPATH/bin`

### Local Install

1. Install [Go](https://golang.org/doc/install) and setup your Go workspace
2. Use git to clone the repository: `git clone https://github.com/owasp-amass/oam-tools`
    - At this point, a directory called `oam-tools` should be made
3. Go into the `oam-tools` directory by running `cd oam-tools`, and then build the desired program by running `go build ./cmd/TOOL_NAME`
    - Example: `go build ./cmd/oam_i2y`
    - To install all the tools at once, you would need to be inside the `oam-tools` directory and iterate through all the tools under `cmd`
        - A one-liner (like this one in bash: `for i in ./cmd/*; do echo $i; go build $i;done`) can be made to handle this scenario.
4. **Enjoy!** The binary will reside in your current working directory, which should be the `oam-tools` directory.

## Corporate Supporters

[![ZeroFox Logo](./images/zerofox_logo.png)](https://www.zerofox.com/) [![IPinfo Logo](./images/ipinfo_logo.png)](https://ipinfo.io/) [![WhoisXML API Logo](./images/whoisxmlapi_logo.png)](https://www.whoisxmlapi.com/)

## Contributing [![Contribute Yes](https://img.shields.io/badge/contribute-yes-brightgreen.svg)](./CONTRIBUTING.md) [![Chat on Discord](https://img.shields.io/discord/433729817918308352.svg?logo=discord)](https://discord.gg/HNePVyX3cp)

We are always happy to get new contributors on board! Join our [Discord Server](https://discord.gg/HNePVyX3cp) to discuss current project goals.

## Troubleshooting [![Chat on Discord](https://img.shields.io/discord/433729817918308352.svg?logo=discord)](https://discord.gg/HNePVyX3cp)

If you need help with installation and/or usage of the tools, please join our [Discord server](https://discord.gg/HNePVyX3cp) where community members can best help you.

**Please avoid opening GitHub issues for support requests or questions!**

## Licensing [![License](https://img.shields.io/badge/license-apache%202-blue)](https://www.apache.org/licenses/LICENSE-2.0)

This program is free software: you can redistribute it and/or modify it under the terms of the [Apache license](LICENSE). OWASP Amass and any contributions are Copyright © by Jeff Foley 2017-2023. Some subcomponents have separate licenses.
