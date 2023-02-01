
<p align="center">
<img src="assets/jacked-logo.svg" style="display: block; margin-left: auto; margin-right: auto; width: 50%;">
</p>

# Jacked

Jacked provides organizations with a more comprehensive look at their application to take calculated actions and create a better security approach. Its primary purpose is to scan vulnerabilities to implement subsequent risk mitigation measures. 

# Features
- 🐞 | Scans image vulnerability; checks if your image is at risk.
- 🔧 | Configuration that helps user's preference using the tool.
- ⛑ | Works with major operating system and many packages.
- 🗃 | Works seamlessly with [Diggity](https://github.com/carbonetes/diggity) (SBOM Container Image and File System)
- 🗄 | Converts results to JSON and Tabulated Format.


# Installation 📥

## Installation Support OS 💽
- Mac
  - darwin_amd64.tar.gz
  - darwin_arm64.tar.gz
- Linux
  - deb
    - linux_amd64.deb
    - linux_arm64.deb
    - linux_ppc64le.deb
  - rpm
    - linux_amd64.rpm
    - linux_arm64.rpm
    - linux_ppc64le.rpm
  - tar.gz
    - linux_amd64.tar.gz
    - linux_arm64.tar.gz
    - linux_ppc64le.tar.gz
- Windows
  - windows_amd64.zip

## Recommended

A great way to install a working binary tool on your terminal. 
```bash
curl -sSfL https://raw.githubusercontent.com/carbonetes/jacked/main/install.sh | sh -s -- -d /usr/local/bin
```
You can specify a release version and destination directory for the installation:

```
curl -sSfL https://raw.githubusercontent.com/carbonetes/jacked/main/install.sh | sh -s -- -d <DESTINATION_DIR> -v <RELEASE_VERSION>
```


# Getting Started 🚀  

## Run the CLI tool 🏁
Once you've successfully installed the Jacked and wanted to scan an image, on your terminal:
```
jacked <image>
```
<details>
<summary>Jacked Running on a terminal:</summary>

<p align="center">
<img src="assets/jacked-scan.gif" style="display: block; margin-left: auto; margin-right: auto; width: 100%;">
</p>

</details>

## Output formats

The output format for Jacked is configurable as well using the
`-o` (or `--output`) option:

The available `formats` are:
- `table`: A columnar summary (default).
- `json`: Use this to get as much information out of Jacked.
- `cyclonedx-xml`: An XML report conforming to the [CycloneDX 1.4 specification](https://cyclonedx.org/specification/overview/).
- `cyclonedx-json`: A JSON report conforming to the [CycloneDX 1.4 specification](https://cyclonedx.org/specification/overview/).
- `spdx-tag-value`: A tag-value formatted report conforming to the [SPDX 2.2 specification](https://spdx.github.io/spdx-spec/).
- `spdx-json`: A JSON report conforming to the [SPDX 2.2 JSON Schema](https://github.com/spdx/spdx-spec/blob/v2.2/schemas/spdx-schema.json).format.
- `spdx-xml`: A XML report conforming to the [SPDX 2.2 XML: Schema](https://github.com/mil-oss/spdx-xsd/blob/master/xml/xsd/spdx-xml-ref.xsd).format.
## Useful Commands and Flags 🚩
```
jacked [command] [flag]
```
### Available Commands and their flags with description:


```
jacked config [flag]
```
|     Flag      |               Description                |
| :------------ | :--------------------------------------- |
| `-d`,`--display` | Display the content of the configuration file. |
| `-h`,`--help` | Help for configuration.       |
| `-p`,`--path` | Display the path of the configuration file.          |
| `-r`,`--reset` | Restore default configuration file.   |

```
jacked db [flag]
```
|       Flag        |               Description                |
| :---------------- | :--------------------------------------- |
| `-i`, `--info`    | Print database metadata information.     |
| `-v`, `--version` | Print database current version.          |

```
jacked version [flag] [string]
```
|     Flag      |               Description                |
| :------------ | :--------------------------------------- |
| `-o` [string], `--output` [string] | format to display results (table, json, cyclonedx-xml, cyclonedx-json, spdx-xml, spdx-json, spdx-tag-value) (default "table") |

## Configuration 🚧
Improve using the tool based on your preferences.
<br>
Configuration search paths:
- `<HOME>/.jacked.yaml`

Configuration options (example values are the default):

```yaml
settings:
  # supported output types: (table, json, cyclonedx-xml, cyclonedx-json, spdx-xml, spdx-json, spdx-tag-value) (default "table") 
  output: table
  # quiet mode disable all output except vulnerability result
  quiet: false
  # show with license result
  license: false
  # show with secret result
  secret: false
  # Policy that ignores specified vulnerability from the result
ignore:
  vulnerability:
    cve: []
    severity: []
  package:
    name: []
    type: []
    version: []
```

## License

[Apache 2.0](https://choosealicense.com/licenses/apache-2.0/)
