
<p align="center">
<img src="assets/jacked-logo.svg" style="display: block; margin-left: auto; margin-right: auto; width: 50%;">
</p>

# Jacked

Jacked provides organizations with a more comprehensive look at their application to take calculated actions and create a better security approach. Its primary purpose is to scan vulnerabilities to implement subsequent risk mitigation measures. Partnered with [Diggity](https://github.com/carbonetes/diggity) for generating a Software Bill of Materials (SBOM) from container images and filesystems.

# Features
- 🐞 | Scans image vulnerability; checks if your image is at risk.
- 🔧 | Configuration that helps user's preference using the tool.
- ⛑ | Works with major operating system and many packages.
- 🗃 | Works seamlessly with [Diggity](https://github.com/carbonetes/diggity) (SBOM Container Image and File System)
- 🗄 | Converts results to JSON and Tabulated Format.


# Installation 📥
## Recommended

A great way to install a working binary tool on your terminal. 
```bash
curl -sSfL https://raw.githubusercontent.com/carbonetes/jacked/main/install.sh | sh -s -- -d /usr/local/bin
```
## Build 🏗

Go Programming Language together with the cloned repository are needed to run the CLI tool.
```bash
$ git clone https://github.com/carbonetes/jacked
$ go install .
```

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


## Choosing another destination path & install previous version 🎲
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


<summary>Jacked Running on a terminal:</summary>
<p align="center">
<img src="assets/jacked-scan.gif" style="display: block; margin-left: auto; margin-right: auto; width: 50%;">
</p>

## Output formats

The output format for Jacked is configurable as well using the
`-o` (or `--output`) option:

The available `formats` are:
- `table`: A columnar summary (default).
- `json`: Use this to get as much information out of Jacked.
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
| `-d`,`--display` | Displays the content of the configuration file. |
| `-h`,`--help` | Help for config.       |
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
| `-o` [string], `--output` [string] | format to display results ([text, json]) (default "text") |

## Configuration 🚧
Improve using the tool based on your preferences.
<br>
Configuration search paths:
- `<HOME>/.jacked.yaml`

Configuration options (example values are the default):

```yaml
settings:
  output: table
  quiet: false
  license: false
  secret: false
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
