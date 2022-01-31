# Nmap2Tex


Nmap2Tex allows you to automatically create a LaTeX document presenting all of the key information retrieved from a Nmap scan.


## Features:

The features that Nmap2Tex currently officially supports are:
- Complete support for Nmap network scans.
- Vulnerability reports with smart highlighting based on each vulnerability's and system's risk.
- External vulnerability Nmap scan inputs on top of another network scan.
- Custom LaTeX template file.
- Renames certain services to a human readable name (check the <a href="#services">services</a> section for more information).
- Custom services list.
- Table of users with the superusers highlighted (check the <a href="#users-list">users list</a> section for more information).
- Custom user seperators.
- Template and services updates.


## Installation:

**Dependencies:**
- Python 3.10
- Latexmk

**Note: If you are not running Python 3.10, download the nmap2tex.py file and run it with Python (`python nmap2tex.py`).**

1. Download the latest release.
2. Run `nmap2tex` to retrieve the LaTeX template and services file or download them manually and place them in the working directory.
3. Enjoy!


## Usage:

```
nmap2tex [Nmap scan].xml [output file].tex
```

### Vulnerability Report:

**Vulnerability report on the provided scan:**
```
nmap2tex [Nmap scan].xml [output file].tex -vr
```

**Vulnerability report with an external Nmap vulnerability scan:**
```
nmap2tex [Nmap scan].xml [output file].tex -v [Nmap vuln scan].xml
```

### Users List:

Nmap2Tex has support for an external list of users which it will then display in a table with the superusers in bold.

```
nmap2tex [Nmap scan].xml [output file].tex -u [user list file]
```

#### User Separation:

To denote the separation between two usernames, the following characters are used:
`\n`, `\t`, `,`, `.`, `:`, `;`, `/`, `\`, `-` and '\`'

If you wish to denote the separation between users with another character or specify the character to be used, you can use the `-us` flag.
```
nmap2tex [Nmap scan].xml [output file].tex -u [user list file] -us [character]
```

#### Superuser Denotation:

To denote a user as a superuser, their username must be surrounded by one of the following combination of characters:
`**`, `{}`, `[]`, `()`, `""`, `''`.

Example:
```
user1, user2, user3, *superuser1*, user4, [superuser2], user5...
```

### Services:

Nmap2Tex will change the name of a specific set of services into a human-readable alternative to allow for easier and faster understanding of the Nmap scans.
By default, a `services.json` file will be retrieved if it is not already present and placed in the working directory which will contain all of the original names and their human-readable alternatives.

#### Modifying:

You can choose to modify the `services.json` file to your liking but you can also provide it an external file by using the `-s` flag.
If you choose to modify the `services.json` file or provide your own, **original service names are on the left, human-readable service names are on the right**.

```
nmap2tex [Nmap scan].xml [output file].tex -s [services].json
```

#### Updating:

You can update your `services.json` file to the latest version by using the `-su` flag when running Nmap2Tex.
**This WILL overwrite the file called `services.json` in the working directory.**

```
nmap2tex [Nmap scan].xml [output file].tex -su
```

### LaTeX Template:

Nmap2Tex includes a LaTeX template file which includes all the commands and the formatting into the output LaTeX file.
By default, a `template.tex` file will be retrieved if it does not already exist and will be placed in the working directory.

#### Modifying:

You can modify the `template.tex` file or provide your own, however **DO NOT change the name of any of the LaTeX environments or commands** otherwise it **WILL** cause issues.
To provide your own LaTeX template file, you can use the `-t` flag.

```
nmap2tex [Nmap scan].xml [output file].tex -t [template].tex
```

#### Updating:

You can update your `template.tex` file to the latest version by using the `-tu` flag when running Nmap2Tex.
**This WILL overwrite the file called `template.tex` in the working directory.**

```
nmap2tex [Nmap scan].xml [output file].tex -tu
```


## Issues and Contribution:

If you find issues, please report them by creating an issue in the repository and I will address them.
If you wish to help contribute, create an issue and if approved, offer a pull request containing the change, or I will add it to the roadmap.
