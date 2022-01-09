# Nmap2Tex


Nmap2Tex allows you to automatically create a LaTeX document presenting all of the information retrieved from your Nmap scan.  


## Supported Scan Types:
Nmap2Tex plans to support the greatest amount of Nmap scan types and scripts and the majority already will work but below are the scan types that are fully compatible and have being tested.  
  
__Nmap scans currently supported:__  
- Regular scan
- Vulnerability script scan

Nmap2Tex also supports a user list being provided to allow for a table of users to be generated. Currently the user list has to contain one user per line however, support for custom separators and designation for administrator users is coming soon.


## LaTeX Customisation:

The `template.tex` file contains all of the LaTeX commands used by the Nmap2Tex program and is also provided with a basic page and header formatting.  
You can modify the `template.tex` file to your liking however, **DO NOT CHANGE THE NAME OF THE COMMANDS** otherwise it will cause issues with the formatting, requiring you to manually correct it after every usage.  
You can however, change the contents of the commands to your liking without causing any issues.  


## Usage:

`Nmap2Tex [-u USERS] [-t TEMPLATE] [-s SERVICES] [-v VULN] [-h] [--version] Nmap Output`
