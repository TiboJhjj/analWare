# AnalWare

**AnalWare** is a Python-based malware analysis tool that utilizes YARA rules to detect and identify malware signatures within files. This tool is designed for security researchers and malware analysts to streamline the process of file scanning against a predefined set of rules.

## Features

- Multi-threaded scanning for faster analysis.
- Supports various types of YARA rules including malware, crypto, anti-debugging, and more.
- Ability to update the YARA rules repository directly from GitHub.
- Detailed match reporting including the type of rule that triggered each match.

## Installation

To get started, clone this repository and install the required Python libraries:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd <YOUR_REPOSITORY_NAME>
pip install -r requirements.txt
git clone https://github.com/Yara-Rules/rules.git
```

## Help tool

```bash
usage: AnalWare.py [-h] [-f FILE] [-M] [-Cr] [-AB] [-C] [-EK] [-WS] [-E] [-MM] [-CV] [-P] [-MD] [-ALL]
                   [--update]

File analysis with YARA rules

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Path to the file to analyze
  -M                    Use malware rules
  -Cr                   Use crypto rules
  -AB                   Use anti-debug/anti-VM rules
  -C                    Use capabilities rules
  -EK                   Use exploit kits rules
  -WS                   Use webshell rules
  -E                    Use email rules
  -MM                   Use mobile malware rules
  -CV                   Use CVE rules
  -P                    Use packers rules
  -MD                   Use maldocs rules
  -ALL                  Use all rules
  --update              Update the rules repository with git pull
```
