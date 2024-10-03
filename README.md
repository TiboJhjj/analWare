# AnalWare

**AnalWare** is a Python-based malware analysis tool that utilizes YARA rules to detect and identify malware signatures within files. This tool is designed for security researchers and malware analysts to streamline the process of file scanning against a predefined set of rules.

## Features

- Multi-threaded scanning for faster analysis.
- Supports various types of YARA rules including malware, crypto, anti-debugging, and more.
- Ability to update the YARA rules repository directly from GitHub.
- Detailed match reporting including the type of rule that triggered each match.

## Get started

```bash
git clone https://github.com/TiboJhjj/analWare.git
cd analWare
pip install -r requirements.txt
python analWare.py --init
```

## Help tool

```bash
usage: analWare.py [-h] [--init] [-f FILE] [-M] [-Cr] [-AB] [-C] [-EK] [-WS] [-E] [-MM] [-CV] [-P]
                  [-MD] [-ALL] [--update]

File analysis with YARA rules

options:
  -h, --help            show this help message and exit

  --init                initialize the project by cloning the rules repository
  --update              Update the rules repository

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
```
