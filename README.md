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

Analyse de fichier avec règles YARA

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Chemin du fichier à analyser
  -M                    Utiliser les règles de malware
  -Cr                   Utiliser les règles de crypto
  -AB                   Utiliser les règles d'anti-debug/anti-VM
  -C                    Utiliser les règles de capabilities
  -EK                   Utiliser les règles d'exploit kits
  -WS                   Utiliser les règles de webshell
  -E                    Utiliser les règles d'email
  -MM                   Utiliser les règles de mobile malware
  -CV                   Utiliser les règles de CVE
  -P                    Utiliser les règles de packers
  -MD                   Utiliser les règles de maldocs
  -ALL                  Utiliser toutes les règles
  --update              Mettre à jour le dépôt de règles avec git pull
```
