# NoSQLMap-ng

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-yellow.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-GPLv3-red.svg)](https://github.com/Xorriath/NoSQLMap-ng/blob/master/COPYING)

NoSQLMap-ng is a Python 3 fork of [NoSQLMap](https://github.com/codingo/NoSQLMap), an open source tool designed to audit for and automate injection attacks against NoSQL databases and web applications using NoSQL, in order to disclose or clone data from the database.

Originally authored by [@tcsstool](https://twitter.com/tcstoolHax0r), maintained by [@codingo\_](https://twitter.com/codingo_), and ported to Python 3 as NoSQLMap-ng. Named as a tribute to [sqlmap](http://sqlmap.org). Its concepts are based on Ming Chow's presentation at Defcon 21, ["Abusing NoSQL Databases"](https://www.defcon.org/images/defcon-21/dc-21-presentations/Chow/DEFCON-21-Chow-Abusing-NoSQL-Databases.pdf).

## DBMS Support

Presently the tool's exploits are focused around MongoDB and CouchDB, but additional support for other NoSQL platforms such as Redis and Cassandra are planned in future releases.

## Installation

```
pipx install git+https://github.com/Xorriath/NoSQLMap-ng.git
```

Or from a local clone:

```
git clone https://github.com/Xorriath/NoSQLMap-ng.git
pipx install ./NoSQLMap-ng
```

## Usage

### CLI Mode

```
nosqlmap-ng --attack 2 --victim <target> --webPort <port> --uri <path> \
  --httpMethod POST --postData "param1,value1,param2,value2" \
  --injectedParameter <num> --injectSize <size>
```

### CLI Options

| Option | Description |
|---|---|
| `--attack` | Attack type: `1` = DB access attacks, `2` = Web app attacks, `3` = Scan for anonymous access |
| `--platform` | Target platform: `MongoDB` (default) or `CouchDB` |
| `--victim` | Target host/IP |
| `--webPort` | Web application port |
| `--uri` | URI path (e.g. `/index.php`) |
| `--httpMethod` | `GET` or `POST` (default: `GET`) |
| `--https` | `ON` or `OFF` (default: `OFF`) |
| `--postData` | POST parameters as comma-separated list: `name1,val1,name2,val2` |
| `--requestHeaders` | Custom headers as comma-separated list: `name1,val1,name2,val2` |
| `--injectedParameter` | Index of the parameter to inject (1-based, follows order given in `--postData`) |
| `--injectSize` | Size of random baseline string for injection testing |
| `--verb` | Verbose mode: `ON` or `OFF` (default: `OFF`) |
| `--dbPort` | Target database port (for direct DB attacks) |
| `--myIP` | Local IP for DB cloning / reverse shells |
| `--myPort` | Local port for shell listener |

### Example

Test a POST login form for NoSQL injection:

```
nosqlmap-ng --attack 2 --victim 192.168.1.100 --webPort 80 --uri /login.php \
  --httpMethod POST --postData "email,admin@example.com,password,test123" \
  --injectedParameter 2 --injectSize 4
```

### Interactive Mode

Run `nosqlmap-ng` without arguments to use the interactive menu.

## Vulnerable Applications

This repo includes an intentionally vulnerable web application for testing. Requires Docker:

```
cd vuln_apps
docker-compose build && docker-compose up
```

Then visit: http://127.0.0.1/index.html

## Requirements

- Python >= 3.6
- pymongo >= 4.0
- requests >= 2.28
- CouchDB >= 1.2
- httplib2 >= 0.20
- A local MongoDB instance (for DB cloning features)
