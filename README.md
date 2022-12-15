# ISEhole

Business Ready Documents for Cisco Identity Services Engine

## Current API Coverage

Active Directory

Admin Users

Allowed Protocols

Authentication Dictionaries

Authorization Dictionaries

Authorization Profiles

Command Sets

Conditions

CSRs

DACLs

Deployment Nodes

Endpoint Groups

Endpoints

Eval Licenses

Hot Patches

Identity Groups

Identity Store Sequences

Identity Stores

Internal Users

Last Backup

License Connection Type

License Feature Map

License Register

License Smart State

License Tier State

NBAR Apps

Network Access Condition Authentication

Network Access Condition Authorization

Network Access Condition Policy Sets

Network Access Conditions

Network Access Dictionary Authentication

Network Access Dictionary Authorization

Network Access Dictionary Policy Sets

Network Access Dictionaries

Network Access Identity Stores

Network Access Policy Sets

Network Access Security Groups

Network Access Service Names

Network Authorization Profiles

Network Device Groups

Network Devices

Node Interfaces

Node Profiles

Nodes

PAN HA

Patches

Policy Set Dictionary

Policy Sets

Portals

Profilers

Proxies

Repositories

Self Registration Portals

Service Names

SGT ACLs

SGTs

Shell Profiles

Sponsor Groups

Sponsored Guest Portals

Sponsor Portals

System Certificates

Transport Gateways

Trusted Certificates
## Installation

```console
$ python3 -m venv ISE
$ source ISE/bin/activate
(ACI) $ pip install isehole
```

## Usage - Help

```console
(ISE) $ isehole --help
```

## Usage - In-line

```console
(ISE) $ isehole --url <url to ISE> --username <ISE username> --password <ISE password>
```

## Usage - Interactive

```console
(ISE) $ isehole
ISE URL: <URL to ISE>
ISE Username: <ISE Username>
ISE Password: <ISE Password>
```

## Usage - Environment Variables

```console
(ISE) $ export URL=<URL to ISE>
(ISE) $ export USERNAME=<ISE Username>
(ISE) $ export PASSWORD=<ISE Password>
```

## Recommended VS Code Extensions

Excel Viewer - CSV Files

Markdown Preview - Markdown Files

Markmap - Mindmap Files

Open in Default Browser - HTML Files

## Contact

Please contact John Capobianco if you need any assistance
