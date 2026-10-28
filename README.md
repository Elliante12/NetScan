# Network Scanner

A menu-driven Python network reconnaissance and monitoring toolkit for **authorized labs, home networks, and security research**.

> **Version:** 0.3.0 (as displayed by the application)  
> **Interface:** Interactive terminal menu  
> **Primary file:** `Network_Scanner.py`

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Run the Scanner](#run-the-scanner)
- [Menu Reference](#menu-reference)
- [Example Workflow](#example-workflow)
- [Permissions and Platform Notes](#permissions-and-platform-notes)
- [Understanding Results](#understanding-results)
- [Troubleshooting](#troubleshooting)
- [Security and Responsible Use](#security-and-responsible-use)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)

## Overview

Network Scanner groups common network discovery, service inspection, monitoring, and reporting utilities in one terminal application. Choose an operation from the numbered menu, enter the requested target or settings, and review the output in the terminal.

The tool is intended for learning and authorized defensive testing. Results are best treated as **initial indicators** that should be verified with reliable, purpose-built tools.

## Features

### Basic scanning

- **IP Ping** — checks reachability using the operating system's `ping` command.
- **Port Scan** — checks a specified range of TCP ports on a host.
- **Device Recognition** — discovers devices on a network using the scanner's network-discovery routines.
- **Device Details** — displays additional information for devices found by a previous discovery scan.
- **Ping Sweep** — checks a range of addresses for responding hosts.
- **Route Trace** — traces the network path toward a destination.
- **DNS Enumeration** — looks up address information and checks a list of common subdomains.

### Advanced scanning and monitoring

- **Packet Sniffer** — observes selected network traffic and reports supported HTTP, DNS, and ARP information. The implementation also attempts to identify credential-like values in unencrypted HTTP POST data; use only in a controlled lab with explicit authorization.
- **Bandwidth Monitor** — samples system network counters and estimates upload/download rates.
- **Vulnerability Scanner** — associates selected open ports with a built-in list of possible issues and runs a few additional checks.
- **Wi-Fi Scanner** — lists nearby wireless networks using operating-system tools.
- **Web Application Scanner** — checks for indicators such as missing security headers, exposed common paths, information disclosure, and possible injection issues.
- **ARP Spoofing Detector** — watches ARP responses for IP-to-MAC address changes.
- **SSL Certificate Analyzer** — displays certificate metadata and flags some potential certificate issues.
- **Service Fingerprinter** — attempts to identify services from returned banners.
- **SSH/Remote Access Scanner** — checks common remote-access service ports.
- **Wi-Fi Deauthentication Detector** — monitors wireless frames for patterns that may indicate deauthentication activity.

### Enterprise-oriented utilities

- **Active Directory Scanner** — menu option for directory-related scanning.
- **Network Topology Mapper** — menu option for mapping discovered network devices.
- **Port Knock Scanner** — checks a supplied sequence of ports.

### Utilities

- **Continuous Monitoring**
- **Export Results**
- **Generate Report**

The available options are shown in the application's terminal menu. Some checks depend on the operating system, privileges, network adapter, and installed external utilities.

## Requirements

- Python 3
- [Nmap](https://nmap.org/download.html) installed and available on your `PATH` for Nmap-backed features
- A terminal/command prompt
- Network access to the systems you are authorized to assess

The script imports these Python packages:

- `python-nmap` (`nmap`)
- `requests`
- `tqdm`
- `psutil`
- `scapy`
- `pyOpenSSL` (`OpenSSL`)
- `paramiko`
- `ldap3`
- `dnspython` (`dns`)
- `netifaces`

The source also contains an optional MySQL check that imports `PyMySQL` when needed. Some features call operating-system utilities such as `ping`, `traceroute`/`tracert`, `netsh`, `iwlist`, or `nmcli`; availability varies by platform.

## Installation

### 1. Get the project

Clone your repository, or place the Python file in a project directory.

```bash
git clone <your-repository-url>
cd <your-repository-directory>
```

If you are not using Git yet, create a folder and put `Network_Scanner.py` inside it.

### 2. Create a virtual environment

**Windows (PowerShell):**

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**macOS / Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Python dependencies

```bash
python -m pip install --upgrade pip
python -m pip install python-nmap requests tqdm psutil scapy pyOpenSSL paramiko ldap3 dnspython netifaces PyMySQL
```

`PyMySQL` is included for the optional MySQL check. If a package fails to install on your platform, consult that package's installation instructions.

### 4. Install Nmap

Install Nmap using the official download page: <https://nmap.org/download.html>.

Confirm that it is available:

```bash
nmap --version
```

If the command is not found, add Nmap to your `PATH` or reinstall it with the appropriate platform installer.

## Run the Scanner

From the directory containing the script:

```bash
python "Network_Scanner.py"
```

On some systems, the command may be `python3` instead of `python`.

The program opens an interactive menu. Enter the number for the operation you want, then follow the prompts. Use **`0`** to exit.

> **Tip:** Start with a small, known lab target and a narrow port range. Scanning a large network can take time and may trigger monitoring alerts.

## Menu Reference

| Menu option | Operation | What it does |
|---:|---|---|
| `1` | IP Ping | Checks whether a host responds to ping |
| `2` | Port Scan | Scans a chosen start/end port range |
| `3` | Device Recognition | Discovers network devices |
| `4` | Device Details | Shows details for the most recent device scan |
| `5` | Export Results | Exports available scan results |
| `6` | Ping Sweep | Checks a range of IP addresses |
| `7` | Continuous Monitoring | Runs a monitoring workflow |
| `8` | Route Trace | Traces a route to a host |
| `9` | DNS Enumeration | Looks up DNS/address and common subdomain information |
| `10` | Packet Sniffer | Captures and inspects supported packet data |
| `11` | Bandwidth Monitor | Samples network traffic counters |
| `12` | Vulnerability Scanner | Checks open ports against built-in indicators |
| `13` | Wi-Fi Scanner | Lists nearby wireless networks |
| `14` | Web Application Scanner | Checks a web application for common indicators |
| `15` | ARP Spoofing Detector | Watches for changing IP-to-MAC mappings |
| `16` | SSL Certificate Analyzer | Reads certificate details and flags selected issues |
| `17` | Service Fingerprinter | Attempts service identification from banners |
| `18` | SSH/Remote Access Scanner | Checks common remote-access ports |
| `19` | Wi-Fi Deauth Detector | Watches for suspicious wireless management-frame patterns |
| `20` | Active Directory Scanner | Directory scanning option |
| `21` | Network Topology Mapper | Network mapping option |
| `22` | Port Knock Scanner | Checks a sequence of ports |
| `23` | Generate Report | Generates a report from supported results |
| `0` | Exit | Closes the application |

The menu is the source of truth for the option numbers. Inputs and output details may differ depending on the selected operation and the current code version.

Treat any finding as a lead for manual verification rather than proof of a vulnerability.

## Permissions and Platform Notes

- **Packet capture:** Scapy-based capture may require administrator/root privileges and a supported capture driver.
- **Wi-Fi scanning:** Windows uses `netsh`; the non-Windows path calls `iwlist`, which may not be installed or supported on modern systems. Linux Wi-Fi operations may require elevated privileges.
- **Nmap:** Install the Nmap application separately; installing the Python wrapper alone is not enough.
- **Network adapters:** Wireless monitoring features may require a compatible adapter and, for some operations, monitor mode.
- **Operating-system commands:** Ping, route tracing, and Wi-Fi commands differ by OS. A command that works on one platform may not work on another.
- **Permissions:** Run with the minimum privileges needed. Avoid running the entire application as administrator/root unless a specific authorized feature requires it.

## Understanding Results

- **Open port:** A service accepted a connection at scan time. This does not, by itself, mean the service is vulnerable.
- **Possible vulnerability:** The scanner's built-in port-to-issue list is a heuristic. It is not a complete vulnerability database and does not confirm that a listed CVE applies to the detected software/version.
- **Missing web security header:** This is a configuration signal to review, not automatically an exploitable vulnerability.
- **Certificate warning:** Verify certificate dates, hostname coverage (including Subject Alternative Names), trust chain, and client behavior with a dedicated TLS tool.
- **ARP change:** A device may legitimately change its MAC address or network configuration; an alert needs investigation.
- **No finding:** This does not prove that a host or application is secure. Firewalls, timeouts, permissions, protocol encryption, and incomplete checks can affect results.

## Troubleshooting

### `ModuleNotFoundError`

Activate your virtual environment and install the dependencies:

```bash
python -m pip install python-nmap requests tqdm psutil scapy pyOpenSSL paramiko ldap3 dnspython netifaces PyMySQL
```

### `nmap` is not found

Install the Nmap system application and make sure `nmap --version` works in the same terminal used to run Python.

### Permission or packet-capture errors

Try a supported capture interface and follow your operating system's Scapy/libpcap/Npcap setup instructions. Use elevated privileges only when necessary and only on an authorized network.

### Wi-Fi scan returns no networks

Check that the wireless adapter is enabled and that the relevant OS utility (`netsh` on Windows or `iwlist` on the non-Windows code path) is available. The `iwlist` approach may not work on every modern Linux distribution.

### A scan reports no results

Confirm the target is correct and reachable, that you have permission to test it, and that firewalls or routing are not blocking probes. Some hosts intentionally do not respond to ping or unsolicited connections.

### Results look incorrect

Several checks use simple signatures or heuristics. Validate results with current vendor documentation and dedicated tools before making security decisions.

## Security and Responsible Use

This tool is for **educational, research, and defensive use on systems you own or are explicitly authorized to assess**.

- Obtain permission before scanning networks, hosts, websites, or wireless environments.
- Do not use packet capture to collect other people's traffic or credentials.
- Do not attempt login checks against systems without explicit authorization.
- Keep scan scope narrow and avoid disruptive testing on production services.
- Protect reports and packet captures because they may contain IP addresses, hostnames, URLs, or other sensitive data.
- Follow applicable laws, organizational policies, and the rules of the network owner.

The packet-sniffing implementation attempts to extract credential-like strings from unencrypted HTTP POST data, and remote-access checks include default-credential attempts. These features can expose sensitive information or cause account lockouts. Use them only in a controlled environment with explicit authorization.

## Limitations

- The vulnerability checks are based on a small, hard-coded set of port/service indicators and should not be treated as comprehensive CVE verification.
- Web checks use simple response-content and status-code heuristics; false positives and false negatives are possible.
- DNS enumeration is limited to the record lookups and common subdomain names implemented in the script.
- Wireless monitoring depends on hardware, drivers, privileges, and OS support.
- Some menu entries may have platform-specific requirements or limited coverage.
- This README describes the provided source file; it does not imply that every feature has been independently tested on every platform.

## Contributing

Contributions are welcome. 

## License

Licensed under the MIT license.
