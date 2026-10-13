# PortLens

A lightweight, multithreaded TCP port scanner written in Python. PortLens shows which ports are open on a host, names the service running on each, and flags risky services that shouldn't be exposed.

> **Legal notice:** Only scan systems you own or have explicit written permission to test. Unauthorized port scanning may be illegal in your country.

## Features

- Fast multithreaded TCP connect scanning
- Scan a custom range, a list of ports, or a built-in list of common ports
- Service name detection for each open port
- Security notes for risky exposed services (Telnet, FTP, RDP, SMB, Redis, etc.)
- Adjustable timeout and thread count
- No third-party dependencies (Python standard library only)

## Requirements

- Python 3.9 or newer
- Works on Windows, macOS and Linux

## Installation

### 1. Check Python is installed

```bash
python --version
```

On macOS/Linux you may need `python3` instead of `python`.

### 2. Get the project

If it's in a Git repository:

```bash
git clone https://github.com/mohdsufiyansheikeh-hue/Port-Lens.git
cd PortLens
```

Or just download `port_scanner.py` into a folder and open a terminal there.

### 3. (Optional) Create a virtual environment

**Windows**
```bash
python -m venv venv
venv\Scripts\activate
```

**macOS / Linux**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

PortLens uses only the standard library, so this step installs nothing extra today. It's included so future dependencies have a home.

## Usage

```bash
python port_scanner.py <host> [options]
```

| Option | Description | Default |
|---|---|---|
| `-p`, `--ports` | Ports to scan, e.g. `80,443` or `1-1024` | `1-1024` |
| `--top` | Scan only a list of common ports | off |
| `-t`, `--timeout` | Per-port timeout in seconds | `0.5` |
| `-w`, `--workers` | Number of parallel threads | `100` |
| `-h`, `--help` | Show help | |

### Examples

Scan your own machine:
```bash
python port_scanner.py 127.0.0.1
```

Scan a range on your router:
```bash
python port_scanner.py 192.168.1.1 -p 1-1024
```

Scan specific ports with a longer timeout:
```bash
python port_scanner.py localhost -p 22,80,443,8080 -t 1.0
```

Quick scan of common ports:
```bash
python port_scanner.py 192.168.1.1 --top
```

### Sample output

```
Scanning 192.168.1.1 (192.168.1.1) - 34 ports
Only scan systems you own or have permission to test.

PORT    SERVICE       NOTE
------------------------------------------------------------
22      ssh
23      telnet        Telnet is unencrypted; use SSH instead
80      http
443     https

Done: 4 open of 34 scanned in 1.12s
```

## How it works

PortLens performs a full TCP connect scan. It attempts a normal TCP connection to each port, and if the connection succeeds the port is reported as open. Threads let many ports be checked at once.

## Limitations

- IPv4 and TCP only (no UDP scanning)
- Results can be affected by firewalls and rate limiting
- Doesn't identify service versions

## Contributing

Pull requests and suggestions are welcome. Please open an issue first to discuss major changes.

## License

Released under the MIT License. See [LICENSE](LICENSE) for details.
