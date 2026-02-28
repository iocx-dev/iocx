# iocx Command‑Line Interface (CLI)

The iocx CLI provides a simple, fast way to extract Indicators of Compromise (IOCs) from text, logs, and binaries. It wraps the same engine used by the Python API and exposes a clean set of options suitable for both interactive use and scripting.

## Installation
```bash

pip install iocx

```

After installation, the iocx command becomes available on your system.

## Basic Usage

Extract IOCs from a file or raw text:
```bash

iocx "Suspicious domain: evil.com"

```

Extract from a file:
```bash

iocx sample.bin

```

Read from stdin:
```bash

echo "visit http://malicious.example" | iocx -

```

## Command‑Line Options

The CLI supports a focused set of flags designed to keep the interface simple while still offering meaningful control.

### Input
| Flag  | Description                                        |
|-------|----------------------------------------------------|
| input | File path or raw text. Use `-` to read from stdin. |


### Output
| Flag               | Description                                        |
|--------------------|----------------------------------------------------|
| -o, --output FILE  | Write JSON output to a file instead of stdout.     |
| -c, --compact      | Minify JSON output (indent=None).                  |

### Examples
```bash

iocx sample.txt --compact
iocx sample.txt -o results.json

```

## Engine Options
| Flag       | Description                                                                |
|------------|----------------------------------------------------------------------------|
| --no-cache | Disable engine caching. Useful for debugging or repeated extraction tests. |


## Detector Options
| Flag             | Description                             |
|------------------|-----------------------------------------|
| --list-detectors | Print all available detectors and exit. |

### Example:
```bash

iocx --list-detectors

```

## Misc
| Flag             | Description                             |
|------------------|-----------------------------------------|
| --version        | Show the installed version of iocx.     |


## Output Format

The CLI always emits JSON. A typical output structure looks like:
```json

{
  "urls": ["http://example.com"],
  "domains": ["example.com"],
  "emails": [],
  "ips": [],
  "filepaths": [],
  "hashes": [],
  "base64": []
}

```

Minified output is enabled with:
```bash

iocx input.txt --compact

```

### Examples

Extract from a PE file
```bash

iocx malware.exe

```

Extract from logs
```bash

iocx logs.txt -o iocs.json

```

Pipe data in
```bash

cat suspicious.log | iocx - --compact

```

List detectors
```bash

iocx --list-detectors

```

## Exit Codes
Code	Meaning
0	Success
1	Invalid arguments or runtime error

## ioc --help example
```text
usage: iocx [-h] [-o OUTPUT] [-p] [--no-cache] [--list-detectors] [--version] input

Static IOC extractor for binaries, logs, and text.

Input:
  input                 File path or raw text. Use '-' to read from stdin.

Output:
  -o OUTPUT, --output OUTPUT
                        Write JSON output to a file instead of stdout.
  -c, --compact         Minified JSON output.

Engine Options:
  --no-cache            Disable engine caching.

Detector Options:
  --list-detectors      List available detectors and exit.

Misc:
  --version             Show version and exit.
  -h, --help            Show this help message and exit.

```

## Design Philosophy

The CLI is intentionally minimal:

- One command (iocx)
- One required argument (input)
- A handful of intuitive flags
- No subcommands
- No unnecessary complexity
