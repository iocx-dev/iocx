# iocx Command‑Line Interface (CLI)

The IOCX CLI provides a simple, fast way to extract Indicators of Compromise (IOCs) from text, logs, and binaries. It wraps the same engine used by the Python API and exposes a clean set of options suitable for both interactive use and scripting.

## Installation
```bash

pip install iocx

```

After installation, the `iocx` command becomes available on your system.

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

echo "visit http://malicious.com" | iocx -

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
| -e, --enrich       | Add detection enrichment data to the output        |

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
| Flag                | Description                                                            |
|---------------------|------------------------------------------------------------------------|
| --list-detectors    | Print all available detectors and exit.                                |
| --list-transformers | Print all available transformers and exit.                             |
| --list-enrichers    | Print all available enrichers and exit.                                |
| -m, --min-length    | Minimum printable string length for the string extractor (default: 4). |

### Example:
```bash

iocx --list-detectors

```

## Misc
| Flag             | Description                                                                  |
|------------------|------------------------------------------------------------------------------|
| --version        | Show the installed version of iocx.                                          |
| -d, --dev        | Intended for plugin developers. Loads plugins from the local environment     |


## Output Format

The CLI always emits JSON (Indent=2 by default). A typical output structure looks like:
```json
{
  "file": "example.txt",
  "type": "text",
  "iocs": {
    "urls": ["http://example.com"],
    "domains": ["example.com"],
    "emails": [],
    "ips": [],
    "filepaths": [],
    "hashes": [],
    "base64": []
  },
  "metadata": {}
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
| Code | Meaning                            |
|------|------------------------------------|
|  0   | Success                            |
|  1   | Invalid arguments or runtime error |

## iocx --help example
```text
usage: iocx [-h] [-o OUTPUT] [-c] [-e] [--no-cache] [--list-detectors] [--list-transformers] [--list-enrichers] [-m N] [--version] [-d] [input]

Static IOC extractor for binaries, logs, and text.

options:
  -h, --help            show this help message and exit

Input:
  input                 File path or raw text. Use '-' to read from stdin.

Output:
  -o OUTPUT, --output OUTPUT
                        Write JSON output to a file instead of stdout.
  -c, --compact         Output compact (minified) JSON.
  -e, --enrich          Write enrichment data to the JSON output.

Engine Options:
  --no-cache            Disable engine caching.

Detector Options:
  --list-detectors      List available detectors and exit.
  --list-transformers   List available transformer plugins.
  --list-enrichers      List available enricher plugins.
  -m N, --min-length N  Minimum printable string length for the string extractor (default: 4).

Misc:
  --version             Show version and exit.
  -d, --dev             Enable local plugins.
```

## Design Philosophy

The CLI is intentionally minimal:

- One command (iocx)
- One required argument (input)
- A handful of intuitive flags
- No subcommands
- No unnecessary complexity
