# iocx Command‑Line Interface (CLI)

The IOCX CLI provides a fast, script‑friendly interface for extracting Indicators of Compromise (IOCs) from text, logs, binaries, and PE files. It wraps the same engine used by the Python API and exposes a clean, minimal set of options suitable for both interactive use and automation.

## Installation

```bash
pip install iocx
```

After installation, the `iocx` command becomes available on your system.

## Basic Usage

Extract IOCs from raw text:

```bash
iocx "Suspicious domain: evil.com"
```

Extract from a file:

```bash
iocx sample.exe
```

Read from stdin:

```bash
echo "visit http://malicious.com" | iocx -
```

## Command‑Line Options

The CLI is intentionally minimal: one command, one input, and a handful of focused flags.

### Input
| Flag  | Description                                        |
|-------|----------------------------------------------------|
| input | File path or raw text. Use `-` to read from stdin. |


### Output Options
| Flag                                           | Description                                        |
|------------------------------------------------|----------------------------------------------------|
| -o, --output FILE                              | Write JSON output to a file instead of stdout.     |
| -c, --compact                                  | Minify JSON output (no indentation).               |
| -e, --enrich                                   | Include enrichment metadata in the output          |
| -a, --analyse/--analyze `[basic, deep, full]`  | Enable PE analysis (default: deep)                 |

### Examples

```bash
iocx sample.txt --compact
iocx sample.txt -o results.json
iocx sample.exe -a full
```

## Engine Options
| Flag       | Description                                                                |
|------------|----------------------------------------------------------------------------|
| --no-cache | Disable engine caching. Useful for debugging or repeated extraction tests. |


## Detector, Transformer, and Enricher Options
| Flag                | Description                                                            |
|---------------------|------------------------------------------------------------------------|
| --list-detectors    | List all available detectors and exit.                                 |
| --list-transformers | List all available transformers and exit.                              |
| --list-enrichers    | List all available enrichers and exit.                                 |
| -m, --min-length    | Minimum printable string length for the string extractor (default: 4). |

### Example:

```bash
iocx --list-detectors
```

## Miscellaneous
| Flag             | Description                                                                  |
|------------------|------------------------------------------------------------------------------|
| --version        | Show the installed version of iocx.                                          |
| -d, --dev        | Loads plugins from the local environment (for plugin developers)             |


## Output Format

IOCX always emits JSON. By default, output is pretty‑printed with indentation.

### Example

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

Minified output:

```bash
iocx input.txt --compact
```

### Additional Examples

Extract from a PE file:

```bash
iocx malware.exe
```

Extract from logs:

```bash
iocx logs.txt -o iocs.json
```

Pipe data in:

```bash
cat suspicious.log | iocx - --compact
```

List detectors:

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
  -a [{basic,deep,full}], --analyse [{basic,deep,full}], --analyze [{basic,deep,full}]
                        Enable PE analysis (basic, deep, full; default: deep).

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
- A small, intuitive set of flags
- No subcommands
- No unnecessary complexity

The goal is to provide a fast, predictable, script‑friendly interface that mirrors the Python API without exposing internal complexity.
