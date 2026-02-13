import json
import argparse
from ..engine import extract_iocs

def main():
    parser = argparse.ArgumentParser(description="Static IOC extractor")
    parser.add_argument("input", help="File path or raw text")
    args = parser.parse_args()

    result = extract_iocs(args.input)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
