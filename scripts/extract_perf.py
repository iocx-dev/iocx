import json
import re
import sys
from pathlib import Path

# Matches lines like:
# [perf] engine end-to-end 1MB: 0.0354s
PERF_LINE = re.compile(r"\[perf\]\s+(?P<name>.+?):\s+(?P<value>[0-9.]+)s")

def parse_perf_log(path: Path):
    metrics = {}
    with path.open() as f:
        for line in f:
            m = PERF_LINE.search(line)
            if m:
                name = m.group("name").strip()
                value = float(m.group("value"))
                metrics[name] = value
    return metrics

def main():
    if len(sys.argv) != 4:
        print("Usage: extract_perf.py perf.log perf.json perf_summary.json")
        sys.exit(1)

    log_path = Path(sys.argv[1])
    json_path = Path(sys.argv[2])
    out_path = Path(sys.argv[3])

    # Parse raw log
    log_metrics = parse_perf_log(log_path)

    # Load pytest JSON report (optional)
    try:
        with json_path.open() as f:
            pytest_json = json.load(f)
    except Exception:
        pytest_json = {}

    summary = {
        "metrics": log_metrics,
        "pytest": pytest_json.get("summary", {}),
    }

    with out_path.open("w") as f:
        json.dump(summary, f, indent=2)

    print(f"Wrote summary to {out_path}")

if __name__ == "__main__":
    main()
