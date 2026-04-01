import json
import sys
from pathlib import Path

def load_summaries(folder: Path):
    summaries = []
    for file in sorted(folder.glob("summary_*.json")):
        ts = file.stem.replace("summary_", "")
        with file.open() as f:
            data = json.load(f)
        summaries.append((ts, data))
    return summaries

def generate_dashboard(summaries):
    lines = []
    lines.append("# Performance Dashboard\n")
    lines.append("Automatically generated from historic performance runs.\n")

    if not summaries:
        lines.append("_No data available yet._")
        return "\n".join(lines)

    # Collect all metrics across all runs
    all_metrics = {}
    for ts, data in summaries:
        for name, value in data["metrics"].items():
            all_metrics.setdefault(name, {})[ts] = value

    # Group by category (first word)
    grouped = {}
    for full_name in all_metrics.keys():
        category = full_name.split()[0]
        grouped.setdefault(category, []).append(full_name)

    # Render each category
    for category in sorted(grouped.keys()):
        lines.append(f"\n## {category}\n")

        # For each metric inside the category
        for metric in sorted(grouped[category]):
            lines.append(f"\n### {metric}\n")
            lines.append("| Timestamp | Time (s) |")
            lines.append("|-----------|----------|")

            for ts, data in summaries:
                value = data["metrics"].get(metric)
                if value is not None:
                    lines.append(f"| {ts} | {value:.6f} |")

    return "\n".join(lines)

def main():
    if len(sys.argv) != 2:
        print("Usage: generate_perf_dashboard.py <summary-folder>")
        sys.exit(1)

    folder = Path(sys.argv[1])
    summaries = load_summaries(folder)
    md = generate_dashboard(summaries)
    print(md)

if __name__ == "__main__":
    main()
