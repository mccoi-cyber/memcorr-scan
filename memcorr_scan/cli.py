import argparse
import json
import sys

from .scanner import scan_paths

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_COLOR = {"critical": "\033[91m", "high": "\033[93m", "medium": "\033[94m", "low": "\033[90m"}
RESET = "\033[0m"


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="memcorr-scan",
        description="Keyless local static scanner for common C/C++ memory-corruption patterns.",
    )
    parser.add_argument("paths", nargs="+", help="Files or directories to scan")
    parser.add_argument("--json", metavar="FILE", help="Write full JSON report to FILE")
    parser.add_argument("--min-severity", choices=["low", "medium", "high", "critical"],
                         default="low", help="Only show findings at or above this severity")
    parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical", "never"],
                         default="never",
                         help="Exit non-zero if any finding at or above this severity is present "
                              "(useful as a CI gate)")
    args = parser.parse_args(argv)

    result = scan_paths(args.paths)
    min_rank = SEVERITY_ORDER[args.min_severity]
    shown = [f for f in result.findings if SEVERITY_ORDER[f.severity] <= min_rank]
    shown.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.line))

    print(f"memcorr-scan: {result.files_scanned} file(s) scanned, {len(result.findings)} finding(s)\n")
    counts = result.by_severity()
    print("  " + "  ".join(f"{sev}: {counts[sev]}" for sev in ("critical", "high", "medium", "low")))
    print()

    for f in shown:
        color = SEVERITY_COLOR.get(f.severity, "")
        print(f"{color}[{f.severity.upper()}] {f.title} ({f.cwe}){RESET}")
        print(f"  {f.file}:{f.line}")
        if f.snippet:
            print(f"    {f.snippet}")
        print(f"  -> {f.description}")
        print(f"  Fix: {f.recommendation}\n")

    if args.json:
        with open(args.json, "w") as out:
            json.dump({
                "files_scanned": result.files_scanned,
                "summary": counts,
                "findings": [vars(f) for f in result.findings],
            }, out, indent=2)
        print(f"Full JSON report written to {args.json}")

    if args.fail_on != "never":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] <= threshold for f in result.findings):
            sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
