#!/usr/bin/env python3
"""Turn a JA4 mapping CSV (FoxIO's ja4plus-mapping.csv shape, or a ja4db
export with at least `ja4` and `Application`/`Library` columns) into
data/ja4-classes.json for leesided's ua_vs_ja4_mismatch flag.

    bin/ja4-classes.py ja4plus-mapping.csv > data/ja4-classes.json

Classes are assigned by name against two small lists; anything else is
`unknown`, which never flags. Edit the lists, not the output.
"""
import csv, json, sys

BROWSERS = ("chrome", "chromium", "firefox", "safari", "edge", "opera", "brave", "vivaldi", "webkit")
LIBRARIES = ("python", "golang", "go-http", "go net", "curl", "wget", "okhttp", "java", "node", "axios",
             "requests", "urllib", "libcurl", "ruby", "php", "perl", "rust", "reqwest", "hyper", ".net", "dotnet",
             "powershell", "scrapy", "masscan", "nmap", "zgrab", "sqlmap", "nuclei", "ffuf", "httpx", "aiohttp")


def classify(application: str, library: str) -> str:
    name = f"{application} {library}".lower()
    if library.strip():
        return "library"
    if any(b in name for b in BROWSERS):
        return "browser"
    if any(l in name for l in LIBRARIES):
        return "library"
    return "unknown"


def main(path: str) -> None:
    entries, seen = [], set()
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            ja4 = (row.get("ja4") or row.get("ja4_fingerprint") or "").strip()
            if not ja4 or ja4 in seen or ja4.count("_") != 2:
                continue
            seen.add(ja4)
            application = (row.get("Application") or row.get("application") or "").strip()
            library = (row.get("Library") or row.get("library") or "").strip()
            entries.append({"ja4": ja4, "class": classify(application, library),
                            "application": application or library})
    json.dump({"source": f"{path}, classes assigned by bin/ja4-classes.py", "entries": entries},
              sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
