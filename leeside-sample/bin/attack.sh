#!/usr/bin/env bash
# Malicious traffic (docs/windside.md section 4): one kind per run, each with
# a fresh store and one manifest; `all` runs every kind in sequence. Needs
# the tools from bin/tools.sh on PATH (ffuf, sqlmap, nuclei). Target: the
# local stack on 7391, never 7390.
set -eu
BIN="$(cd "$(dirname "$0")" && pwd)"
export PATH="$HOME/.local/bin:$PATH"
# shellcheck source=gen-lib.sh
source "$BIN/gen-lib.sh"

need() {
    command -v "$1" >/dev/null || { echo "missing $1: run bin/tools.sh (operator, needs sudo for apt)" >&2; exit 1; }
}

traffic_ffuf() { # $1=base $2=work: directory brute force. The wordlist
    # carries no #-comments (ffuf would request them) and no paths the app
    # never turns into events: ignored routes (/up) and files php -S serves
    # statically (/robots.txt, /.htaccess). Every line must produce exactly
    # one turn.
    need ffuf
    ffuf -u "$1/FUZZ" -w "$BIN/wordlist.txt" -s -mc all -o "$2/ffuf.json" -of json
    python3 -c "import json; print(len(json.load(open('$2/ffuf.json'))['results']))" >"$2/sent"
    echo "   ffuf: $(cat "$2/sent") paths requested"
}

traffic_sqlmap() { # $1=base $2=work: parameter injection on one query parameter
    need sqlmap
    sqlmap -u "$1/api/venues?limit=10" -p limit --batch --level 1 --risk 1 \
        --threads 4 --output-dir "$2/sqlmap" --flush-session >"$2/sqlmap.log" 2>&1
    echo "   sqlmap: parameter run on /api/venues?limit finished"
}

traffic_nuclei() { # $1=base $2=work: template scan, small template set
    need nuclei
    # -ni: no Interactsh callbacks (they would phone oast.site and their
    # requests would pollute the request count: only localhost counts).
    nuclei -u "$1" -t http/exposures/apis/,http/exposures/backups/,http/vulnerabilities/generic/ \
        -duc -ni -sj -retries 1 -o "$2/nuclei.txt" >"$2/nuclei.log" 2>&1
    touch "$2/sent_daemon"
    printf '%s\n' nuclei.txt nuclei.log >"$2/keep"
    echo "   nuclei: exposures apis/backups + generic scan finished"
}

traffic_scraper() { # $1=base $2=work: Python requests, spoofed Chrome UA, 300 ms cadence
    python3 "$BIN/scraper.py" "$1" 120
    echo 120 >"$2/sent"
}

traffic_scraper_nocookie() { # $1=base $2=work: same scraper, cookie persistence off
    python3 "$BIN/scraper.py" --no-cookie "$1" 120
    echo 120 >"$2/sent"
}

traffic_stuffing() { # $1=base $2=work: random bearers and API keys from one address
    local base="$1" work="$2" i
    for i in $(seq 1 50); do
        curl -sf -o /dev/null -H "X-Api-Key: wrong-$RANDOM-$RANDOM" "$base/api/ping" || true
    done
    for i in $(seq 1 50); do
        curl -sf -o /dev/null -H "Authorization: Bearer [REDACTED]" \
            -d "phone=0661111111&otp=00000$((i % 10))" "$base/portal/login" || true
    done
    echo 100 >"$work/sent"
    echo "   stuffing: 50 wrong API keys + 50 bearer logins"
}

traffic_forgery() { # $1=base $2=work: bad webhook signatures at high rate
    local base="$1" work="$2" i
    for i in $(seq 1 100); do
        curl -sf -o /dev/null -H 'Content-Type: application/json' \
            -H "X-Signature: 0badf00d$i" -H "X-Signer: acct_$((i % 5))" \
            -d '{"order":42}' "$base/webhooks/demo" || true
    done
    echo 100 >"$work/sent"
    echo "   forgery: 100 bad signatures"
}

traffic_honeytoken() { # $1=base $2=work: follow the hidden link, hit /admin-backup
    local base="$1" work="$2" i href
    for i in $(seq 1 20); do
        href=$(curl -sf -c "$work/jar" -b "$work/jar" "$base/" | grep -o '/admin-backup' | head -1)
        curl -sf -o /dev/null -c "$work/jar" -b "$work/jar" "$base$href" || true
        curl -sf -o /dev/null -c "$work/jar" -b "$work/jar" "$base/admin-backup" || true
    done
    echo 60 >"$work/sent"
    echo "   honeytoken: 20 hidden-link crawls with a cookie jar"
}

case "${1:-all}" in
    ffuf) gen_run attack-ffuf traffic_ffuf ;;
    sqlmap) gen_run attack-sqlmap traffic_sqlmap ;;
    nuclei) gen_run attack-nuclei traffic_nuclei ;;
    scraper) gen_run attack-scraper traffic_scraper ;;
    scraper-nocookie) gen_run attack-scraper-nocookie traffic_scraper_nocookie ;;
    stuffing) gen_run attack-stuffing traffic_stuffing ;;
    forgery) gen_run attack-forgery traffic_forgery ;;
    honeytoken) gen_run attack-honeytoken traffic_honeytoken ;;
    all)
        gen_run attack-ffuf traffic_ffuf
        gen_run attack-sqlmap traffic_sqlmap
        gen_run attack-nuclei traffic_nuclei
        gen_run attack-scraper traffic_scraper
        gen_run attack-scraper-nocookie traffic_scraper_nocookie
        gen_run attack-stuffing traffic_stuffing
        gen_run attack-forgery traffic_forgery
        gen_run attack-honeytoken traffic_honeytoken
        ;;
    *) echo "usage: $0 [ffuf|sqlmap|nuclei|scraper|scraper-nocookie|stuffing|forgery|honeytoken|all]" >&2; exit 1 ;;
esac
