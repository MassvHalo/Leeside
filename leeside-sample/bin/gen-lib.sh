#!/usr/bin/env bash
# Shared by bin/benign.sh and bin/attack.sh (docs/windside.md section 4).
# Every run starts leesided on 7391 with a fresh store: the count window
# never expires by time and all local traffic shares one net_hash, so a
# reused store would inherit the previous run's turns in its cluster
# windows and the labels would be wrong. Runs never overlap in time: this
# refuses to start when 7391 already answers, same as the e2e.
#
# Usage in the caller (after BIN=/SAMPLE-BIN setup):
#   source "$BIN/gen-lib.sh"
#   gen_run <kind> <traffic_fn>   # traffic_fn receives $BASE as $1
set -u

GEN_SAMPLE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN_LEESIDED="$GEN_SAMPLE/../leesided/target/release/leesided"
GEN_RULES="$GEN_SAMPLE/../leesided/rules/install"
GEN_API=127.0.0.1:7391
GEN_SERVE_PORT=8766
GEN_SOURCE=127.0.0.1
# Fixed test key, like the e2e's: deterministic hashes per install rule.
GEN_HASH_KEY="${GEN_HASH_KEY:-leeside-gen-test-key-do-not-use-in-production}"

gen_cleanup() {
    [ -n "${GEN_LPID:-}" ] && kill "$GEN_LPID" 2>/dev/null
    [ -n "${GEN_PPID:-}" ] && kill "$GEN_PPID" 2>/dev/null
    wait 2>/dev/null
    [ -n "${GEN_SOCKDIR:-}" ] && rm -rf "$GEN_SOCKDIR"
}

gen_run() {
    local kind="$1" traffic_fn="$2"
    local run_id="${kind}-$(date -u +%Y%m%dT%H%M%SZ)"
    # Work on disk, not tmpfs: /tmp is 918M here and a full tmpfs fails
    # runs with SQLite IO errors. Override with LEESIDE_RUN_TMP.
    local tmp_base="${LEESIDE_RUN_TMP:-$GEN_SAMPLE/runs/tmp}"
    mkdir -p "$tmp_base"
    local work="$tmp_base/leeside-gen-$run_id"
    # Sockets stay on tmpfs under a short path: sun_path caps at 108
    # bytes and the disk work path is far longer. Two inodes, no data.
    local sockdir="${LEESIDE_RUN_SOCK:-/tmp}/leeside-gen-$run_id"
    rm -rf "$sockdir"
    mkdir -p "$sockdir"
    GEN_SOCKDIR="$sockdir"
    local runs_dir="$GEN_SAMPLE/runs/$run_id"
    local base="http://127.0.0.1:$GEN_SERVE_PORT"

    [ -x "$GEN_LEESIDED" ] || { echo "build leesided first: (cd ../leesided && cargo build --release)" >&2; exit 1; }
    if curl -sf "http://$GEN_API/health" >/dev/null 2>&1; then
        echo "something already answers on $GEN_API (a run or the e2e?); runs never overlap" >&2
        exit 1
    fi
    if curl -sf -o /dev/null "http://127.0.0.1:$GEN_SERVE_PORT/" >/dev/null 2>&1; then
        echo "something already serves on $GEN_SERVE_PORT (a stale artisan serve?); stop it first" >&2
        exit 1
    fi

    trap gen_cleanup EXIT
    rm -rf "$work"; mkdir -p "$work/run"

    # Label routes (windside section 3): the sample app's honeytoken and
    # its completed business actions, so the auto-labelers fire on runs.
    LEESIDED_SOCKET_DIR="$sockdir" LEESIDED_DB="$work/gen.sqlite" LEESIDED_API="$GEN_API" \
    LEESIDED_RULES_DIR="$GEN_RULES" LEESIDED_HASH_KEY="$GEN_HASH_KEY" RUST_LOG=info \
    LEESIDED_HONEYTOKEN_ROUTES="admin.backup" \
    LEESIDED_BUSINESS_ROUTES="portal.login,api.ping,webhooks.demo" \
        "$GEN_LEESIDED" serve >"$work/leesided.log" 2>&1 &
    GEN_LPID=$!
    for _ in $(seq 1 50); do curl -sf "http://$GEN_API/health" >/dev/null && break; sleep 0.1; done
    curl -sf "http://$GEN_API/health" >/dev/null || { echo "leesided did not come up; see $work/leesided.log" >&2; exit 1; }

    # exec: the backgrounded subshell becomes php, so serve.pid is php's
    # pid and cleanup kills the server, not a dead subshell.
    (cd "$GEN_SAMPLE" && exec env LEESIDE_TRANSPORT=udg \
        LEESIDE_EVENTS_SOCKET="$sockdir/events.sock" LEESIDE_CHECK_SOCKET="$sockdir/check.sock" \
        LEESIDE_HASH_KEY="$GEN_HASH_KEY" \
        php artisan serve --host 127.0.0.1 --port "$GEN_SERVE_PORT" >"$work/php.log" 2>&1 &
        echo $! >"$work/serve.pid")
    GEN_PPID=$(cat "$work/serve.pid")
    for _ in $(seq 1 100); do curl -sf -o /dev/null "$base/" && break; sleep 0.1; done
    curl -sf -o /dev/null "$base/" || { echo "artisan serve did not come up; see $work/php.log" >&2; exit 1; }

    # The two warmup turns must have landed before the watermark: label
    # import calls everything after it run traffic, whatever its stamp.
    for _ in $(seq 1 50); do
        [ "$(sqlite3 "$work/gen.sqlite" "select count(*) from turns;")" = "2" ] && break
        sleep 0.1
    done
    [ "$(sqlite3 "$work/gen.sqlite" "select count(*) from turns;")" = "2" ] \
        || { echo "warmup turns did not land (want exactly 2)" >&2; exit 1; }
    local warmup_last_turn_id
    warmup_last_turn_id=$(sqlite3 "$work/gen.sqlite" "select turn_id from turns order by rowid desc limit 1;")
    [ -n "$warmup_last_turn_id" ] || { echo "warmup turn has no turn_id" >&2; exit 1; }

    # The stack is warm (the warmup hits are not generator traffic): the
    # manifest interval starts here, at millisecond precision so the two
    # warmup turns sharing start's second stay outside it.
    local start_ts start_ms start_iso end_ts end_ms end_iso
    start_ts=$(date +%s); start_ms=$(date +%s%3N); start_iso=$(date -u -d "@$start_ts" +%Y-%m-%dT%H:%M:%SZ)
    echo "== run $run_id: $kind on $base (store: fresh)"
    "$traffic_fn" "$base" "$work"
    sleep 3   # stragglers: events land after their responses
    end_ts=$(date +%s); end_ms=$(date +%s%3N); end_iso=$(date -u -d "@$end_ts" +%Y-%m-%dT%H:%M:%SZ)

    # Counts cover the manifest interval only: the two warmup hits predate
    # it and stay unlabeled, like any non-generator traffic would.
    # The send/store ledger: sent (generator count, or served minus the two
    # warmup hits when the tool reports none), served (artisan log lines,
    # static assets included), turns (interval rows), and the daemon's own
    # received/bad/dropped counters. A mismatch fails the run after the
    # manifest is written, so the evidence survives.
    local served received bad_event dropped max_dropped_since_last sent sent_source
    # Served lines carry the request path; pathless lines (connection noise,
    # malformed targets php -S answers itself) never reach Laravel and so
    # can never become turns.
    served=$(grep -acE '^  [0-9]{4}-.* /' "$work/php.log")
    received=$(curl -s "http://$GEN_API/health" | python3 -c 'import sys,json; print(json.load(sys.stdin)["ingest"]["total"])')
    bad_event=$(curl -s "http://$GEN_API/health" | python3 -c 'import sys,json; print(json.load(sys.stdin)["ingest"]["bad_event"])')
    dropped=$(curl -s "http://$GEN_API/health" | python3 -c 'import sys,json; print(json.load(sys.stdin)["store"]["dropped"])')
    # Served requests that can never become turns: static files php -S
    # answers itself, and the ignored /up health route. Only the
    # served-derived sent needs them subtracted (generators that report
    # their own count already exclude them).
    local static_hits up_hits
    static_hits=$(grep -aE '^  [0-9]{4}-.* /' "$work/php.log" | python3 -c "
import sys, os
from urllib.parse import unquote
n = 0
for line in sys.stdin:
    parts = line.split()
    if len(parts) < 3:
        continue
    path = unquote(parts[2].split('?')[0])
    if path.endswith('.php'):
        continue  # executed by php -S, so a turn, not a static file
    if os.path.isfile(os.path.join('$GEN_SAMPLE/public', path.lstrip('/'))):
        n += 1
print(n)
")
    up_hits=$(grep -acE '^  [0-9]{4}-.* /up( |$)' "$work/php.log" || true)
    if [ -f "$work/sent" ]; then
        sent=$(cat "$work/sent"); sent_source="generator"
    elif [ -f "$work/sent_daemon" ]; then
        # Tool-side counts include non-localhost noise (nuclei template
        # evals); the daemon's accepted count minus the two warmup events
        # is the exact localhost-sent. The tripwire below still guards
        # timestamp and write anomalies, plus bad/dropped explicitly.
        sent=$((received - 2)); sent_source="daemon"
    else
        sent=$((served - 2 - static_hits - up_hits)); sent_source="served"
    fi
    local turns actor_rows cluster_rows
    turns=$(sqlite3 "$work/gen.sqlite" "select count(*) from turns where ts_ms >= $start_ms and ts_ms <= $end_ms;")
    actor_rows=$(sqlite3 "$work/gen.sqlite" "select count(*) from feature_vectors where scope='actor' and ts_us >= $((start_ms * 1000)) and ts_us <= $((end_ms * 1000));")
    cluster_rows=$(sqlite3 "$work/gen.sqlite" "select count(*) from feature_vectors where scope='cluster' and ts_us >= $((start_ms * 1000)) and ts_us <= $((end_ms * 1000));")
    max_dropped_since_last=$(sqlite3 "$work/gen.sqlite" "select coalesce(max(dropped_since_last),0) from turns where ts_ms >= $start_ms and ts_ms <= $end_ms;")
    local by_surface
    by_surface=$(sqlite3 "$work/gen.sqlite" "select coalesce(surface,'null') || ':' || count(*) from feature_vectors where ts_us >= $((start_ms * 1000)) and ts_us <= $((end_ms * 1000)) group by surface order by count(*) desc;" | paste -sd' ' -)
    [ "$turns" -gt 0 ] || { echo "no turns landed in the interval; the stack was mismatched" >&2; exit 1; }

    mkdir -p "$runs_dir"
    python3 - "$runs_dir/manifest.json" <<EOF
import json,sys
json.dump({
    "run_id": "$run_id", "kind": "$kind",
    "start": "$start_iso", "start_ts": $start_ts, "start_ms": $start_ms,
    "end": "$end_iso", "end_ts": $end_ts, "end_ms": $end_ms,
    "source_address": "$GEN_SOURCE", "fresh_store": True,
    "warmup_last_turn_id": "$warmup_last_turn_id",
    "db": "gen.sqlite", "base_url": "$base",
    "turns": $turns, "actor_rows": $actor_rows, "cluster_rows": $cluster_rows,
    "sent": $sent, "sent_source": "$sent_source", "served": $served,
    "static_hits": $static_hits, "up_hits": $up_hits,
    "received": $received, "bad_event": $bad_event, "dropped": $dropped,
    "max_dropped_since_last": $max_dropped_since_last,
}, open(sys.argv[1], "w"), indent=2)
EOF
    # The daemon is done: stop it, fold the WAL into the database, then
    # copy. Copying while it runs leaves a stub: small stores never reach
    # the 1000-page auto-checkpoint, so the file holds almost nothing.
    trap - EXIT
    gen_cleanup
    for _ in $(seq 1 50); do
        kill -0 "$GEN_LPID" 2>/dev/null || break
        sleep 0.1
    done
    sqlite3 "$work/gen.sqlite" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null
    cp "$work/gen.sqlite" "$work/leesided.log" "$work/php.log" "$runs_dir/"
    # The copy must hold the run: a stub copy (WAL left behind) fails here,
    # not pages later in label-import.
    [ "$(sqlite3 "$runs_dir/gen.sqlite" "select count(*) from turns;")" = "$(sqlite3 "$work/gen.sqlite" "select count(*) from turns;")" ] \
        || { echo "DB COPY MISMATCH: $runs_dir/gen.sqlite lost turns; the checkpoint did not hold" >&2; exit 1; }
    if [ -f "$work/keep" ]; then
        while IFS= read -r kf; do cp "$work/$kf" "$runs_dir/" 2>/dev/null; done <"$work/keep"
    fi

    echo "   $kind | turns $turns | actor rows $actor_rows | cluster rows $cluster_rows | surfaces: $by_surface"
    echo "   sent $sent ($sent_source) | served $served (static $static_hits, up $up_hits) | received $received | bad $bad_event | dropped $dropped | max_dropped_since_last $max_dropped_since_last"
    echo "   manifest + db: $runs_dir"
    if [ "$bad_event" != "0" ] || [ "$dropped" != "0" ]; then
        echo "DIRTY RUN: bad_event=$bad_event dropped=$dropped; generator traffic must be clean" >&2
        exit 1
    fi
    if [ "$sent" != "$turns" ]; then
        echo "SENT-STORED MISMATCH: generator sent $sent but $turns turns landed; manifest + db kept for forensics" >&2
        echo "   forensics: db_total $(sqlite3 "$runs_dir/gen.sqlite" "select count(*) from turns;") | below_interval $(sqlite3 "$runs_dir/gen.sqlite" "select count(*) from turns where ts_ms < $start_ms;") | above_interval $(sqlite3 "$runs_dir/gen.sqlite" "select count(*) from turns where ts_ms > $end_ms;") | min_ts_ms $(sqlite3 "$runs_dir/gen.sqlite" "select min(ts_ms) from turns;") | max_ts_ms $(sqlite3 "$runs_dir/gen.sqlite" "select max(ts_ms) from turns;") | interval [$start_ms, $end_ms]" >&2
        exit 1
    fi

    # Green runs keep everything in runs/; the work dir (~6 MB on tmpfs)
    # goes, so stale runs cannot fill /tmp and fail later ones. Red runs
    # keep the work dir for forensics.
    rm -rf "$work"
}
