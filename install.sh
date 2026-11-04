#!/usr/bin/env bash
# Leeside product installer: leesided, the tap and Windside on an Ubuntu
# 22.04 or 24.04 box that already hosts a Laravel app behind nginx.
# Run as: curl -sSL https://raw.githubusercontent.com/MassvHalo/Leeside/master/install.sh | sudo bash
# The Laravel package is printed instructions at the end.
#
# Env overrides (all optional): LEESIDE_BINARY (a local leesided binary
# to install instead of downloading; with it set the box never contacts
# the release, so the model and rules downloads are skipped too),
# LEESIDE_DOMAIN, LEESIDE_LLM_KEY, LEESIDE_GEOIP_ACCOUNT,
# LEESIDE_GEOIP_KEY. Flags: --yes (skip prompts), --uninstall [--purge],
# --help.
set -euo pipefail

GH_REPO="MassvHalo/Leeside"
RELEASE_BASE="https://github.com/${GH_REPO}/releases/latest/download"
BIN_NAME="" # set in main from uname -m; see bin_name
BIN_PATH="/usr/local/bin/leesided"
ENV_DIR="/etc/leeside"
ENV_FILE="/etc/leeside/leesided.env"
INSTALL_CONF="/etc/leeside/install.conf"
MODEL_DIR="/var/lib/leeside/windside-model"
RULES_NAME="leesided-rules.tar.gz"
RULES_DIR="/usr/local/bin/rules/install"
RULES_SHA="/etc/leeside/rules.sha256"
DATA_DIR="/usr/local/bin/data"
LIB_DIR="/var/lib/leeside"
RUN_DIR="/run/leeside"
TMPFILES_ENTRY="/etc/tmpfiles.d/leeside.conf"
NGINX_SNIPPET="/etc/nginx/snippets/windside.conf"
NGINX_ZONE="/etc/nginx/conf.d/windside.conf"
NGINX_INCLUDE="include snippets/windside.conf;"
DAEMON_UNIT="/etc/systemd/system/leesided.service"
TAP_UNIT="/etc/systemd/system/leesided-tap.service"
HEALTH_URL="http://127.0.0.1:7390/health"

log() { printf '%s\n' "$*"; }
die() {
    # die <what-failed> <what-to-do>
    printf 'ERROR: %s\nFix: %s\n' "$1" "$2" >&2
    exit 1
}

check_root() {
    [ "$(id -u)" = "0" ] || die "run as root." "rerun with sudo: curl -sSL https://raw.githubusercontent.com/${GH_REPO}/master/install.sh | sudo bash"
}

check_arch() {
    # check_arch <uname -m>; the release carries x86_64 and aarch64 binaries.
    case "$1" in
        x86_64|aarch64) ;;
        *) die "this CPU is $1; the release ships x86_64 and aarch64." "install on an x86_64 or aarch64 box, or build from source: git clone https://github.com/${GH_REPO} && cd Leeside/leesided && cargo build --release" ;;
    esac
}

bin_name() {
    # bin_name <uname -m>; prints the release asset for this CPU.
    case "$1" in
        x86_64) echo "leesided-x86_64-linux" ;;
        aarch64) echo "leesided-aarch64-linux" ;;
        *) return 1 ;;
    esac
}

distro_ok() {
    # distro_ok <ID> <VERSION_ID>; succeeds on Ubuntu 22.04/24.04.
    if [ "$1" = "ubuntu" ] && { [ "$2" = "22.04" ] || [ "$2" = "24.04" ]; }; then
        return 0
    fi
    return 1
}

check_distro() {
    [ -r /etc/os-release ] || die "no /etc/os-release; cannot tell the distro." "run on Ubuntu 22.04 or 24.04"
    # shellcheck disable=SC1091
    . /etc/os-release
    distro_ok "${ID:-}" "${VERSION_ID:-}" || die "this is ${ID:-unknown} ${VERSION_ID:-unknown}; need Ubuntu 22.04 or 24.04." "run on Ubuntu 22.04 or 24.04"
}

check_www_data() {
    id -u www-data >/dev/null 2>&1 || die "no www-data user; the box should already host the Laravel app." "install nginx and php-fpm first (Ubuntu: apt-get install -y nginx php-fpm), then rerun"
}

apt_base() {
    # $1 is VERSION_ID; the pcap package renamed in 24.04 (t64 transition).
    local pcap="libpcap0.8"
    if [ "$1" = "24.04" ]; then pcap="libpcap0.8t64"; fi
    export DEBIAN_FRONTEND=noninteractive
    apt-get update || die "apt-get update failed." "check DNS and the apt sources, then rerun (the install is idempotent)"
    # shellcheck disable=SC2086
    apt-get install -y curl ca-certificates openssl sqlite3 $pcap \
        || die "apt-get install failed." "run it by hand to see the conflict, fix it, then rerun"
    command -v curl >/dev/null || die "curl still missing after apt." "apt-get install -y curl, then rerun"
    command -v openssl >/dev/null || die "openssl still missing after apt." "apt-get install -y openssl, then rerun"
}

download() {
    # download <url> <dest>; retries, fails loudly with a fix.
    curl -sSL --fail --retry 3 --retry-delay 2 --connect-timeout 15 -o "$2" "$1" \
        || die "download failed: $1" "check network access to github.com, then rerun"
    [ -s "$2" ] || die "downloaded an empty file: $1" "rerun; if it repeats, the release asset is missing"
}

sha_of() { sha256sum "$1" | awk '{print $1}'; }

verify_sha256() {
    # verify_sha256 <file> <sha-file>; the sha file holds either a bare
    # hash or sha256sum output.
    local want
    want="$(awk '{print $1}' "$2")"
    [ "$(sha_of "$1")" = "$want" ] || die "hash mismatch on $1." "delete $1 and rerun; if it repeats, the release asset is corrupt"
}

install_binary() {
    # Installs the daemon binary. Prints "changed" or "kept".
    if [ -n "${LEESIDE_BINARY:-}" ]; then
        [ -f "$LEESIDE_BINARY" ] || die "LEESIDE_BINARY=$LEESIDE_BINARY is not a file." "point it at a leesided binary"
        if [ -f "$BIN_PATH" ] && [ "$(sha_of "$LEESIDE_BINARY")" = "$(sha_of "$BIN_PATH")" ]; then
            echo "kept"
            return 0
        fi
        log "local binary $LEESIDE_BINARY: skipping the hash check." >&2
        install -m 0755 "$LEESIDE_BINARY" "$BIN_PATH" \
            || die "cannot write $BIN_PATH." "check disk space and permissions, then rerun"
        echo "changed"
        return 0
    fi
    local tmp sha_url
    tmp="$(mktemp -d)" || die "cannot make a temp dir." "check TMPDIR and disk space, then rerun"
    sha_url="${RELEASE_BASE}/${BIN_NAME}.sha256"
    download "$sha_url" "$tmp/sha256"
    if [ -f "$BIN_PATH" ] && [ "$(sha_of "$BIN_PATH")" = "$(awk '{print $1}' "$tmp/sha256")" ]; then
        rm -rf "$tmp"
        echo "kept"
        return 0
    fi
    download "${RELEASE_BASE}/${BIN_NAME}" "$tmp/leesided"
    verify_sha256 "$tmp/leesided" "$tmp/sha256"
    install -m 0755 "$tmp/leesided" "$BIN_PATH" \
        || die "cannot write $BIN_PATH." "check disk space and permissions, then rerun"
    rm -rf "$tmp"
    echo "changed"
}

make_dirs() {
    mkdir -p "$ENV_DIR" "$LIB_DIR" "$MODEL_DIR" \
        || die "cannot create $ENV_DIR / $LIB_DIR / $MODEL_DIR." "check disk space and permissions, then rerun"
    chown -R www-data:www-data "$LIB_DIR" \
        || die "cannot chown $LIB_DIR to www-data." "check the www-data user exists, then rerun"
    printf 'd %s 0770 www-data www-data -\n' "$RUN_DIR" > "$TMPFILES_ENTRY" \
        || die "cannot write $TMPFILES_ENTRY." "check disk space and permissions, then rerun"
    systemd-tmpfiles --create "$TMPFILES_ENTRY" \
        || die "systemd-tmpfiles failed." "run systemd-tmpfiles --create $TMPFILES_ENTRY by hand to see why, then rerun"
}

install_model() {
    # Fetches the model files when missing; leaves present ones alone.
    # A local binary means an offline box: the release is never contacted.
    if [ -n "${LEESIDE_BINARY:-}" ]; then
        echo "skipped (LEESIDE_BINARY set: offline mode, the release is never contacted)"
        return 0
    fi
    local changed=0 f
    for f in manifest.json model.txt; do
        if [ ! -s "$MODEL_DIR/$f" ]; then
            download "${RELEASE_BASE}/$f" "$MODEL_DIR/$f"
            changed=1
        fi
    done
    chown www-data:www-data "$MODEL_DIR/manifest.json" "$MODEL_DIR/model.txt" \
        || die "cannot chown the model files." "check the www-data user exists, then rerun"
    [ "$changed" = "1" ] && echo "changed" || echo "kept"
}

rules_current() {
    # rules_current <want-sha>; true when the installed rules match and
    # the directory actually holds rules.
    [ -f "$RULES_SHA" ] || return 1
    [ "$(cat "$RULES_SHA")" = "$1" ] || return 1
    [ -n "$(ls "$RULES_DIR"/*.json 2>/dev/null)" ] || return 1
    return 0
}

apply_rules() {
    # apply_rules <tarball> <sha-file> <want-sha>; verifies and places
    # the generic install set and the JA4 classes where each default
    # lookup finds them.
    verify_sha256 "$1" "$2"
    local stage
    stage="$(mktemp -d)" || die "cannot make a temp dir." "check TMPDIR and disk space, then rerun"
    tar -xzf "$1" -C "$stage" || die "cannot extract the rules tarball." "check disk space, then rerun"
    [ -n "$(ls "$stage"/*.json 2>/dev/null)" ] || die "the rules tarball held no rules." "check the release asset, then rerun"
    [ -f "$stage/data/ja4-classes.json" ] || die "the rules tarball held no JA4 classes." "check the release asset, then rerun"
    mkdir -p "$RULES_DIR" || die "cannot create $RULES_DIR." "check disk space and permissions, then rerun"
    rm -f "$RULES_DIR"/*.json
    cp "$stage"/*.json "$RULES_DIR"/ || die "cannot place the rules." "check disk space and permissions, then rerun"
    mkdir -p "$DATA_DIR" || die "cannot create $DATA_DIR." "check disk space and permissions, then rerun"
    install -m 0644 "$stage/data/ja4-classes.json" "$DATA_DIR/ja4-classes.json" \
        || die "cannot place the JA4 classes." "check disk space and permissions, then rerun"
    rm -rf "$stage"
    printf '%s\n' "$3" > "$RULES_SHA" || die "cannot write $RULES_SHA." "check disk space and permissions, then rerun"
    chmod 600 "$RULES_SHA" || die "cannot chmod $RULES_SHA." "check disk space and permissions, then rerun"
}

install_rules() {
    # Downloads, verifies and extracts the generic install rules.
    # Prints "changed", "kept", or the offline skip. A local binary
    # means an offline box: the release is never contacted.
    if [ -n "${LEESIDE_BINARY:-}" ]; then
        echo "skipped (LEESIDE_BINARY set: offline mode, the release is never contacted)"
        return 0
    fi
    local tmp want
    tmp="$(mktemp -d)" || die "cannot make a temp dir." "check TMPDIR and disk space, then rerun"
    download "${RELEASE_BASE}/${RULES_NAME}.sha256" "$tmp/sha256"
    want="$(awk '{print $1}' "$tmp/sha256")"
    if rules_current "$want"; then
        rm -rf "$tmp"
        echo "kept"
        return 0
    fi
    download "${RELEASE_BASE}/${RULES_NAME}" "$tmp/rules.tar.gz"
    apply_rules "$tmp/rules.tar.gz" "$tmp/sha256" "$want"
    rm -rf "$tmp"
    echo "changed"
}

read_answer() {
    # read_answer <varname> <prompt> <secret:0|1>; reads one line from the
    # terminal (stdin is the script under curl|bash).
    local var="$1" prompt="$2" secret="$3" val
    [ -r /dev/tty ] || die "no terminal to ask $var." "rerun with --yes and the LEESIDE_* env vars (see --help)"
    if [ "$secret" = "1" ]; then
        read -r -s -p "$prompt" val < /dev/tty || die "cannot read from the terminal." "rerun with --yes and the LEESIDE_* env vars"
        printf '\n' >&2
    else
        read -r -p "$prompt" val < /dev/tty || die "cannot read from the terminal." "rerun with --yes and the LEESIDE_* env vars"
    fi
    printf -v "$var" '%s' "$val"
}

ask() {
    # ask <varname> <env-name> <prompt> <secret:0|1>
    # Env wins, --yes keeps the blank, else the terminal is asked.
    # Every answer may be blank; each has a graceful fallback.
    local var="$1" env="$2" prompt="$3" secret="$4" val
    val="${!env:-}"
    if [ -z "$val" ] && [ "${YES:-0}" = "0" ]; then
        read_answer "$var" "$prompt" "$secret"
    else
        printf -v "$var" '%s' "$val"
    fi
}

rand_hex() { openssl rand -hex 32 || die "openssl rand failed." "check the openssl install, then rerun"; }

write_env() {
    # write_env <dir> <llm-key-or-empty>; writes the daemon env, mode 600.
    # Prints the three generated secrets on one line (space-separated) for
    # the once-only summary; the file is the record afterwards.
    local dir="$1" llm_key="$2" mode="off"
    local hash_key api_token viewer_token
    if [ -n "$llm_key" ]; then mode="live"; fi
    hash_key="$(rand_hex)"
    api_token="$(rand_hex)"
    viewer_token="$(rand_hex)"
    ( umask 077
    cat > "$dir/leesided.env" <<EOF
# Leeside daemon environment (written by install.sh $(date -u +%F); mode 600).
LEESIDED_HASH_KEY=$hash_key
LEESIDED_API_TOKEN=$api_token
LEESIDED_VIEWER_TOKEN=$viewer_token
LEESIDED_CONSOLE_PATH=/windside
LEESIDED_TRUSTED_PROXY=127.0.0.1
LEESIDED_CONSOLE_ALLOW=
LEESIDED_LLM_URL=https://inference.baseten.co/v1
LEESIDED_LLM_MODEL=meta-models/muse-spark-open-1026
LEESIDED_LLM_KEY=$llm_key
LEESIDED_LLM_MODE=$mode
LEESIDED_WINDSIDE_MODE=shadow
LEESIDED_WINDSIDE_MODEL=$MODEL_DIR
# Route names are this app's; list them once known (restart leesided after).
LEESIDED_HONEYTOKEN_ROUTES=
LEESIDED_BUSINESS_ROUTES=
EOF
    ) || die "cannot write $dir/leesided.env." "check disk space and permissions, then rerun"
    chmod 600 "$dir/leesided.env" \
        || die "cannot chmod $dir/leesided.env." "check disk space and permissions, then rerun"
    printf '%s %s %s\n' "$hash_key" "$api_token" "$viewer_token"
}

env_value() {
    # env_value <file> <key>; prints the value of a KEY=value line.
    grep -E "^$2=" "$1" | tail -1 | cut -d= -f2-
}

write_units() {
    cat > "$DAEMON_UNIT" <<'EOF' || die "cannot write $DAEMON_UNIT." "check disk space and permissions, then rerun"
[Unit]
Description=Leeside daemon (rules, check and event sockets)
After=network.target
Wants=network.target
Conflicts=leeside-artisan-tap.service

[Service]
Type=simple
User=www-data
Group=www-data
# /run/leeside comes from /etc/tmpfiles.d/leeside.conf (0770 www-data).
Environment=LEESIDED_SOCKET_DIR=/run/leeside
Environment=LEESIDED_DB=/var/lib/leeside/leesided.sqlite
Environment=LEESIDED_API=127.0.0.1:7390
# GeoLite2 for asn and country enrichment. With the files absent leesided
# logs once and leaves the columns null.
Environment=LEESIDED_GEOIP_ASN=/var/lib/GeoIP/GeoLite2-ASN.mmdb
Environment=LEESIDED_GEOIP_COUNTRY=/var/lib/GeoIP/GeoLite2-Country.mmdb
Environment=RUST_LOG=info
# No LEESIDED_RULES_DIR: the default lookup finds the install set at
# /usr/local/bin/rules/install. App-specific rules go through the
# overrides file.
EnvironmentFile=/etc/leeside/leesided.env
StateDirectory=leeside
ExecStart=/usr/local/bin/leesided serve
StandardError=journal
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
    cat > "$TAP_UNIT" <<'EOF' || die "cannot write $TAP_UNIT." "check disk space and permissions, then rerun"
[Unit]
Description=Leeside passive fingerprint tap (JA4 and JA4T to leesided)
After=leesided.service
Wants=leesided.service

[Service]
Type=simple
User=www-data
Group=www-data
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=yes
Environment=LEESIDED_SOCKET_DIR=/run/leeside
Environment=LEESIDED_TAP_PORTS=80,443
Environment=LEESIDED_TAP_TLS_PORTS=443
# LEESIDED_TAP_IFACE may be set in leesided.env; unset, the tap takes the
# interface of the default route.
Environment=RUST_LOG=info
EnvironmentFile=-/etc/leeside/leesided.env
ExecStart=/usr/local/bin/leesided tap
StandardError=journal
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
}

setup_geoip() {
    # setup_geoip <account> <key>; installs geoipupdate, fetches the two
    # databases the daemon reads. Skipped when either is blank.
    [ -n "$1" ] && [ -n "$2" ] || { log "GeoIP skipped (no account/key)."; return 0; }
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y geoipupdate \
        || die "apt-get install geoipupdate failed." "run it by hand to see the conflict, then rerun"
    if [ -f /etc/GeoIP.conf ]; then
        cp /etc/GeoIP.conf /etc/GeoIP.conf.pre-leeside \
            || die "cannot back up /etc/GeoIP.conf." "check disk space and permissions, then rerun"
        log "existing /etc/GeoIP.conf backed up to /etc/GeoIP.conf.pre-leeside."
    fi
    cat > /etc/GeoIP.conf <<EOF || die "cannot write /etc/GeoIP.conf." "check disk space and permissions, then rerun"
# Written by the Leeside installer.
AccountID $1
LicenseKey $2
EditionIDs GeoLite2-ASN GeoLite2-Country
EOF
    chmod 600 /etc/GeoIP.conf \
        || die "cannot chmod /etc/GeoIP.conf." "check disk space and permissions, then rerun"
    geoipupdate -v || die "geoipupdate failed." "check the account id and key in /etc/GeoIP.conf, then run geoipupdate -v by hand"
    [ -s /var/lib/GeoIP/GeoLite2-ASN.mmdb ] && [ -s /var/lib/GeoIP/GeoLite2-Country.mmdb ] \
        || die "geoipupdate ran but the databases are missing." "run geoipupdate -v by hand to see why"
    log "GeoIP databases installed."
}

start_services() {
    systemctl daemon-reload || die "systemctl daemon-reload failed." "run it by hand to see why"
    systemctl enable --now leesided leesided-tap \
        || die "cannot start leesided." "run journalctl -u leesided --no-pager | tail -30 to see why"
}

wait_health() {
    local i
    for i in $(seq 1 60); do
        if curl -sf -o /dev/null "$HEALTH_URL" 2>/dev/null; then return 0; fi
        sleep 2
    done
    die "leesided never answered /health." "run journalctl -u leesided --no-pager | tail -30 and systemctl status leesided"
}

write_nginx_files() {
    # The locations are server-level, so they live in the snippet; the
    # zone is http-level, so it lives in conf.d (included at http level
    # by the stock nginx.conf). One file cannot hold both.
    cat > "$NGINX_SNIPPET" <<EOF || die "cannot write $NGINX_SNIPPET." "check disk space and permissions, then rerun"
# Windside console (written by the Leeside installer $(date -u +%F)).
# Included inside the app's server block(s); the daemon serves the
# paths itself, so there is no rewrite.
location = /windside { return 301 /windside/; }
location = /windside/login {
    limit_req zone=windside_login burst=5 nodelay;
    proxy_pass http://127.0.0.1:7390;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_read_timeout 15s;
}
location /windside/ {
    proxy_pass http://127.0.0.1:7390;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_read_timeout 15s;
}
EOF
    cat > "$NGINX_ZONE" <<EOF || die "cannot write $NGINX_ZONE." "check disk space and permissions, then rerun"
# Windside console login rate limit (written by the Leeside installer $(date -u +%F)).
limit_req_zone \$binary_remote_addr zone=windside_login:1m rate=5r/m;
EOF
}

find_domain_conf() {
    # find_domain_conf <sites-enabled-dir> <domain>; prints the conf
    # whose server_name mentions the domain, or nothing.
    local dir="$1" domain="$2" f
    local esc="${domain//./\\.}"
    for f in "$dir"/*; do
        [ -f "$f" ] || continue
        if grep -Eq "server_name[^;]*[[:space:]]$esc([[:space:];]|$)" "$f" 2>/dev/null; then
            printf '%s\n' "$f"
            return 0
        fi
    done
    return 0
}

insert_include() {
    # insert_include <conf>; adds the snippet include before the closing
    # brace of every top-level server block. Idempotent.
    local conf="$1"
    if grep -Fq "$NGINX_INCLUDE" "$conf" 2>/dev/null; then return 0; fi
    local tmp
    tmp="$(mktemp)" || die "cannot make a temp file." "check TMPDIR and disk space, then rerun"
    awk -v inc="$NGINX_INCLUDE" '
        /server[[:space:]]*\{/ && !in_server { in_server = 1; opened = NR }
        in_server {
            line = $0
            opens = gsub(/\{/, "{", line)
            closes = gsub(/\}/, "}", line)
            depth += opens - closes
            if (depth == 0) {
                if (NR > opened) { print "\t" inc }
                in_server = 0
            }
        }
        { print }
    ' "$conf" > "$tmp" || die "cannot edit $conf." "add the line by hand (see below), then run nginx -t"
    cat "$tmp" > "$conf" || die "cannot write $conf." "check disk space and permissions, then rerun"
    rm -f "$tmp"
}

setup_nginx() {
    # setup_nginx <domain-or-empty>; wires the console into nginx, or
    # prints the by-hand step when the conf cannot be found.
    write_nginx_files
    local conf=""
    if [ -n "$1" ]; then
        conf="$(find_domain_conf /etc/nginx/sites-enabled "$1")"
    fi
    if [ -z "$conf" ]; then
        if [ -z "$1" ] && [ "${YES:-0}" = "1" ]; then
            log "WARNING: no domain given; the console is not wired into nginx."
        fi
        log "nginx: no sites-enabled conf mentions ${1:-<no domain given>}."
        manual_nginx
        return 0
    fi
    conf="$(readlink -f "$conf")"
    cp "$conf" "$conf.pre-leeside" \
        || die "cannot back up $conf." "check disk space and permissions, then rerun"
    log "nginx conf backed up to $conf.pre-leeside."
    insert_include "$conf"
    nginx -t || die "nginx -t failed after the include." "restore $conf.pre-leeside over $conf, run nginx -t, and add the line by hand (see below)"
    if ! nginx -T 2>/dev/null | grep -q "zone=windside_login"; then
        log "WARNING: this nginx.conf does not include conf.d; the login limit zone is not loaded."
        log "Add this at http level (outside any server block) by hand: limit_req_zone \$binary_remote_addr zone=windside_login:1m rate=5r/m;"
    fi
    systemctl reload nginx || die "nginx reload failed." "run nginx -t and systemctl status nginx to see why"
    log "nginx: console proxied."
}

manual_nginx() {
    cat <<EOF
Add the console to the app's nginx server block by hand:

    $NGINX_INCLUDE

inside the server block (both of them when the conf has an HTTP and an
HTTPS server), then run: nginx -t && systemctl reload nginx
The files $NGINX_SNIPPET and $NGINX_ZONE are already in place.
EOF
}

print_summary() {
    # print_summary <domain-or-empty> <hash> <api> <viewer> <fresh:0|1>
    # Secrets print only on a fresh install; a re-run re-prints the
    # viewer token (read back from the kept env file) and points at the
    # file for the rest.
    local domain="$1" hash_key="$2" api_token="$3" viewer_token="$4" fresh="$5"
    local url="http://127.0.0.1:7390/windside/"
    if [ -n "$domain" ]; then url="https://$domain/windside/"; fi
    cat <<EOF

================ Leeside installed ================
Windside console: $url
EOF
    if [ "$fresh" = "1" ]; then
        cat <<EOF
Viewer token (read-only, safe to share): $viewer_token

The next two lines print ONCE. Copy them now; afterwards they live
only in $ENV_FILE (root-readable).
Admin token (full console access): $api_token
Hash key (LEESIDE_HASH_KEY below): $hash_key
EOF
    else
        cat <<EOF
Viewer token (read-only, safe to share): $viewer_token
Admin token and hash key unchanged; read them as root from $ENV_FILE.
EOF
    fi
    local rules_n=0 f rules_line
    for f in "$RULES_DIR"/*.json; do
        [ -f "$f" ] || continue
        rules_n=$((rules_n + 1))
    done
    rules_line="none installed (offline mode, or the download was skipped)"
    if [ "$rules_n" -gt 0 ]; then
        rules_line="$rules_n generic rules in $RULES_DIR"
    fi
    local geoip_line="skipped (no MaxMind account/key at install time)"
    if [ -s "${GEOIP_DB:-/var/lib/GeoIP/GeoLite2-Country.mmdb}" ]; then
        geoip_line="installed; the geoipupdate package refreshes them twice weekly on its own timer"
    fi
    cat <<EOF
Rules: $rules_line.
App-specific rules go through the overrides file when ready.
GeoIP: $geoip_line.
Turn enforcement on: fresh installs watch only; the global mode starts at monitor and the install rules start as shadow, so run both steps when you are ready for Leeside to act; PUT /mode {"mode":"monitor"} is the kill switch.
  source $ENV_FILE
  curl -s -X PUT http://127.0.0.1:7390/mode -H "Authorization: Bearer \$LEESIDED_API_TOKEN" -H "Content-Type: application/json" -d '{"mode":"enforce"}'
  for f in /usr/local/bin/rules/install/*.json; do curl -s -X PUT "http://127.0.0.1:7390/rules/\$(basename "\$f" .json)" -H "Authorization: Bearer \$LEESIDED_API_TOKEN" -H "Content-Type: application/json" -d @"\$f"; echo; done
--------------------------------------------------------
Laravel app steps (as the app user, in the app directory):

    git clone https://github.com/${GH_REPO} /opt/leeside   # or anywhere the app user can read
    composer config repositories.leeside '{"type":"path","url":"/opt/leeside/leeside-laravel","options":{"symlink":true}}'
    composer require 'leeside/laravel:@dev'

Then in the app's .env:

    LEESIDE_HASH_KEY=$([ "$fresh" = "1" ] && printf '%s' "$hash_key" || printf '<the value in %s>' "$ENV_FILE")
    LEESIDE_TAG_SECRET=<run once: openssl rand -hex 32; keep it stable afterwards>
    LEESIDE_EVENTS_SOCKET=$RUN_DIR/events.sock
    LEESIDE_CHECK_SOCKET=$RUN_DIR/check.sock

The provider registers its middleware itself. Three wirings stay with
the app (leeside-laravel/README.md): keep the _lsd cookie in clear,
verify webhook signatures ahead of the gate, vouch for API keys.
========================================================
EOF
}

uninstall() {
    # uninstall <purge:0|1>
    command -v systemctl >/dev/null || die "no systemctl here." "remove the install by hand (units, /usr/local/bin/leesided, /etc/leeside)"
    log "stopping leesided and leesided-tap."
    systemctl stop leesided leesided-tap 2>/dev/null || true
    systemctl disable leesided leesided-tap 2>/dev/null || true
    rm -f "$DAEMON_UNIT" "$TAP_UNIT"
    systemctl daemon-reload || true
    rm -f "$BIN_PATH"
    rm -rf /usr/local/bin/rules
    rm -rf "$RUN_DIR"
    if [ -n "$ENV_DIR" ] && [ "$ENV_DIR" = "/etc/leeside" ]; then rm -rf /etc/leeside; fi
    rm -f "$NGINX_SNIPPET" "$NGINX_ZONE" "$TMPFILES_ENTRY"
    # Take the include back out of every conf that has it.
    local f
    for f in /etc/nginx/sites-enabled/*; do
        [ -f "$f" ] || continue
        if grep -Fq "$NGINX_INCLUDE" "$f" 2>/dev/null; then
            f="$(readlink -f "$f")"
            sed -i "\|$NGINX_INCLUDE|d" "$f" \
                || log "WARNING: cannot edit $f; remove the $NGINX_INCLUDE line by hand."
            log "removed the include from $f."
        fi
    done
    if nginx -t 2>/dev/null; then
        systemctl reload nginx || log "WARNING: nginx reload failed; check systemctl status nginx."
    else
        log "WARNING: nginx -t fails after the uninstall; fix the conf, then reload nginx."
    fi
    if [ -f /etc/GeoIP.conf.pre-leeside ]; then
        mv /etc/GeoIP.conf.pre-leeside /etc/GeoIP.conf
        log "restored the pre-existing /etc/GeoIP.conf."
    else
        rm -f /etc/GeoIP.conf
    fi
    if [ "$1" = "1" ]; then
        rm -rf /var/lib/leeside
        log "purged /var/lib/leeside."
    else
        log "kept /var/lib/leeside (rerun with --uninstall --purge to remove it)."
    fi
    log "uninstalled. System packages (curl, sqlite3, geoipupdate) were left in place."
}

usage() {
    cat <<EOF
Usage: install.sh [--yes] [--uninstall [--purge]] [--help]

Installs leesided, the tap and Windside. Reads answers from the
terminal unless --yes; every answer also has an env var:

    LEESIDE_BINARY        local binary; the box then never contacts the release (offline)
    LEESIDE_DOMAIN        the app's domain (finds its nginx conf)
    LEESIDE_LLM_KEY       Baseten key (blank: the LLM stays off)
    LEESIDE_GEOIP_ACCOUNT MaxMind account id (blank: GeoIP skipped)
    LEESIDE_GEOIP_KEY     MaxMind licence key
EOF
}

main() {
    YES=0
    local uninstall=0 purge=0 arg
    for arg in "$@"; do
        case "$arg" in
            --yes) YES=1 ;;
            --uninstall) uninstall=1 ;;
            --purge) purge=1 ;;
            --help|-h) usage; exit 0 ;;
            *) die "unknown argument: $arg." "run with --help" ;;
        esac
    done
    if [ "$uninstall" = "1" ]; then
        check_root
        uninstall "$purge"
        exit 0
    fi
    if [ "$purge" = "1" ]; then die "--purge needs --uninstall." "run with --uninstall --purge, or without --purge"; fi

    check_root
    check_arch "$(uname -m)"
    BIN_NAME="$(bin_name "$(uname -m)")"
    check_distro
    check_www_data
    # shellcheck disable=SC1091
    . /etc/os-release

    local fresh=1
    if [ -f "$ENV_FILE" ]; then
        fresh=0
        log "existing install found; keeping $ENV_FILE and its tokens."
    fi

    log "== packages"
    apt_base "$VERSION_ID"

    log "== binary"
    local bin_state
    bin_state="$(install_binary)"
    log "binary: $bin_state."

    log "== directories, model and rules"
    make_dirs
    log "model: $(install_model)."
    log "rules: $(install_rules)."

    local domain llm_key geoip_account geoip_key
    if [ -f "$INSTALL_CONF" ]; then
        # shellcheck disable=SC1090
        . "$INSTALL_CONF"
        domain="${LEESIDE_DOMAIN:-${SAVED_DOMAIN:-}}"
    fi
    if [ "$fresh" = "1" ]; then
        log "== questions (blank is always a valid answer)"
        ask DOMAIN_IN LEESIDE_DOMAIN "App domain (its nginx conf): " 0
        ask KEY_IN LEESIDE_LLM_KEY "Baseten key (blank: LLM off): " 1
        ask GEO_A LEESIDE_GEOIP_ACCOUNT "MaxMind account id (blank: skip GeoIP): " 0
        ask GEO_K LEESIDE_GEOIP_KEY "MaxMind licence key (blank: skip GeoIP): " 1
        domain="$DOMAIN_IN" llm_key="$KEY_IN" geoip_account="$GEO_A" geoip_key="$GEO_K"
        printf 'SAVED_DOMAIN=%s\n' "$domain" > "$INSTALL_CONF" \
            || die "cannot write $INSTALL_CONF." "check disk space and permissions, then rerun"
        chmod 600 "$INSTALL_CONF" \
            || die "cannot chmod $INSTALL_CONF." "check disk space and permissions, then rerun"
    else
        domain="${domain:-}"
        llm_key=""
        geoip_account="${LEESIDE_GEOIP_ACCOUNT:-}"; geoip_key="${LEESIDE_GEOIP_KEY:-}"
        if [ -n "${LEESIDE_DOMAIN:-}" ]; then domain="$LEESIDE_DOMAIN"; fi
        printf 'SAVED_DOMAIN=%s\n' "$domain" > "$INSTALL_CONF" 2>/dev/null || true
        chmod 600 "$INSTALL_CONF" 2>/dev/null || true
    fi

    local hash_key="" api_token="" viewer_token=""
    if [ "$fresh" = "1" ]; then
        log "== environment"
        read -r hash_key api_token viewer_token <<< "$(write_env "$ENV_DIR" "$llm_key")"
    else
        viewer_token="$(env_value "$ENV_FILE" LEESIDED_VIEWER_TOKEN)"
        [ -n "$viewer_token" ] || die "the kept $ENV_FILE has no LEESIDED_VIEWER_TOKEN." "add one (openssl rand -hex 32) and rerun"
    fi

    log "== services"
    write_units
    start_services
    if [ "$bin_state" = "changed" ] && [ "$fresh" = "0" ]; then
        systemctl restart leesided leesided-tap \
            || die "cannot restart after the binary update." "run journalctl -u leesided --no-pager | tail -30 to see why"
    fi
    wait_health

    # GeoIP runs on a fresh install when either credential is present
    # (setup skips itself when one is blank), and on a re-run only when
    # both arrive explicitly — the forgotten-credentials recovery.
    local want_geoip=0
    if [ -n "$geoip_account" ] || [ -n "$geoip_key" ]; then want_geoip=1; fi
    if [ "$fresh" = "0" ] && { [ -z "$geoip_account" ] || [ -z "$geoip_key" ]; }; then
        want_geoip=0
    fi
    if [ "$want_geoip" = "1" ]; then
        log "== GeoIP"
        setup_geoip "$geoip_account" "$geoip_key"
    fi

    log "== nginx"
    setup_nginx "$domain"

    print_summary "$domain" "$hash_key" "$api_token" "$viewer_token" "$fresh"
}

if [ -z "${BASH_SOURCE[0]:-}" ] || [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
