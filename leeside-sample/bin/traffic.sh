#!/usr/bin/env bash
# Three acts against `php artisan serve`. Prints nothing itself;
# watch `php artisan leeside:tap` for the events.
set -u

BASE="${BASE_URL:-http://127.0.0.1:8000}"
JAR="${JAR:-/tmp/leeside-traffic-jar.txt}"
UA="leeside-traffic/1.0"

rm -f "$JAR"

opts=(-s -o /dev/null -c "$JAR" -b "$JAR" -A "$UA" --max-time 5)

get() {
    curl "${opts[@]}" "$BASE$1"
}

post() {
    curl "${opts[@]}" -d "$2" "$BASE$1"
}

# Act 1: a benign browse.
get "/"
get "/venues/1"
get "/venues/2"
get "/venues/3"
get "/api/venues"
post "/api/venues/1/visit" "guests=2"

# Act 2: a validation burst (bad phone lengths, bad OTPs, one good login).
post "/portal/login" "phone=123&otp=12"
post "/portal/login" "phone=066111111&otp=123456"
post "/portal/login" "phone=06611111111&otp=12"
post "/portal/login" "phone=0661111111&otp=000001"
post "/portal/login" "phone=0661111111&otp=000002"
post "/portal/login" "phone=0662222222&otp=000003"
post "/portal/login" "phone=0662222222&otp=12345"
post "/portal/login" "phone=abc&otp=abcdef"
post "/portal/login" "phone=0663333333&otp=999999"
post "/portal/login" "phone=0661111111&otp=123456"

# Act 3: enumeration (venues 1 to 25, most 404).
for id in $(seq 1 25); do
    get "/venues/$id"
done
