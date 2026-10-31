# Actor identity and surface classification

Brief for leeside-laravel (capture) and leesided (resolution). Implement in the capture package first; the leesided section defines the contract the package must leave ready. The wire-level consequences (event schema v2, the v2 probe, hashing namespaces, config keys, the response-modification exception) are written into `brief.md`, which stays the contract; this file is the reasoning and the field definitions it points to.

## Why this exists

IP and user agent are a sessionisation key, not an identity. Attackers control both for free (residential proxies, spoofed UA strings), and legitimate machine clients (partner servers, mobile apps, webhooks) look exactly like bots under browser-shaped rules: no cookies, no Sec-Fetch headers, no asset loads, a Go or Python TLS stack, one IP doing a lot. Any single heuristic therefore misfires in one direction or the other.

Two rules fix this:

1. Classify the surface a request belongs to before scoring it, and let every expectation depend on the surface.
2. The capture layer records identifiers and facts. It never decides who the actor is. leesided resolves actors from the recorded identifiers.

## 1. Surface classification (package)

Add a `surface` field to the capture record. Evaluate in this order, first match wins:

1. `honeypot` when the matched route belongs to the honeypot group (group does not exist yet; leave the hook).
2. `webhook` when the route or path matches the configured webhook list (config: route names or path prefixes; default prefix `/webhooks/`).
3. `api` when the request carries `Authorization: Bearer ...`, or any configured API-key header name (default list: `X-Api-Key`, `Api-Key`), or the matched route uses the `api` middleware group or the `/api` prefix.
4. `web` otherwise.

Also set a boolean `is_asset` for paths that look like static assets (extension in a configured list) regardless of surface. Assets normally never reach PHP; when they do, leesided wants to know.

Config overrides must allow forcing a surface by route name or path prefix, because real apps have API routes under odd prefixes.

## 2. Identifiers captured per request (package)

All of these are columns or well-defined keys in the existing capture record. Extend whatever record and table the package already writes; do not create a parallel table. Nullable where not applicable.

| Field | Content | Notes |
|---|---|---|
| `auth_id` | `Auth::id()` as string | null when guest. **In the repo this is the existing `principal` (hashed).** |
| `session_hash` | keyed hash of `session()->getId()` | null when no session. **In the repo this is the existing `session_key`.** |
| `credential_kind` | `bearer`, `api_key`, `webhook_sig`, null | which machine credential was presented |
| `credential_hash` | keyed hash of the credential value (token, key, or the verified webhook signer id) | never store the raw value |
| `tag_id` | id part of the Leeside tag cookie | see section 3 |
| `tag_status` | `valid`, `absent`, `malformed`, `bad_mac`, `issued` | `issued` when this response set a new tag |
| `ip` | client IP as Laravel resolves it with trusted proxies configured | **Socket transport only; leesided hashes on ingest and stores `ip_hash`, `net_hash`, `asn`, never the address.** |
| `ip_trust` | `direct` or `forwarded` | forwarded only when the hop was a trusted proxy |
| `ua` | raw User-Agent | **Not stored: the package emits `ua_class` and the 16-hex `ua_hash`; the raw string never leaves PHP.** |
| `ua_class` | `chromium`, `firefox`, `safari`, `other_browser`, `library`, `empty` | cheap regex classification, no full parser |
| `shape_hash` | request-shape fingerprint | see section 4 |
| `shape_*` | the fingerprint components as separate columns | so leesided can re-derive with a different recipe |
| `flags` | consistency flags | bitmask or JSON array, see section 5 |
| `ja4`, `ja4t`, `h2_fp` | copied from trusted proxy headers when present | see section 7, store null today |
| `ts_ms` | request time, millisecond precision | **In the repo this is `ts` (microseconds) and `ts_us` on the row.** |

Keyed hashes: the package's existing `Hasher` (HMAC-SHA256 under `LEESIDE_HASH_KEY`, one namespace per field, 16 hex). New namespaces: `credential`, `tag`, `shape`; leesided adds `ip` and `net` under the same key. No second salt.

No database lookups on the request path. Everything above is string work on the current request.

## 3. Leeside tag cookie (package, web surface only)

Cookie name: `_lsd` (configurable).

Value: `base64url(id || issued_at) . "." . base64url(mac)` where `id` is 16 random bytes, `issued_at` is a 4-byte big-endian unix timestamp, and `mac` is the first 16 bytes of `HMAC-SHA256(secret, id || issued_at)`.

Secret: `LEESIDE_TAG_SECRET` from config; when unset, derive from `APP_KEY` with an HKDF-style label so installs work without a new env var.

Attributes: `HttpOnly; SameSite=Lax; Path=/; Max-Age=31536000`, plus `Secure` when the request is secure (a hard `Secure` is dropped by browsers over plain http in development).

When to set: only when `surface = web`, the response is HTML (`Content-Type: text/html`), and the request did not present a `valid` tag. Never set it on `api`, `webhook` or asset responses. Never rotate a valid tag. Setting happens in a `handle()`-phase middleware: `CaptureTurn::terminate()` runs after the response has left.

Reading: parse from the raw `$_COOKIE` superglobal, not from the Laravel cookie bag, so the host app's `EncryptCookies` middleware cannot interfere with reading. For writing, the install steps must add `_lsd` to the host app's `encryptCookies(except: [...])` list, and the package's install docs and AGENTS.md must say so. At runtime, if the incoming `_lsd` looks like a Laravel encrypted payload (base64 JSON with `iv` and `value`), set `tag_status = malformed` and log a config warning once.

Status mapping: missing cookie → `absent`; wrong shape → `malformed`; MAC mismatch → `bad_mac`; MAC ok → `valid`.

The signals derived from the tag live in leesided (section 8), except `bad_mac`, which is a per-request fact and goes into `flags` too.

## 4. Request-shape fingerprint (package)

JA4H-style, computed from the current request. Store the composite `shape_hash` and each component:

- `shape_method` (GET, POST ...)
- `shape_http_version` (`$_SERVER['SERVER_PROTOCOL']`)
- `shape_has_cookie`, `shape_has_referer` (booleans)
- `shape_header_count` (client headers only; exclude nginx-added ones such as `X-Forwarded-*`, `X-Real-IP`; `Host` can stay)
- `shape_accept_language` (first 4 chars of the primary language, or `0000`)
- `shape_header_names_hash` (hash of the header names in received order, lowercased)
- `shape_cookie_names_hash` (hash of the sorted cookie names)

`shape_hash` is the hash of those components joined with `_`.

Verification item: header casing is lost through FastCGI and received order may or may not survive. Write a test that sends headers in a known unusual order through the real nginx + php-fpm path and checks `$_SERVER` ordering. If order survives, keep it. If not, fall back to sorted names and record `shape_order_reliable = false` in the capture record so leesided knows which recipe produced the hash.

## 5. Consistency flags (package, per request only)

Set each flag from the current request alone. Cross-request logic belongs to leesided.

- `ua_chromium_no_ch`: `ua_class = chromium` and no `Sec-CH-UA` header
- `browser_no_sec_fetch`: `ua_class` is a browser class and no `Sec-Fetch-Mode` header (note: Safari before 16.4 did not send these; treat as weak)
- `browser_no_accept_language`: browser class and no `Accept-Language`
- `html_get_no_html_accept`: browser class, GET on `web`, `Accept` present but without `text/html` or `*/*`
- `library_ua_on_web`: `ua_class = library` or `empty` on `web` surface
- `cookies_on_api`: session or tag cookie present on `api` surface (SPAs do this legitimately; informational)
- `bearer_with_sec_fetch`: `api` surface with `Sec-Fetch-*` headers (browser calling the API; informational)
- `tag_bad_mac`: tag present and MAC failed
- `proxy_header_untrusted`: a `X-Leeside-*` header arrived from a hop that is not a trusted proxy (section 7)

Flags are features for Windside, never verdicts. Nothing in the package blocks or alters a response, with the single exception of the tag `Set-Cookie` and the denials the gate already issues.

## 6. Surface rules (what applies where)

| Expectation | web | api | webhook | honeypot |
|---|---|---|---|---|
| Tag cookie issued | yes (HTML only) | no | no | yes |
| Cookie-absence rule (leesided) | yes | no | no | yes |
| Sec-Fetch / Accept-Language expectations | yes | no | no | yes |
| Asset-load expectation (leesided) | yes | no | no | no |
| Primary identity | `auth_id` > `session_hash` > `tag_id` | `credential_hash` > `auth_id` | `credential_hash` (verified signer) > `ip` range | `tag_id` > shape + ip |
| Rate and cadence computed per | actor | credential | signer | actor |

Never compute rate per IP on `api` or `webhook`. One partner server is many users behind one address. In leesided this is a `credential` window scope; when a credential is presented, a `peer` scope condition evaluates as empty and the sticky peer lookup is skipped, on any surface. Without a credential the peer applies as on web, so unauthenticated scanners on `api` are still caught per address. Consequence, by design: a peer blocked for `web` abuse is not blocked on `api` with a valid credential.

## 7. Proxy-provided fingerprints (contract only, for now)

leesided (or a patched nginx) will later pass TLS and TCP fingerprints to PHP as headers:

- `X-Leeside-JA4` (TLS ClientHello fingerprint)
- `X-Leeside-JA4T` (TCP SYN fingerprint)
- `X-Leeside-H2` (HTTP/2 SETTINGS and priority fingerprint)

The package stores them into `ja4`, `ja4t`, `h2_fp` only when the request came through a trusted proxy. If they arrive otherwise, store null and set `proxy_header_untrusted`. The nginx config in leeside-sample must overwrite these three headers on every proxied request (set to the real value, or to empty) so a client cannot inject them.

Schema and parsing ship now so the proxy work later is additive.

## 8. leesided: actor resolution (second phase)

Input: capture records with the fields above. Output: `actor_id` per request plus per-actor feature windows for Windside.

Graph model: one node per identifier value (`auth:<hash>`, `sess:<hash>`, `cred:<hash>`, `tag:<id>`, `ja4+asn:<...>`, `shape+net:<...>`). A request connects the nodes it carries.

- Strong edges merge nodes into one actor: `principal`, `session_key`, `credential_hash`, `valid tag_id`. Precedence as in section 6.
- Weak edges only cluster with a confidence score: `ja4 + asn`, `shape_hash + net_hash`, `ua_hash + net_hash`. Weak edges never merge two actors that are separated by a strong identifier. First cut: weak edges are features, not merges.

Enrichment on ingest: ASN and /24 from the IP (MaxMind GeoLite2 ASN; needs a license key, a database file on the host and the `maxminddb` crate), country for the Accept-Language check. The address itself is hashed and dropped.

Cross-request signals leesided derives (web and honeypot surfaces only unless noted):

- `tag_dropped`: an actor received `tag_status = issued` and a later request from the same weak cluster arrives with `absent`. Non-browser client.
- `tag_moved`: a `valid` tag arrives with a new IP or UA. Links the actor across rotation; not suspicious by itself.
- `no_assets_after_html`: HTML served, no asset requests from the actor within a window. Weak on its own (assets may be cached or served by nginx and never captured).
- `credential_moved` (api): one `credential_hash` seen from a new `ja4` or new ASN, or from two ASNs inside a short window. Primary leak indicator for API traffic.
- `ua_vs_ja4_mismatch`: browser `ua_class` with a library JA4, once JA4 is available.
- Cadence features per actor (or per credential on api): inter-request interval distribution, path entropy, 404 rate, honeytoken hits.

Windside gets per-actor windows with `surface` as a feature. Train per surface or at least with surface in the vector; otherwise the model learns "no cookies means bot" and flags every partner.

## 9. leeside-sample changes

Add routes that exercise all surfaces so captured traffic covers them:

- `/` and a second page under `web`, both referencing at least one CSS and one JS asset.
- `/api/ping` behind token auth (a static key middleware is enough), returning JSON.
- `/webhooks/demo` with HMAC signature verification over the body and a shared secret.
- A hidden link in the HTML and a `/admin-backup` path reserved for the future honeypot group (just a 404 for now, but route-named so the surface rule can pick it up).

nginx: `trustProxies` set to the nginx address in the sample app; the three `X-Leeside-*` headers overwritten on every proxied request.

## 10. Tests the package must carry

- Tag is issued on an HTML `web` response and only there; never on `api`, `webhook`, JSON or asset responses.
- A valid tag presented back yields `tag_status = valid` and no new `Set-Cookie`.
- A tag with a tampered MAC yields `bad_mac` and the flag.
- An encrypted-looking tag (host forgot the except list) yields `malformed` and one logged warning.
- Surface classification: bearer on a `web` route → `api`; configured webhook prefix → `webhook`; override by route name works.
- `credential_hash` is stable across requests for the same token and never equals the raw token.
- Header order survival through nginx + php-fpm (section 4), run against the real stack, not the test client.
- `X-Leeside-JA4` from a non-trusted hop is dropped and flagged.

## 11. Do not

- Do not pick an identity at capture time beyond the raw fields. No `actor_id` in the package.
- Do not block, challenge or modify responses from the package beyond the gate's denials and the tag cookie.
- Do not store raw tokens, API keys, session ids, webhook secrets, user agents or IP addresses.
- Do not compute anything per IP on machine surfaces.
- Do not add a JavaScript snippet or client-side fingerprinting in this phase.

## Order of work

0. `brief.md`: schema v2, the v2 probe, hashing namespaces, config, the cookie exception (done 2026-10-31).
1. leesided accepts v2 events and probes, `turns` columns, `credential` scope, `surface` in rule `match`. Must land before the package ships v2.
2. Surface classification and the identifier columns (sections 1, 2).
3. Tag cookie with its install step (section 3).
4. Shape fingerprint and flags, including the header-order test (sections 4, 5).
5. Proxy header contract and sample app routes (sections 7, 9).
6. Package tests (section 10).
7. leesided resolution (section 8) after the webapp is deployed.
