# Third-party software and data in Leeside

Copyleft: nothing binding. The only GPL/LGPL mentions are legs of
permissive-first multi-licenses, satisfied without them: `r-efi`
(Apache-2.0 OR LGPL-2.1-or-later OR MIT) and `nette/schema` +
`nette/utils` (BSD-3-Clause OR GPL-2.0-only OR GPL-3.0-only,
satisfied via BSD). No GPL-only or AGPL code anywhere below.

## Notices

- JA4 (TLS client fingerprint): FoxIO, LLC, BSD 3-Clause. The tap
  implements the published specification. Notice: "JA4 is a
  fingerprinting standard by FoxIO, LLC, licensed under BSD 3-Clause."
- JA4T (TCP fingerprint): FoxIO License 1.1, patent pending.
  Permitted for internal, academic and non-monetized use; a vendor
  selling it needs an OEM licence from FoxIO. Leeside's current
  build is non-commercial. Before any commercial use, JA4T is
  replaced by a vendor-neutral TCP fingerprint of our own format or
  an OEM licence is obtained. Reference:
  https://github.com/FoxIO-LLC/ja4
- data/ja4-classes.json: derived from the JA4 (TLS) column of
  FoxIO's ja4plus-mapping.csv in the repository above, about 65
  rows, no explicit licence on the file; to be regenerated from our
  own tap captures post-submission.
- GeoLite2: "This product includes GeoLite2 Data created by
  MaxMind, available from https://www.maxmind.com." Leeside does
  not redistribute the databases; each operator downloads them
  under their own MaxMind account via geoipupdate. The EULA
  requires prompt use of updated databases and destruction of old
  ones within 30 days.
- Muse Spark Open: Meta's open-weights model, used under the Muse
  Model License (October 15, 2026) and its Usage Policy, served
  through Baseten. Attribution per Section 2: "Built with Muse
  Spark Open". Outputs are the operator's (Section 4).

Provenance cut: 2026-11-03. Regenerate the dependency lists from
the lock files when they move.

## Rust crates (leesided)

From `cargo license` over `leesided` (direct and transitive,
including dev-dependencies), grouped by licence, verbatim:

```
(Apache-2.0 OR MIT) AND Unicode-3.0 (1): unicode-ident
0BSD OR Apache-2.0 OR MIT (1): adler2
Apache-2.0 (5): borsh-derive, ciborium, ciborium-io, ciborium-ll, sync_wrapper
Apache-2.0 AND ISC (1): ring
Apache-2.0 OR Apache-2.0 WITH LLVM-exception OR MIT (3): linux-raw-sys, rustix, wasi
Apache-2.0 OR BSD-2-Clause OR MIT (2): zerocopy, zerocopy-derive
Apache-2.0 OR BSL-1.0 (1): ryu
Apache-2.0 OR ISC OR MIT (1): rustls
Apache-2.0 OR LGPL-2.1-or-later OR MIT (1): r-efi
Apache-2.0 OR MIT (154): ahash, anes, anstyle, arc-swap, atomic-waker, autocfg, base64, bit-set, bit-vec, bitflags, block-buffer, borsh, bumpalo, cast, cc, cfg-if, chacha20, clap, clap_builder, clap_lex, cookie, cookie_store, core_detect, cpufeatures, cpufeatures, crc32fast, criterion, criterion-plot, crossbeam-deque, crossbeam-epoch, crossbeam-utils, crypto-common, deranged, digest, displaydoc, document-features, dyn-clone, either, equivalent, errno, fallible-iterator, fallible-streaming-iterator, fastrand, find-msvc-tools, flate2, fnv, form_urlencoded, futures-core, futures-task, futures-util, getrandom, getrandom, half, hashbrown, hashbrown, hashlink, hermit-abi, http, httparse, httpdate, idna, idna_adapter, indexmap, ipnetwork, itertools, itoa, js-sys, lazy_static, libc, litrs, lock_api, log, mime, num-conv, num-traits, once_cell, parking_lot, parking_lot_core, percent-encoding, pin-project-lite, pkg-config, powerfmt, proc-macro-crate, proc-macro2, proptest, quick-error, quote, rand, rand_core, rand_xorshift, rayon, rayon-core, regex, regex-automata, regex-syntax, rustls-pki-types, rustversion, rusty-fork, scopeguard, serde, serde_core, serde_derive, serde_derive_internals, serde_json, serde_path_to_error, serde_urlencoded, sha2, shlex, signal-hook-registry, smallvec, socket2, stable_deref_trait, syn, syn, tempfile, thiserror, thiserror-impl, thread_local, time, time-core, time-macros, tinytemplate, toml_datetime, toml_edit, toml_parser, typenum, unarray, ureq, ureq-proto, url, utf8-zero, utf8_iter, utf_types, vcpkg, version_check, wait-timeout, wasm-bindgen, wasm-bindgen-macro, wasm-bindgen-macro-support, wasm-bindgen-shared, web-sys, windows-link, windows-sys, windows-sys, windows-targets, windows_aarch64_gnullvm, windows_aarch64_msvc, windows_i686_gnu, windows_i686_gnullvm, windows_i686_msvc, windows_x86_64_gnu, windows_x86_64_gnullvm, windows_x86_64_msvc, zeroize
Apache-2.0 OR MIT OR Zlib (1): miniz_oxide
BSD-3-Clause (1): subtle
BSD-3-Clause AND MIT (1): matchit
CDLA-Permissive-2.0 (1): webpki-roots
ISC (3): maxminddb, rustls-webpki, untrusted
MIT (42): axum, axum-core, bytes, cfg_aliases, crunchy, dashmap, generic-array, http-body, http-body-util, hyper, hyper-util, is-terminal, leesided, libsqlite3-sys, matchers, mio, nu-ansi-term, oorandom, plotters, plotters-backend, plotters-svg, redox_syscall, rusqlite, schemars, schemars_derive, sharded-slab, simd-adler32, slab, synstructure, tokio, tokio-macros, tower, tower-layer, tower-service, tracing, tracing-attributes, tracing-core, tracing-log, tracing-subscriber, valuable, winnow, zmij
MIT OR Unlicense (5): aho-corasick, memchr, same-file, walkdir, winapi-util
Unicode-3.0 (18): icu_collections, icu_locale_core, icu_normalizer, icu_normalizer_data, icu_properties, icu_properties_data, icu_provider, litemap, potential_utf, tinystr, writeable, yoke, yoke-derive, zerofrom, zerofrom-derive, zerotrie, zerovec, zerovec-derive
Zlib (1): zlib-rs
```

## Composer packages (leeside/laravel)

From `leeside-laravel/composer.lock`, grouped by licence (116
packages, runtime and dev):

- `Apache-2.0` (1): phpoption/phpoption 1.10.0
- `BSD-3-Clause` (29): hamcrest/hamcrest-php v3.0.0,
  league/commonmark 2.10.4, league/config v1.2.0, mockery/mockery
  1.6.15, nikic/php-parser v5.9.0, phar-io/manifest 2.0.4,
  phar-io/version 3.2.1, phpunit/php-code-coverage 12.5.8,
  phpunit/php-file-iterator 6.0.2, phpunit/php-invoker 6.0.0,
  phpunit/php-text-template 5.0.1, phpunit/php-timer 8.0.0,
  phpunit/phpunit 12.5.42, sebastian/cli-parser 4.2.1,
  sebastian/comparator 7.1.8, sebastian/complexity 5.0.0,
  sebastian/diff 7.0.1, sebastian/environment 8.1.2,
  sebastian/exporter 7.0.3, sebastian/global-state 8.0.3,
  sebastian/lines-of-code 4.0.1, sebastian/object-enumerator 7.0.0,
  sebastian/object-reflector 5.0.0, sebastian/recursion-context
  7.0.1, sebastian/type 6.0.4, sebastian/version 6.0.1,
  theseer/tokenizer 2.0.1, tijsverkoyen/css-to-inline-styles v2.4.0,
  vlucas/phpdotenv v5.8.0
- `BSD-3-Clause+GPL-2.0-only+GPL-3.0-only` (2): nette/schema v1.4.0,
  nette/utils v4.1.6 (Nette's triple licence; satisfied via BSD, see
  the copyleft line above)
- `MIT` (84): brick/math 1.0.0, carbonphp/carbon-doctrine-types
  3.2.1, composer/semver 3.5.2, dflydev/dot-access-data v3.0.3,
  doctrine/inflector 2.1.1, doctrine/lexer 3.0.3,
  dragonmantank/cron-expression v3.6.1, egulias/email-validator
  4.0.4, fakerphp/faker v1.24.1, filp/whoops 2.18.7,
  fruitcake/php-cors v1.4.0, graham-campbell/result-type v1.2.0,
  guzzlehttp/guzzle 8.3.1, guzzlehttp/promises 3.1.0,
  guzzlehttp/psr7 3.2.0, guzzlehttp/uri-template v2.0.1,
  laravel/framework v13.39.0, laravel/pail v1.2.7, laravel/prompts
  v0.3.26, laravel/serializable-closure v2.1.0, laravel/tinker
  v3.0.2, league/flysystem 3.36.0, league/flysystem-local 3.35.3,
  league/mime-type-detection 1.17.0, league/uri 7.9.1,
  league/uri-interfaces 7.9.1, monolog/monolog 3.12.1,
  myclabs/deep-copy 1.14.0, nesbot/carbon 3.15.1,
  nunomaduro/collision v8.9.5, nunomaduro/termwind v2.4.0,
  orchestra/canvas v11.1.0, orchestra/canvas-core v11.0.0,
  orchestra/sidekick v1.2.23, orchestra/testbench v11.3.0,
  orchestra/testbench-core v11.6.0, orchestra/workbench v11.3.0,
  psr/clock 1.0.0, psr/container 2.0.2, psr/event-dispatcher 1.0.0,
  psr/http-client 1.0.3, psr/http-factory 1.1.0, psr/http-message
  2.0, psr/log 3.0.2, psr/simple-cache 3.0.0, psy/psysh v0.12.24,
  ramsey/collection 2.1.1, ramsey/uuid 4.9.4,
  staabm/side-effects-detector 1.0.5, symfony/clock v8.1.9,
  symfony/console v8.1.10, symfony/css-selector v8.1.10,
  symfony/deprecation-contracts v3.7.1, symfony/error-handler v8.1.10,
  symfony/event-dispatcher v8.1.5, symfony/event-dispatcher-contracts
  v3.7.1, symfony/finder v8.1.10, symfony/http-foundation v8.1.10,
  symfony/http-kernel v8.1.10, symfony/mailer v8.1.10, symfony/mime
  v8.1.10, symfony/polyfill-ctype v1.37.0,
  symfony/polyfill-intl-grapheme v1.43.3, symfony/polyfill-intl-idn
  v1.43.0, symfony/polyfill-intl-normalizer v1.43.0,
  symfony/polyfill-mbstring v1.43.3, symfony/polyfill-php80 v1.43.0,
  symfony/polyfill-php82 v1.43.0, symfony/polyfill-php83 v1.43.0,
  symfony/polyfill-php84 v1.43.0, symfony/polyfill-php85 v1.43.0,
  symfony/polyfill-php86 v1.43.0, symfony/polyfill-time v1.42.0,
  symfony/polyfill-uuid v1.43.0, symfony/process v8.1.10,
  symfony/routing v8.1.10, symfony/service-contracts v3.7.3,
  symfony/string v8.1.10, symfony/translation v8.1.10,
  symfony/translation-contracts v3.7.1, symfony/uid v8.1.9,
  symfony/var-dumper v8.1.10, symfony/yaml v8.1.10,
  voku/portable-ascii 2.1.1

npm (console UI, direct dependencies only, verified in
`leesided/ui/node_modules`): vue 3.5.44 MIT, vite 6.4.5 MIT,
@vitejs/plugin-vue 5.2.1 MIT. Transitive npm licences are not
audited here.

## Fonts (console UI)

- Inter (400/500 UI, 300 headlines), SIL Open Font License 1.1,
  loaded from Google Fonts; self-hosting is a follow-up.
- IBM Plex Mono (data, labels), SIL Open Font License 1.1, loaded
  from Google Fonts; self-hosting is a follow-up.

## Curated data files (leesided/data)

- `payload-patterns.json`: written from scratch. 31 curated regexes
  in five classes (sqli, xss, traversal, ssti, cmdi) over standard
  attack vocabulary; landed in 04af9cb with no external source
  cited in the repo or its history.
- `scanner-paths.json`: curated from scratch. The file's own note
  calls it "curated scanner-probe path segments"; landed in
  1fb63d6 with no external source cited in the repo or its history.
- `ja4-classes.json`: derived from FoxIO's sample mapping. The
  file's own `source` field names `ja4plus-mapping.csv`
  (github.com/FoxIO-LLC/ja4); `leesided/bin/ja4-classes.py`
  converts the CSV shape into classes, and the tap loads it at
  startup (see `leesided/src/tap/classes.rs`).

## JA4 and JA4T in the repo

Every place JA4 or JA4T is computed, stored, named or displayed,
file and line, at this cut. JA4/JA4T are FoxIO's open fingerprint
specification: the tap implements the computation from the spec
(`leesided/src/tap/ja4.rs`, `leesided/src/tap/ja4t.rs`) and maps
fingerprints to application classes from FoxIO data (above). A
licensing decision on JA4T is the operator's.

- docs/DEPLOY.md: 140,142,184
- docs/actor-identity.md: 46,73,120,121,124,132,135,144,145,170
- docs/brief.md: 147,202,402,474
- docs/console.md: 57
- docs/design/windside-review-actor.html: 36,1209,1211,1449,1450,
  1451,1590,1592,1774,1776
- docs/handoff.md: 31,34,57,58,61,68
- docs/inspector.md: 28
- docs/llm-evals.md: 43,51
- docs/llm.md: 80,105
- docs/outcomes.md: 24
- docs/windside.md: 28,42,52,95
- leeside-laravel/config/leeside.php: 70
- leeside-laravel/src/Event/TurnEventFactory.php:
  146,147,395,400,402,404 (reads JA4/JA4T from the
  X-Leeside-JA4/X-Leeside-JA4T proxy headers; does not compute)
- leeside-laravel/src/Shape/RequestShape.php: 9,29
- leeside-sample/bin/offbox-api.sh: 3
- leesided/bin/e2e.sh: 175,176,179,180,181,215
- leesided/bin/ja4-classes.py: 2,3,4,6,34,35,37,40,42
- leesided/data/ja4-classes.json: 2,4,5,6,7,8,9
- leesided/docs/actors.md: 13,33,160,167,168,225,240,293
- leesided/docs/rules.md: 752,755,758,759,760
- leesided/docs/tap.md:
  4,12,13,24,29,31,34,35,38,57,72,83,100,112,113,121,122,125,
  127,128,129,130,132,135,136,137,142,151,158,159,163,164
- leesided/migrations/0002_v2.sql: 20,21 (turns.ja4/ja4t columns)
- leesided/src/actors/mod.rs: 29,36,75,88,109,204,640,641
- leesided/src/config.rs: 28,29,211,236,239,247,319,320
- leesided/src/console/mod.rs: 592,677,678,758,759
- leesided/src/console/pages.rs:
  971,973,974,977,1045,1046,1441,1442,1447,1449,1451
- leesided/src/console/queries.rs:
  858,859,875,917,918,1146,1177,1180,1181,1783,1784,1817,1915,
  1961,1962,2264,2265,2274,2275,2279,3895,3896,3900
- leesided/src/engine.rs:
  18,63,64,285,287,351,377,823,824,827,828,829,832,835,837,
  839,840,841,849,850,874,876,877,1174,1175,1204,1206,1209,
  1210,1301,1381,1449,1460,1461
- leesided/src/faithfulness.rs:
  173,176,177,284,323,423,503,509,661,668,674,679,681,683
- leesided/src/llm.rs:
  16,410,430,612,640,641,674,1259,2687,2700,2754,2769,2945,
  3113,3278,3311,3327,3358,4276
- leesided/src/llm_eval.rs: 1387,1866
- leesided/src/main.rs: 429,494,558,783
- leesided/src/rules/features.rs: 361
- leesided/src/store/mod.rs: 126,127,269,270
- leesided/src/store/writer.rs: 165,166,170,171,172,174,453,492,493
- leesided/src/tap/capture.rs: 3,11,12,80,160,162,168,184,188,430,
  439,446,451
- leesided/src/tap/classes.rs:
  1,5,7,37,42,46,48,50,60,62,63,66,67,72,73,99,104,106
- leesided/src/tap/conns.rs:
  33,34,53,54,62,63,70,71,123,124,134,135,137,138,153,155,156,
  157,161,162,164,165,167,208,214,215,276,278,287,291,294,306,
  313,315,316,318,319,334,335,339,343,344,346,348,351,359,360,
  364,376,377,397,398,402
- leesided/src/tap/ja4.rs:
  1,3,23,33,99,109,111,211,259,262,275,280,336 (computation)
- leesided/src/tap/ja4t.rs: 1,8,80,83,88,89,90 (computation)
- leesided/src/tap/mod.rs: 3,5,15,16,31,36
- leesided/tests/integration.rs:
  83,85,154,156,186,188,233,1386,1579,1633,2705,2711,2715,2716,
  2731,2759,2763,2788,2789,2790,2796,2797,2798,2802,2803,2806,
  2809,2821,2849,2850,2854,2858,2863,2864,2865,2868,2876,2881,
  2885,2899,2900,2901,2905,2908,2918,2919,2922
