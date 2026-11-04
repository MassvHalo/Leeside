# Release

One command stages every asset; the operator uploads. Nothing here
deploys anything.

## Assets

Each asset ships with a `.sha256` beside it (14 files). The installer
verifies the binary, UI, and rules hashes; the model shas are for the
operator's own checking.

| Asset | Purpose |
| --- | --- |
| `leesided-x86_64-linux` | Daemon for x86_64 boxes |
| `leesided-aarch64-linux` | Daemon for ARM boxes (Graviton) |
| `manifest.json`, `model.txt` | Windside model 0.1.0 → `/var/lib/leeside/windside-model` |
| `leeside-ui.tar.gz` | Dashboard build → `/var/www/leeside-ui`, where `serve_dist` reads it |
| `leesided-rules.tar.gz` | Generic rules → `/usr/local/bin/rules/install`, plus `data/ja4-classes.json` → `/usr/local/bin/data` |

## One command

From a clean tree at a pushed HEAD:

```bash
bin/release.sh v0.1.0
```

It builds the native and cross-compiled x86_64 binaries, strips the
copies, builds `ui/dist` and both tarballs reproducibly (fixed owner,
mtime, sorted members, `gzip -n`), copies the model files, hashes
everything into `/tmp/leeside-release/<short-sha>/`, and prints the
`gh release create` command. It refuses on a dirty tree or an unpushed
HEAD, and tells the operator the `apt-get`/`rustup` lines when the
cross toolchain is missing. The operator pastes the printed command;
release.sh itself never runs `gh`.

## VM proof

On a fresh Ubuntu 22.04/24.04 box with a Laravel app behind nginx:

1. Install: `curl -sSL https://raw.githubusercontent.com/MassvHalo/Leeside/master/install.sh | sudo LEESIDE_DOMAIN=example.com bash -s -- --yes`.
2. `systemctl is-active leesided` → `active`; `curl -sf http://127.0.0.1:7390/health`.
3. Log in at `https://example.com/windside/login` with the viewer
   token from the summary. The dashboard renders — not "Dashboard
   not published". That 503 was the R-1 blocker; the installer now
   ships the UI asset.
4. Open Settings › Status: five panels, no login loop.
5. Turn enforcement on with the summary's two steps when ready.

Before any of that, on this box: `bash leesided/target/installer-test.sh`
(all groups green) and `bash leesided/target/smoke-install/run.sh`
(viewer login against the install layout, dashboard renders,
`/api/v1/status` 200).
