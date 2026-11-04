//! The Windside console's pages (docs/inspector.md): server-rendered
//! HTML, one inlined stylesheet, no JavaScript beyond `<details>`
//! toggles and a copy button. Everything from the store is
//! HTML-escaped on the way out: turns carry attacker text.
//!
//! Tokens are `docs/console.md` section 5, dark first. Fonts fall back
//! to the system stacks; the box carries no webfonts.

use super::queries::{
    ActorDetail, ActorRow, Call, CallRow, ClusterDetail, ClusterRow, DecisionView, DraftView,
    FeatureRowView, Job, LabelRef, ModelView, Outcome, PayloadRow, ReviewFull, RuleView, ScoreView,
    SettingsView, TapInfo, Trace, TraceProposal, Turn, TurnLite,
};
use super::Role;
use std::collections::HashMap;
use std::fmt::Write as _;

/// Escape everything from the store.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn civil_from_days(z: u64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era as i64 * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// A microsecond timestamp in both forms the brief asks for: UTC with
/// microseconds beside the ISO form.
pub fn fmt_ts_us(ts_us: i64) -> String {
    let secs = ts_us.div_euclid(1_000_000);
    let micros = ts_us.rem_euclid(1_000_000) as u32;
    let days = secs.div_euclid(86_400) as u64;
    let tod = secs.rem_euclid(86_400) as u32;
    let (y, m, d) = civil_from_days(days);
    let (h, mi, s) = (tod / 3600, tod % 3600 / 60, tod % 60);
    format!(
        "{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02}.{micros:06} UTC \
         · {y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{micros:06}Z"
    )
}

/// A unix-seconds timestamp in the same two forms.
pub fn fmt_ts_s(ts_s: i64) -> String {
    fmt_ts_us(ts_s.saturating_mul(1_000_000))
}

fn mono(s: &str) -> String {
    format!("<span class=\"mono\">{}</span>", esc(s))
}

fn copy_button(value: &str) -> String {
    format!(
        "<button type=\"button\" class=\"copy\" data-copy=\"{}\">copy</button>",
        esc(value)
    )
}

fn id_cell(id: &str) -> String {
    format!(
        "<span class=\"idcell\">{} {}</span>",
        mono(id),
        copy_button(id)
    )
}

fn chip(text: &str, class: &str) -> String {
    format!("<span class=\"chip {class}\">{}</span>", esc(text))
}

fn outcome_chip(o: Outcome) -> String {
    chip(o.as_str(), o.chip())
}

fn status_chip(status: &str) -> String {
    let class = match status {
        "failed" => "bad",
        "done" => "good",
        "running" => "info",
        _ => "muted",
    };
    chip(status, class)
}

fn label_chip(label: &str) -> String {
    let class = match label {
        "malicious" => "bad",
        "benign" => "good",
        _ => "muted",
    };
    chip(label, class)
}

fn opt(v: &Option<String>) -> &str {
    v.as_deref().unwrap_or("—")
}

fn opt_int(v: Option<i64>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "—".to_string())
}

/// The server pages share the SPA's skin: the three `:root` token
/// blocks and every component rule the server markup uses are lifted
/// from `docs/design/windside-review-actor.html` (via the SPA's
/// stylesheets) verbatim, in handoff order, so the cascade matches.
/// What follows the last lift is server-only glue (page rhythm,
/// small chips and buttons, key-value lists, forms), expressed
/// through the same tokens. Coral is the one accent (hostile or
/// primary action); green means positive.
const STYLE: &str = r#"
/* ---------- Tokens ---------- */
:root {
  /* Colour. One accent: --hostile. */
  --ground: #0D1015;
  --surface-1: #12161C;
  --surface-2: #181D25;
  --selected: #1D2430;
  --line: #232A34;
  --line-strong: #323B48;
  --text: #E4E8EE;
  --text-2: #A6B0BE;
  --text-3: #8A95A4;
  --traffic: #323B48;
  --hostile: #FF7F5C;

  /* Fonts, with system fallbacks */
  --font-sans: "IBM Plex Sans", ui-sans-serif, system-ui, "Segoe UI", sans-serif;
  --font-mono: "IBM Plex Mono", ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  --weight-light: 300;
  --weight-regular: 400;

  /* Type sizes */
  --size-display: 30px;
  --size-title: 24px;
  --size-tile: 20px;
  --size-lead: 14px;
  --size-body: 13px;
  --size-small: 12px;
  --size-label: 11.5px;
  --size-mono: 12px;
  --size-mono-small: 11px;

  /* Spacing, on a 4 px grid */
  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-5: 24px;
  --space-6: 32px;

  /* Radii */
  --radius-1: 2px;
  --radius-2: 4px;
  --radius-3: 6px;
  --radius-pill: 999px;

  /* Layout */
  --sidebar-width: 224px;
  --list-width: 320px;
  --histogram-height: 72px;

  color-scheme: dark;
}

/* ---------- Base ---------- */
* { box-sizing: border-box; }
body {
  margin: 0; min-width: 1280px; background: var(--ground); color: var(--text);
  font: var(--weight-regular) var(--size-body)/19px var(--font-sans);
  font-variant-numeric: tabular-nums; -webkit-font-smoothing: antialiased;
}
h1, h2, p, ul, ol { margin: 0; padding: 0; }
ul, ol { list-style: none; }
a { color: inherit; text-decoration: none; }
button { font: inherit; color: inherit; background: none; border: 0; padding: 0; cursor: pointer; text-align: left; }
button:disabled { cursor: default; }
:focus-visible { outline: 2px solid var(--text); outline-offset: 2px; }
kbd {
  font: var(--weight-regular) var(--size-mono-small)/1 var(--font-mono); color: var(--text-2);
  display: inline-flex; align-items: center; justify-content: center; min-width: 18px; height: 18px; padding: 0 var(--space-1);
  border: 1px solid var(--line-strong); border-radius: var(--radius-2);
}
.arrow { flex: none; fill: none; stroke: var(--text-3); stroke-width: 1.3; }

/* ---------- Frame ---------- */
.frame { display: grid; grid-template-columns: var(--sidebar-width) minmax(0, 1fr); align-items: stretch; }
.content { display: flex; flex-direction: column; min-width: 0; }

/* ---------- Sidebar ---------- */
.sidebar { display: flex; flex-direction: column; gap: var(--space-3); padding: var(--space-3); background: var(--surface-1); border-right: 1px solid var(--line); }
.brand { display: flex; align-items: center; gap: 10px; height: 32px; padding: 0 var(--space-2); font-size: 15px; }
.brand-mark-dim { fill: var(--text-2); }
.brand-mark-hostile { fill: var(--hostile); }
.app-switch { display: flex; align-items: center; justify-content: space-between; gap: var(--space-2); min-height: 32px; padding: 6px var(--space-2) 6px 10px; border: 1px solid var(--line-strong); border-radius: var(--radius-3); font-size: var(--size-small); line-height: 17px; }
.chevron { flex: none; fill: none; stroke: var(--text-3); stroke-width: 1.3; }
.nav { display: flex; flex-direction: column; gap: 2px; }
.nav-link { display: flex; align-items: center; gap: 10px; min-height: 32px; padding: 5px var(--space-2); border-radius: var(--radius-3); color: var(--text-2); cursor: pointer; }
.nav-link:hover { background: var(--surface-2); color: var(--text); }
.nav-link.is-current { background: var(--selected); color: var(--text); }
.nav-icon { flex: none; fill: none; stroke: var(--text-3); stroke-width: 1.2; }
.nav-link.is-current .nav-icon { stroke: var(--text); }
.nav-label { flex: 1; }
.nav-child { min-height: 26px; padding: 3px var(--space-2) 3px 32px; font-size: 12.5px; line-height: 18px; }
.nav-group summary { list-style: none; }
.nav-group summary::-webkit-details-marker { display: none; }
.nav-group[open] > summary .arrow { transform: rotate(90deg); }
.count-pill { font: var(--weight-regular) var(--size-mono-small)/15px var(--font-mono); padding: 1px 6px; border-radius: var(--radius-pill); background: var(--selected); color: var(--text); }
.sidebar-foot { display: flex; flex-direction: column; gap: var(--space-2); padding: var(--space-3) var(--space-2) 0; border-top: 1px solid var(--line); }
.connection { display: flex; align-items: center; gap: 7px; font-size: var(--size-label); line-height: 15px; color: var(--text-2); }
.connection::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: var(--text); }
.user { font-size: var(--size-small); line-height: 17px; color: var(--text-2); }
.user-role { color: var(--text-3); }

/* ---------- Headline ---------- */
.page-head { display: flex; align-items: flex-start; justify-content: space-between; gap: var(--space-5); padding: 28px var(--space-5) 22px; }
.page-head-text { display: flex; flex-direction: column; gap: 6px; min-width: 0; }
.headline-row { max-width: 920px; text-wrap: balance; }
.headline { font: var(--weight-light) var(--size-display)/36px var(--font-sans); letter-spacing: -0.01em; display: inline; }
.headline-dim { color: var(--text-3); }
.subline { font-size: var(--size-lead); line-height: 20px; color: var(--text-2); }

/* ---------- Tokens added for these pages ---------- */
:root {
  --hostile-band: rgba(255, 127, 92, 0.1);
  --size-section: 13px;
  --panel-gap: var(--space-5);
}

/* ---------- Links and small parts ---------- */
.copy { padding: 0 var(--space-2); height: 20px; border: 1px solid var(--line); border-radius: var(--radius-2); font-size: var(--size-mono-small); line-height: 18px; color: var(--text-3); }
.copy:hover { color: var(--text); border-color: var(--line-strong); }
.section-label { font-size: var(--size-label); font-weight: var(--weight-regular); line-height: 15px; color: var(--text-3); }
.mono-cell { font-family: var(--font-mono); font-size: var(--size-mono-small); }

/* ---------- Dense table ---------- */
.table-wrap { overflow-x: auto; min-width: 0; }
.dense-table { width: 100%; border-collapse: collapse; }
.dense-table th { padding: 0 var(--space-3) 6px 0; border-bottom: 1px solid var(--line-strong); font-size: var(--size-label); font-weight: var(--weight-regular); line-height: 15px; text-align: left; color: var(--text-3); white-space: nowrap; }
.dense-table td { padding: 4px var(--space-3) 4px 0; border-bottom: 1px solid var(--line); font-size: var(--size-small); line-height: 17px; white-space: nowrap; }
.dense-table tbody tr:hover td { background: var(--surface-1); }

/* ---------- Panels ---------- */
.panel { display: flex; flex-direction: column; gap: var(--space-3); padding: var(--space-5); min-width: 0; border-bottom: 1px solid var(--line); }
.panel-wide { grid-column: 1 / -1; }
.panel-flat { border-top: 1px solid var(--line); }
.panels { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); border-top: 1px solid var(--line); }
.panel-title { font-size: var(--size-label); font-weight: var(--weight-regular); line-height: 15px; color: var(--text-3); }

/* ---------- Dashboard layer ---------- */
:root {
  --ground: #0A0D12;
  --panel: #10141C;
  --card: #181D27;
  --card-raised: #1F2531;
  --surface-1: #181D27;
  --surface-2: #222835;
  --selected: rgba(255, 255, 255, 0.07);
  --line: rgba(255, 255, 255, 0.07);
  --line-strong: rgba(255, 255, 255, 0.14);
  --text: #F0F2F5;
  --text-2: #A7ADB9;
  --text-3: #7A818E;
  --traffic: #4B4580;
  --hostile: #F0694F;
  --hostile-tint: rgba(240, 105, 79, 0.14);
  --hostile-band: rgba(240, 105, 79, 0.1);
  --positive: #4ADE80;
  --positive-tint: rgba(74, 222, 128, 0.12);

  --font-sans: "Inter", ui-sans-serif, system-ui, "Segoe UI", sans-serif;
  --font-mono: "IBM Plex Mono", ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  --weight-headline: 400; /* never bolder than this in a headline */

  --size-hero: 56px;
  --size-display: 44px;
  --size-title: 30px;
  --size-tile: 30px;
  --size-tracked: 10.5px;
  --tracking-tight: -0.035em;
  --tracking-label: 0.16em;

  --radius-card: 16px;
  --radius-panel: 20px;
  --radius-pill: 999px;
  --radius-3: 8px;
  --sidebar-width: 236px;
  --page-pad: 40px;
  --card-gap: 16px;
  --list-width: 320px;
}

body { background: var(--ground); font-family: var(--font-sans); letter-spacing: -0.005em; }

/* Tracked mono labels */
.section-label, .step-label, .panel-title, .tile-label, .episodes-heading, .closer-label,
.dense-table th, .crumb, .card-label, .nav-section, .connection, .verdict-label {
  font: var(--weight-regular) var(--size-tracked)/15px var(--font-mono);
  letter-spacing: var(--tracking-label); text-transform: uppercase; color: var(--text-3);
}

/* ---------- Shell ---------- */
.frame { grid-template-columns: var(--sidebar-width) minmax(0, 1fr); grid-template-rows: auto 1fr; padding: 0 var(--card-gap) var(--card-gap) 0; background: var(--ground); }
.topbar { grid-column: 1 / -1; display: flex; align-items: center; justify-content: space-between; gap: var(--space-4); height: 60px; padding: 0 var(--space-2) 0 22px; }
.brand { padding: 0; height: auto; font-size: 18px; letter-spacing: -0.02em; }
.brand-mark-hostile { fill: var(--hostile); }
.user { display: flex; align-items: center; gap: 10px; }
.user-avatar { display: grid; place-items: center; width: 32px; height: 32px; border-radius: 50%; background: var(--card-raised); font-size: var(--size-small); color: var(--text); }
.user-text { display: flex; flex-direction: column; }
.user-name { font-size: var(--size-body); line-height: 17px; color: var(--text); }
.user-role { font-size: 11px; line-height: 14px; color: var(--text-3); }

.sidebar { background: none; border-right: 0; padding: var(--space-1) 0 var(--space-4); gap: var(--space-4); }
.jump { display: flex; align-items: center; gap: var(--space-2); height: 34px; margin: 0 var(--space-3); padding: 0 var(--space-2) 0 10px; background: var(--card); border-radius: var(--radius-3); }
.jump:focus-within { outline: 2px solid var(--text); outline-offset: 1px; }
.jump input { flex: 1; min-width: 0; border: 0; outline: 0; background: none; font: var(--weight-regular) var(--size-small)/17px var(--font-sans); color: var(--text); }
.jump input::placeholder { color: var(--text-3); }
.nav { gap: 0; }
.nav-section { padding: var(--space-4) 22px var(--space-2); }
.nav-link { gap: 12px; min-height: 36px; padding: 6px var(--space-3) 6px 20px; border-left: 2px solid transparent; border-radius: 0; color: var(--text-2); }
.nav-link:hover { background: none; color: var(--text); }
.nav-link.is-current { background: none; color: var(--text); border-left-color: var(--hostile); }
.nav-icon { width: 16px; height: 16px; stroke: var(--text-2); }
.nav-link.is-current .nav-icon { stroke: var(--text); }
.nav-child { min-height: 30px; padding: 4px var(--space-3) 4px 48px; font-size: 12.5px; }
.nav-child.is-current { border-left-color: transparent; }
.count-pill { background: var(--hostile-tint); color: var(--hostile); }
.sidebar-foot { margin-top: auto; gap: var(--space-3); padding: var(--space-4) 20px 0; border-top: 1px solid var(--line); }
.app-switch { border: 0; padding: 0; min-height: 0; font-size: var(--size-small); color: var(--text); }
.connection { align-self: flex-start; padding: 5px 10px; border: 1px solid var(--line-strong); border-radius: var(--radius-pill); color: var(--text-2); font-size: 9.5px; letter-spacing: 0.12em; }
.connection.attribution { text-transform: none; }
.connection::before { background: var(--positive); }

.content {
  border-radius: var(--radius-panel); overflow: hidden;
  background-color: var(--panel);
  background-image:
    radial-gradient(640px 240px at 6% 440px, rgba(74, 222, 128, 0.09), transparent 70%),
    radial-gradient(900px 420px at 72% -40px, rgba(120, 104, 230, 0.26), transparent 70%),
    radial-gradient(800px 420px at 8% -60px, rgba(70, 110, 190, 0.22), transparent 70%);
  background-repeat: no-repeat;
  padding-bottom: var(--page-pad);
}

/* ---------- Hero and headlines ---------- */
.headline { display: block; font: var(--weight-headline) var(--size-display)/1.06 var(--font-sans); letter-spacing: var(--tracking-tight); color: var(--text); text-wrap: balance; }
.headline-dim { color: var(--text); }
.headline-rest { color: var(--text-3); }
.headline-row { max-width: none; }
.subline { font-size: 15px; line-height: 22px; color: var(--text-2); }
.page-head { padding: 44px var(--page-pad) var(--space-6); gap: var(--space-5); }
.page-head-text { gap: var(--space-3); }

/* ---------- Pills: chips, buttons ---------- */
.copy { border-radius: var(--radius-pill); padding: 0 10px; }
kbd { border-radius: 5px; }

/* ---------- Workspace: cards ---------- */
.panel { padding: 22px 24px; border-bottom: 1px solid var(--line); }
.episodes, .queue, .detail, .panel, .tile { background: var(--card); border: 1px solid var(--line); border-radius: var(--radius-card); }
.panels { gap: var(--card-gap); margin: 0 var(--page-pad); border: 0; }

/* ---------- Actor ---------- */
.dense-table th { border-bottom-color: var(--line-strong); }
.dense-table tbody tr:hover td { background: rgba(255, 255, 255, 0.03); }

@media (max-width: 1360px) {
  :root { --size-hero: 46px; --size-display: 38px; --page-pad: 28px; --size-title: 26px; --list-width: 280px; }
  .detail { padding: 22px; }
  .panel { padding: 20px; }
  .dense-table th { letter-spacing: 0.08em; padding-right: var(--space-2); }
  .dense-table td { padding-right: var(--space-2); }
}

/* ---------- Server glue: rhythm, chips, buttons, lists, forms ---------- */
/* Page titles are Inter light per the round: the design's headline shape
   at 300 instead of the dashboard layer's 400. */
.headline { font-weight: 300; }
b, strong { font-weight: 500; }
/* The page body carries the page-head's padding; templates change
   classes only, so the wrapper lives in the layout. */
.page { padding: 44px var(--page-pad) 0; min-width: 0; }
.headline { margin-bottom: var(--space-2); }
.subline { margin-bottom: var(--space-4); }
.page > p { margin-bottom: var(--space-3); }
.section-label { margin: var(--space-2) 0; }
.table-wrap { margin-bottom: var(--space-4); }
.page a { color: inherit; text-decoration: underline; text-decoration-color: var(--line-strong); text-decoration-thickness: 1px; text-underline-offset: 3px; }
.page a:hover { text-decoration-color: var(--text); }
/* Status chips: the design's pill at inline size. Coral means hostile
   or needs-attention; green means positive. */
.chip { display: inline-flex; align-items: center; height: 22px; padding: 0 10px; border: 1px solid var(--line-strong); border-radius: var(--radius-pill); font-size: var(--size-small); line-height: 20px; color: var(--text-2); white-space: nowrap; }
.chip.good { color: var(--positive); }
.chip.bad { color: var(--hostile); border-color: var(--hostile); }
.chip.warn { color: var(--hostile); }
.chip.info { color: var(--text); }
.chip.muted { color: var(--text-3); }
/* Buttons: the design's quiet pill, the white primary pill, and the
   small in-table scale. Warning buttons speak in coral. */
.btn { display: inline-flex; align-items: center; justify-content: center; height: 40px; padding: 0 16px; border: 1px solid var(--line-strong); border-radius: var(--radius-pill); background: rgba(255, 255, 255, 0.03); font-size: var(--size-body); line-height: 19px; color: var(--text); cursor: pointer; white-space: nowrap; font-family: var(--font-sans); }
input.btn { font-family: var(--font-sans); }
.btn:hover { background: rgba(255, 255, 255, 0.09); }
.btn-primary { background: var(--text); border-color: var(--text); color: var(--ground); }
.btn-primary:hover { background: #FFFFFF; border-color: #FFFFFF; }
.btn-warn { color: var(--hostile); }
td .btn { height: 26px; padding: 0 10px; font-size: var(--size-small); line-height: 17px; }
form { margin-bottom: var(--space-3); }
form.inline { display: inline; margin: 0; }
input[type=text], input[type=password], select { background: var(--surface-1); border: 1px solid var(--line-strong); color: var(--text); border-radius: var(--radius-3); padding: var(--space-2) var(--space-3); font: var(--weight-regular) var(--size-body)/19px var(--font-sans); }
.page label { font-size: var(--size-body); color: var(--text-2); }
/* Key-value lists keep their grid at the facts' type scale. */
.kv { display: grid; grid-template-columns: 160px minmax(0, 1fr); gap: var(--space-1) var(--space-3); margin: 0 0 var(--space-4); }
.kv dt { font-size: var(--size-label); line-height: 19px; color: var(--text-3); }
.kv dd { margin: 0; font-size: var(--size-body); line-height: 19px; overflow-wrap: anywhere; min-width: 0; }
.mono, code { font-family: var(--font-mono); font-size: var(--size-mono); }
dd.mono { font-family: var(--font-mono); font-size: var(--size-mono); }
td.num { font-family: var(--font-mono); font-size: var(--size-mono); text-align: right; white-space: nowrap; }
.idcell { display: inline-flex; align-items: center; gap: var(--space-2); }
pre { background: var(--surface-1); border: 1px solid var(--line); border-radius: var(--radius-3); padding: var(--space-3) var(--space-4); overflow-x: auto; white-space: pre-wrap; word-break: break-word; font-family: var(--font-mono); font-size: var(--size-mono); line-height: 19px; margin: var(--space-2) 0 var(--space-4); }
.pager { margin: var(--space-4) 0; color: var(--text-2); font-size: var(--size-body); }
.pager a { margin: 0 var(--space-2); }
p.error { color: var(--hostile); }
p.empty { color: var(--text-3); }
blockquote { margin: 0 0 var(--space-3); color: var(--text-2); }
.cols { display: grid; grid-template-columns: 1fr; gap: 0 var(--space-5); }
@media (min-width: 1400px) { .cols { grid-template-columns: 1fr 1fr 1fr; } }
.cols > section { min-width: 0; }
summary { cursor: pointer; }
/* The settings grid sits inside the page padding already. */
.page .panels { margin: 0; }
/* The login form sits in a centred panel. */
.login-wrap { display: flex; justify-content: center; padding: var(--space-6) 0; }
.login-panel { width: 100%; max-width: 440px; }
.login-panel input[type=password] { width: 100%; margin: var(--space-2) 0 var(--space-3); }
"#;

const COPY_SCRIPT: &str = r#"<script>
document.addEventListener("click", function (ev) {
  var b = ev.target.closest("button.copy");
  if (!b) return;
  var v = b.getAttribute("data-copy") || "";
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(v).then(function () {
      b.textContent = "copied";
      setTimeout(function () { b.textContent = "copy"; }, 1200);
    });
  }
});
</script>"#;

/// The same Google Fonts link the SPA uses (Inter 300/400/500,
/// IBM Plex Mono 400); self-hosting is a follow-up either way.
const FONTS: &str = r#"<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono&family=Inter:wght@300;400;500&display=swap" rel="stylesheet">"#;

/// The live shell data the sidebar renders: the review queue length
/// (the pending pill), the Windside mode (the connection line), and
/// the request's hostname (the app switch). Built per page render.
pub struct Shell {
    pub pending: i64,
    pub mode: String,
    pub host: String,
}

/// One source of truth for the sidebar: this function renders the
/// same groups, order and links the SPA renders, byte for byte for
/// the same role (the smoke suite compares them; only the
/// current-page markers legitimately differ). `active` is the path
/// suffix (`/actors`); pages with no nav entry highlight nothing.
/// Viewer sees no Settings group, as in the SPA.
///
/// The markup mirrors the SPA's *rendered* DOM, not its template:
/// no `:`/`@`/`v-` directives, no whitespace between elements (Vue's
/// condenser drops it), attributes in template order.
fn sidebar(prefix: &str, role: Role, shell: &Shell, active: &str) -> String {
    // The current nav child for this page, if it has one.
    let current = match active {
        "/review" => "review-queue",
        "/actors" => "traffic-actors",
        "/clusters" => "traffic-clusters",
        "/rules" => "protection-rules",
        "/labels" => "protection-decisions",
        "/model" => "intelligence-model",
        "/llm" => "intelligence-assistant",
        "/payloads" => "intelligence-payloads",
        "/settings" => "settings-controls",
        _ => "",
    };
    let open_group = current.split('-').next().unwrap_or("");
    /// A nav child link: class, href, then the current marker, in the
    /// SPA template's attribute order.
    fn child(href: &str, label: &str, id: &str, current: &str) -> String {
        let (cls, aria) = if id == current {
            ("nav-link nav-child is-current", " aria-current=\"page\"")
        } else {
            ("nav-link nav-child", "")
        };
        format!("<a class=\"{cls}\" href=\"{href}\"{aria}>{label}</a>")
    }
    /// A nav group: the summary carries the current class when the
    /// group holds the current child, exactly as the SPA's
    /// `route.group` binding does.
    fn group(
        id: &str,
        icon: &str,
        label: &str,
        pill: &str,
        children: &str,
        open_group: &str,
    ) -> String {
        let open = if id == open_group { " open=\"\"" } else { "" };
        let cls = if id == open_group {
            "nav-link is-current"
        } else {
            "nav-link"
        };
        format!(
            "<details class=\"nav-group\"{open}><summary class=\"{cls}\">{icon}\
             <span class=\"nav-label\">{label}</span>{pill}{ARROW}</summary>{children}</details>",
        )
    }
    let pill = if shell.pending > 0 {
        format!(
            "<span class=\"count-pill\" data-field=\"review.pending\">{}</span>",
            shell.pending
        )
    } else {
        // Vue leaves a v-if anchor where the pill would be.
        "<!---->".to_string()
    };
    let review = group(
        "review",
        ICON_REVIEW,
        "Review",
        &pill,
        &format!(
            "{}{}",
            child("#/review", "Queue", "review-queue", current),
            child("#/review/decided", "Decided", "review-decided", current),
        ),
        open_group,
    );
    let traffic = group(
        "traffic",
        ICON_TRAFFIC,
        "Traffic",
        "",
        &format!(
            "{}{}",
            child(
                &format!("{prefix}/actors"),
                "Actors",
                "traffic-actors",
                current
            ),
            child(
                &format!("{prefix}/clusters"),
                "Clusters",
                "traffic-clusters",
                current
            ),
        ),
        open_group,
    );
    let protection = group(
        "protection",
        ICON_PROTECTION,
        "Protection",
        "",
        &format!(
            "{}{}",
            child(
                &format!("{prefix}/rules"),
                "Rules",
                "protection-rules",
                current
            ),
            child(
                &format!("{prefix}/labels"),
                "Decisions",
                "protection-decisions",
                current
            ),
        ),
        open_group,
    );
    let intelligence = group(
        "intelligence",
        ICON_INTELLIGENCE,
        "Intelligence",
        "",
        &format!(
            "{}{}{}",
            child(
                &format!("{prefix}/model"),
                "Model",
                "intelligence-model",
                current
            ),
            child(
                &format!("{prefix}/llm"),
                "Assistant",
                "intelligence-assistant",
                current
            ),
            child(
                &format!("{prefix}/payloads"),
                "Payloads",
                "intelligence-payloads",
                current
            ),
        ),
        open_group,
    );
    let settings = if role == Role::Admin {
        format!(
            "<div class=\"nav-section\">System</div>{}",
            group(
                "settings",
                ICON_SETTINGS,
                "Settings",
                "",
                &format!(
                    "{}{}{}",
                    child("#/settings", "Status", "settings-status", current),
                    child(
                        "#/settings/assistant",
                        "Assistant",
                        "settings-assistant",
                        current
                    ),
                    child(
                        &format!("{prefix}/settings"),
                        "Controls",
                        "settings-controls",
                        current
                    ),
                ),
                open_group,
            )
        )
    } else {
        // Vue leaves a v-if anchor where the System group would be.
        "<!---->".to_string()
    };
    format!(
        "<aside class=\"sidebar\" aria-label=\"Console\">\
         <label class=\"jump\"><input type=\"text\" placeholder=\"Jump to actor id\" \
         aria-label=\"Jump to an actor by id prefix\"><kbd>/</kbd></label>\
         <nav class=\"nav\" aria-label=\"Sections\">\
         <a class=\"nav-link\" href=\"#/\">{ICON_DASHBOARD}<span class=\"nav-label\">Dashboard</span></a>\
         <div class=\"nav-section\">Daily</div>{review}{traffic}\
         <div class=\"nav-section\">Control</div>{protection}{intelligence}{settings}\
         </nav>\
         <div class=\"sidebar-foot\">\
         <button type=\"button\" class=\"app-switch\" aria-haspopup=\"menu\">\
         <span data-field=\"app.host\">{}</span>{CHEVRON}</button>\
         <span class=\"connection\"><span>Connected, \
         <span data-field=\"summary.mode\">{}</span></span></span>\
         <span class=\"connection attribution\"><span>Built with Muse Spark Open</span></span>\
         </div></aside>",
        esc(&shell.host),
        esc(&shell.mode),
    )
}

const ICON_DASHBOARD: &str = r#"<svg class="nav-icon" width="16" height="16" viewBox="0 0 14 14" aria-hidden="true"><path d="M2 6.6 L7 2.4 L12 6.6 V12 H8.6 V8.8 H5.4 V12 H2 Z" fill="none"></path></svg>"#;
const ICON_REVIEW: &str = r#"<svg class="nav-icon" width="16" height="16" viewBox="0 0 14 14" aria-hidden="true"><rect x="1.8" y="1.8" width="10.4" height="10.4" rx="2.4" fill="none"></rect><path d="M4.4 7.2 L6.3 9.1 L9.8 5.2" fill="none"></path></svg>"#;
const ICON_TRAFFIC: &str = r#"<svg class="nav-icon" width="16" height="16" viewBox="0 0 14 14" aria-hidden="true"><path d="M1 7 H3.6 L5.2 3 L8 11 L9.8 7 H13" fill="none"></path></svg>"#;
const ICON_PROTECTION: &str = r#"<svg class="nav-icon" width="16" height="16" viewBox="0 0 14 14" aria-hidden="true"><path d="M7 1.2 L12 3 V7 C12 10 9.8 11.9 7 12.8 C4.2 11.9 2 10 2 7 V3 Z" fill="none"></path></svg>"#;
const ICON_INTELLIGENCE: &str = r#"<svg class="nav-icon" width="16" height="16" viewBox="0 0 14 14" aria-hidden="true"><circle cx="7" cy="7" r="5.2" fill="none"></circle><circle cx="7" cy="7" r="2.2" fill="none"></circle></svg>"#;
const ICON_SETTINGS: &str = r##"<svg class="nav-icon" width="16" height="16" viewBox="0 0 14 14" aria-hidden="true"><path d="M1.5 4 H12.5 M1.5 10 H12.5" fill="none"></path><circle cx="5" cy="4" r="1.6" fill="#0A0D12"></circle><circle cx="9.5" cy="10" r="1.6" fill="#0A0D12"></circle></svg>"##;
const ARROW: &str = r#"<svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg>"#;
const CHEVRON: &str = r#"<svg class="chevron" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M2 3.5 L5 6.5 L8 3.5"></path></svg>"#;
const BRAND_MARK: &str = r#"<svg class="brand-mark" width="20" height="20" viewBox="0 0 20 20" aria-hidden="true"><rect class="brand-mark-dim" x="2" y="4" width="10" height="2.4" rx="1"></rect><rect class="brand-mark-hostile" x="6" y="8.8" width="12" height="2.4" rx="1"></rect><rect class="brand-mark-dim" x="4" y="13.6" width="6" height="2.4" rx="1"></rect></svg>"#;

/// The top bar, the SPA's markup: brand plus the session's user
/// button. The brand links the dashboard (the SPA's `#/` would be a
/// no-op off the app); the button is inert without the SPA's script,
/// like the sidebar's jump box.
fn topbar(prefix: &str, role: Role) -> String {
    let initial = role.as_str()[..1].to_uppercase();
    format!(
        "<header class=\"topbar\"><a class=\"brand\" href=\"{prefix}/\">{BRAND_MARK}<span>windside</span></a>\
         <button type=\"button\" class=\"user\" aria-haspopup=\"menu\">\
         <span class=\"user-avatar\" aria-hidden=\"true\">{initial}</span>\
         <span class=\"user-text\"><span class=\"user-name\" data-field=\"user.name\">{}</span></span>\
         {CHEVRON}</button></header>",
        role.as_str(),
    )
}

fn layout(
    title: &str,
    active: &str,
    body: &str,
    prefix: &str,
    role: Role,
    shell: &Shell,
) -> String {
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{} · Windside</title>{FONTS}<style>{STYLE}</style></head>\
         <body><div class=\"frame\">{}{}\
         <main class=\"content\"><div class=\"page\">{body}</div></main></div>{COPY_SCRIPT}</body></html>",
        esc(title),
        topbar(prefix, role),
        sidebar(prefix, role, shell, active),
    )
}

/// The slim shell for the login and error pages: tokens, fonts and
/// page rhythm, no sidebar (there is no session to render it for).
fn slim_layout(title: &str, body: &str) -> String {
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{} · Windside</title>{FONTS}<style>{STYLE}</style></head>\
         <body><div class=\"page\">{body}</div>{COPY_SCRIPT}</body></html>",
        esc(title),
    )
}

pub fn login_page(next: &str, error: Option<&str>, prefix: &str) -> String {
    let mut body = String::from(
        "<div class=\"login-wrap\"><section class=\"panel login-panel\" aria-label=\"Log in\">\
         <h1 class=\"headline\">Log in to Windside.</h1>\
         <p class=\"subline\">the admin password, or the viewer token for read-only access.</p>",
    );
    if let Some(e) = error {
        let _ = write!(body, "<p class=\"error\">{}</p>", esc(e));
    }
    let _ = write!(
        body,
        "<form class=\"login\" method=\"post\" action=\"{prefix}/login\">\
         <input type=\"hidden\" name=\"next\" value=\"{}\">\
         <label>Password<br><input type=\"password\" name=\"token\" autofocus></label><br>\
         <input class=\"btn btn-primary\" type=\"submit\" value=\"Log in\"></form></section></div>",
        esc(next),
    );
    slim_layout("Log in", &body)
}

pub fn error_page(status: u16, title: &str, detail: &str, prefix: &str) -> String {
    let back = format!("{prefix}/llm");
    slim_layout(
        title,
        &format!(
            "<h1 class=\"headline\">{status} · {}</h1><p>{}</p><p><a href=\"{back}\">Back to LLM calls</a></p>",
            esc(title),
            esc(detail)
        ),
    )
}

fn pager(base: &str, page: i64, total: i64) -> String {
    let size = super::queries::PAGE_SIZE;
    let pages = ((total.max(0) + size - 1) / size.max(1)).max(1);
    let mut out = format!(
        "<p class=\"pager\">Page {} of {pages} · {total} rows</p>",
        page + 1,
    );
    if pages > 1 {
        out.push_str("<p class=\"pager\">");
        if page > 0 {
            let _ = write!(out, "<a href=\"{base}page={}\">← newer</a>", page - 1);
        }
        if page + 1 < pages {
            let _ = write!(out, "<a href=\"{base}page={}\">older →</a>", page + 1);
        }
        out.push_str("</p>");
    }
    out
}

/// `{prefix}/llm`: every call, newest first.
pub fn llm_list(
    calls: &[CallRow],
    page: i64,
    total: i64,
    role: Role,
    prefix: &str,
    shell: &Shell,
) -> String {
    let mut body = String::from("<h1 class=\"headline\">LLM calls.</h1>");
    if calls.is_empty() {
        body.push_str("<p class=\"empty\">No calls logged yet.</p>");
        return layout("LLM calls", "/llm", &body, prefix, role, shell);
    }
    body.push_str(
        "<div class=\"table-wrap\"><table class=\"dense-table\">\
         <tr><th>Time</th><th>Point</th><th>Subject</th><th>Model</th>\
         <th>JSON</th><th>Effort</th><th>Finish</th><th>Prompt</th><th>Completion</th>\
         <th>Reasoning</th><th>Latency</th><th>Outcome</th><th></th></tr>",
    );
    for c in calls {
        let subject = c.subject.as_ref().map_or_else(
            || "—".to_string(),
            |s| format!("{}:{}", esc(&s.scope), esc(&s.id)),
        );
        let _ = write!(
            body,
            "<tr><td class=\"mono\">{}</td><td>{}</td><td class=\"mono\">{subject}</td>\
             <td class=\"mono\">{}</td><td>{}</td><td>{}</td><td>{}</td>\
             <td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td>\
             <td class=\"num\">{}</td><td>{}</td>\
             <td><a href=\"{prefix}/llm/{}\">open</a></td></tr>",
            esc(&fmt_ts_s(c.created_at)),
            esc(&c.point),
            esc(&c.model),
            esc(&c.json_mode),
            esc(opt(&c.effort)),
            esc(opt(&c.finish_reason)),
            opt_int(c.prompt_tokens),
            opt_int(c.completion_tokens),
            opt_int(c.reasoning_tokens),
            c.latency_ms
                .map_or_else(|| "—".to_string(), |ms| format!("{ms} ms")),
            outcome_chip(c.outcome),
            c.id,
        );
    }
    body.push_str("</table></div>");
    body.push_str(&pager(&format!("{prefix}/llm?"), page, total));
    layout("LLM calls", "/llm", &body, prefix, role, shell)
}

fn validation_block(c: &Call) -> String {
    let mut out = String::new();
    out.push_str("<dl class=\"kv\">");
    let _ = write!(
        out,
        "<dt>Schema</dt><dd>{}</dd>\
         <dt>Valid</dt><dd>{}</dd>",
        mono(&c.validation.schema),
        if c.validation.ok {
            chip("valid", "good")
        } else {
            chip("invalid", "bad")
        },
    );
    if let Some(e) = &c.validation.error {
        let _ = write!(out, "<dt>Error</dt><dd>{}</dd>", mono(e));
    }
    out.push_str("</dl>");
    if let Some(p) = &c.parsed_pretty {
        out.push_str("<h2 class=\"section-label\">Parsed</h2>");
        let _ = write!(out, "<pre>{}</pre>", esc(p));
    }
    out.push_str(
        "<h2 class=\"section-label\">Faithfulness</h2>\
         <p class=\"empty\">Not built yet: the faithfulness check lands with a later point.</p>",
    );
    out
}

fn label_block(l: &LabelRef) -> String {
    let mut out = String::from("<dl class=\"kv\">");
    let _ = write!(
        out,
        "<dt>Label</dt><dd>{}</dd>\
         <dt>Subject</dt><dd>{}:{}</dd>\
         <dt>Surface</dt><dd>{}</dd>\
         <dt>Kind</dt><dd>{}</dd>\
         <dt>Confidence</dt><dd class=\"mono\">{}</dd>\
         <dt>Source</dt><dd>{}</dd>\
         <dt>Signals</dt><dd>{}</dd>\
         <dt>Created</dt><dd class=\"mono\">{}</dd>",
        label_chip(&l.label),
        mono(&l.scope),
        id_cell(&l.scope_id),
        mono(opt(&l.surface)),
        mono(opt(&l.kind)),
        l.confidence,
        mono(&l.source),
        mono(opt(&l.signals)),
        esc(&fmt_ts_s(l.created_at)),
    );
    if let Some(n) = &l.note {
        let _ = write!(out, "<dt>Note</dt><dd>{}</dd>", mono(n));
    }
    out.push_str("</dl>");
    out
}

/// `{prefix}/llm/{id}`: one exchange in three columns, verbatim.
pub fn llm_detail(c: &Call, csrf: &str, role: Role, prefix: &str, shell: &Shell) -> String {
    let mut head = format!(
        "<h1 class=\"headline\"><span class=\"headline-rest\">Call </span>{}.</h1>\
         <p class=\"subline\">{} · {} · {}</p>",
        c.id,
        esc(&fmt_ts_s(c.created_at)),
        mono(&c.model),
        outcome_chip(c.outcome),
    );
    head.push_str("<dl class=\"kv\">");
    let _ = write!(
        head,
        "<dt>Call id</dt><dd>{}</dd>\
         <dt>Point</dt><dd>{}</dd>\
         <dt>Subject</dt><dd>{}</dd>\
         <dt>JSON mode</dt><dd>{}</dd>\
         <dt>Effort</dt><dd>{}</dd>\
         <dt>Finish</dt><dd>{}</dd>\
         <dt>Latency</dt><dd class=\"mono\">{}</dd>",
        id_cell(&c.id.to_string()),
        mono(&c.point),
        c.subject.as_ref().map_or_else(
            || "—".to_string(),
            |s| format!("{}:{}", mono(&s.scope), id_cell(&s.id)),
        ),
        mono(&c.json_mode),
        mono(opt(&c.effort)),
        mono(opt(&c.finish_reason)),
        c.latency_ms
            .map_or_else(|| "—".to_string(), |ms| format!("{ms} ms")),
    );
    if let Some(j) = &c.job {
        let _ = write!(
            head,
            "<dt>Job</dt><dd><a href=\"{prefix}/jobs#{}\">job {}</a> ({}) {}</dd>",
            j.id,
            j.id,
            esc(&j.point),
            status_chip(&j.status),
        );
    }
    if let Some(r) = &c.resend_parent {
        let _ = write!(
            head,
            "<dt>Re-send of</dt><dd><a href=\"{prefix}/llm/{r}\">call {r}</a></dd>"
        );
    }
    if !c.resend_children.is_empty() {
        head.push_str("<dt>Re-sent by</dt><dd>");
        for (i, r) in c.resend_children.iter().enumerate() {
            if i > 0 {
                head.push_str(" · ");
            }
            let _ = write!(head, "<a href=\"{prefix}/llm/{r}\">call {r}</a>");
        }
        head.push_str("</dd>");
    }
    head.push_str("</dl>");

    let mut sent = String::from("<section><h2 class=\"section-label\">Sent</h2>");
    sent.push_str("<h2 class=\"section-label\">System prompt</h2>");
    match &c.system_prompt {
        Some(p) => {
            let _ = write!(sent, "<pre>{}</pre>", esc(p));
        }
        None => sent.push_str("<p class=\"empty\">No system prompt in the stored request.</p>"),
    }
    sent.push_str("<h2 class=\"section-label\">Envelope</h2>");
    match &c.envelope_pretty {
        Some(e) => {
            let _ = write!(sent, "<pre>{}</pre>", esc(e));
        }
        None => sent.push_str("<p class=\"empty\">Response only; no request was stored.</p>"),
    }
    sent.push_str(
        "<details><summary class=\"mono\">full request bytes (exactly as stored)</summary>",
    );
    let _ = write!(sent, "<pre>{}</pre></details>", esc(&c.request_pretty));
    sent.push_str("</section>");

    let mut received = String::from("<section><h2 class=\"section-label\">Received</h2>");
    let _ = write!(
        received,
        "<dl class=\"kv\">\
         <dt>Tokens in</dt><dd class=\"mono\">{}</dd>\
         <dt>Tokens out</dt><dd class=\"mono\">{}</dd>\
         <dt>Reasoning</dt><dd class=\"mono\">{}</dd>\
         <dt>Reasoning stored</dt><dd class=\"mono\">{}</dd></dl>",
        opt_int(c.prompt_tokens),
        opt_int(c.completion_tokens),
        opt_int(c.reasoning_tokens),
        match (c.reasoning_full.as_ref().map(|r| r.len()), c.excerpt_capped) {
            (Some(n), capped) => format!(
                "{n} chars, the whole transcript{}",
                if capped {
                    " (the stored 2 KiB excerpt was capped)"
                } else {
                    ""
                }
            ),
            (None, _) => "—".to_string(),
        },
    );
    received.push_str("<h2 class=\"section-label\">Content</h2>");
    match &c.content_pretty {
        Some(t) => {
            let _ = write!(received, "<pre>{}</pre>", esc(t));
        }
        None => received.push_str("<p class=\"empty\">No content in the stored response.</p>"),
    }
    received.push_str("<h2 class=\"section-label\">Reasoning</h2>");
    match &c.reasoning_full {
        Some(r) => {
            let _ = write!(received, "<pre>{}</pre>", esc(r));
        }
        None => received.push_str("<p class=\"empty\">No reasoning in the stored response.</p>"),
    }
    received.push_str("</section>");

    let mut interp = String::from("<section><h2 class=\"section-label\">Interpreted</h2>");
    interp.push_str(&validation_block(c));
    // Only the label point produces a label and feeds the review
    // queue; the other points land an explanation, a class or a draft.
    if c.point == "label" {
        interp.push_str("<h2 class=\"section-label\">Produced label</h2>");
        match &c.produced_label {
            Some(l) => interp.push_str(&label_block(l)),
            None => interp.push_str("<p class=\"empty\">This call produced no label.</p>"),
        }
        interp.push_str("<h2 class=\"section-label\">What happened next</h2>");
        match &c.followup {
            Some(f) => {
                let _ = write!(
                    interp,
                    "<dl class=\"kv\"><dt>Review</dt><dd>{} {}</dd>\
                     <dt>At</dt><dd class=\"mono\">{}</dd></dl>",
                    if f.confirmed {
                        chip("confirmed", "good")
                    } else {
                        chip("rejected", "bad")
                    },
                    mono(&f.label),
                    esc(&fmt_ts_s(f.created_at)),
                );
            }
            None => {
                interp.push_str("<p class=\"empty\">No operator decision on that label yet.</p>");
            }
        }
    }
    if !c.siblings.is_empty() {
        interp.push_str(
            "<h2 class=\"section-label\">Retries on this subject</h2>\
             <div class=\"table-wrap\"><table class=\"dense-table\">",
        );
        for s in &c.siblings {
            let _ = write!(
                interp,
                "<tr><td><a href=\"{prefix}/llm/{}\">call {}</a>{}</td>\
                 <td class=\"mono\">{}</td><td class=\"mono\">budget {}</td>\
                 <td>{}</td></tr>",
                s.id,
                s.id,
                if s.is_self { " (this call)" } else { "" },
                esc(&fmt_ts_s(s.created_at)),
                opt_int(s.budget),
                outcome_chip(s.outcome),
            );
        }
        interp.push_str("</table></div>");
    }
    interp.push_str("</section>");

    let mut tail = String::new();
    if role == Role::Admin {
        tail = format!(
            "<section><h2 class=\"section-label\">Re-send</h2>\
             <p class=\"subline\">Same point, same subject, fresh budget; \
             the new call links back to this one.</p>\
             <form method=\"post\" action=\"{prefix}/llm/{}/resend\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{}\">\
             <button class=\"btn btn-warn\" type=\"submit\">Re-send this call</button>\
             </form></section>",
            c.id, csrf,
        );
        if c.siblings.iter().any(|s| !s.is_self && s.id > c.id) {
            tail.push_str("<p class=\"empty\">Note: a newer attempt exists on this subject.</p>");
        }
    }

    layout(
        &format!("Call {}", c.id),
        "/llm",
        &format!("{head}<div class=\"cols\">{sent}{received}{interp}</div>{tail}"),
        prefix,
        role,
        shell,
    )
}

/// `{prefix}/jobs`: the queue, newest first, with retry and cancel forms.
#[allow(clippy::too_many_arguments)]
pub fn jobs_list(
    jobs: &[Job],
    status: Option<&str>,
    page: i64,
    total: i64,
    csrf: &str,
    role: Role,
    prefix: &str,
    shell: &Shell,
) -> String {
    let mut body = String::from("<h1 class=\"headline\">Jobs.</h1><p class=\"subline\">Filter: ");
    let filters: &[(&str, &str)] = &[
        ("all", "all"),
        ("queued", "queued"),
        ("running", "running"),
        ("done", "done"),
        ("failed", "failed"),
    ];
    for (i, (v, name)) in filters.iter().enumerate() {
        if i > 0 {
            body.push_str(" · ");
        }
        let active = status.unwrap_or("all") == *v;
        if active {
            let _ = write!(body, "<strong>{name}</strong>");
        } else {
            let q = if *v == "all" {
                String::new()
            } else {
                format!("status={v}&")
            };
            let _ = write!(body, "<a href=\"{prefix}/jobs?{q}\">{name}</a>");
        }
    }
    body.push_str("</p>");
    if jobs.is_empty() {
        body.push_str("<p class=\"empty\">No jobs in this state.</p>");
        return layout("Jobs", "/jobs", &body, prefix, role, shell);
    }
    body.push_str(
        "<div class=\"table-wrap\"><table class=\"dense-table\">\
         <tr><th>Id</th><th>Point</th><th>Subject</th><th>Status</th>\
         <th>Attempts</th><th>Enqueued by</th><th>Last error</th><th>Created</th>\
         <th>Updated</th><th>Produced call</th><th></th></tr>",
    );
    for j in jobs {
        let _ = write!(
            body,
            "<tr id=\"{}\"><td class=\"num\">{}</td><td>{}</td>\
             <td class=\"mono\">{}:{}</td><td>{}</td><td class=\"num\">{}</td>\
             <td>{}</td><td>{}</td><td class=\"mono\">{}</td>\
             <td class=\"mono\">{}</td><td>{}</td><td>",
            j.id,
            j.id,
            esc(&j.point),
            esc(&j.subject.scope),
            esc(&j.subject.id),
            status_chip(&j.status),
            j.attempts,
            esc(&j.enqueued_by),
            esc(opt(&j.last_error)),
            esc(&fmt_ts_s(j.created_at)),
            esc(&fmt_ts_s(j.updated_at)),
            j.produced_call.map_or_else(
                || "—".to_string(),
                |id| format!("<a href=\"{prefix}/llm/{id}\">call {id}</a>"),
            ),
        );
        if role == Role::Admin && j.status == "failed" {
            let _ = write!(
                body,
                "<form class=\"inline\" method=\"post\" action=\"{prefix}/jobs/{}/retry\">\
                 <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                 <button class=\"btn\" type=\"submit\">retry</button></form>",
                j.id,
            );
        }
        if role == Role::Admin && j.status == "queued" {
            let _ = write!(
                body,
                "<form class=\"inline\" method=\"post\" action=\"{prefix}/jobs/{}/cancel\">\
                 <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                 <button class=\"btn btn-warn\" type=\"submit\">cancel</button></form>",
                j.id,
            );
        }
        body.push_str("</td></tr>");
    }
    body.push_str("</table></div>");
    let base = match status {
        Some(s) => format!("{prefix}/jobs?status={s}&"),
        None => format!("{prefix}/jobs?"),
    };
    body.push_str(&pager(&base, page, total));
    layout("Jobs", "/jobs", &body, prefix, role, shell)
}

fn score_chip(score: f64, threshold: Option<f64>) -> String {
    let text = format!("{score:.4}");
    match threshold {
        Some(t) if score >= t => chip(&format!("{text} ≥ {t}"), "bad"),
        Some(t) => chip(&format!("{text} < {t}"), "good"),
        None => chip(&text, "muted"),
    }
}

fn verdict_chip(verdict: &str) -> String {
    let class = match verdict {
        "block" => "bad",
        "allow" => "good",
        _ => "warn",
    };
    chip(verdict, class)
}

fn opt_f64(v: Option<f64>) -> String {
    v.map(|n| format!("{n:.2}"))
        .unwrap_or_else(|| "—".to_string())
}

fn turn_link(prefix: &str, turn_id: &Option<String>) -> String {
    match turn_id {
        Some(t) => format!("<a href=\"{prefix}/turns/{}\">{}</a>", esc(t), mono(t)),
        None => "—".to_string(),
    }
}

fn actor_link(prefix: &str, id: &str) -> String {
    format!("<a href=\"{prefix}/actors/{}\">{}</a>", esc(id), mono(id))
}

fn cluster_link(prefix: &str, key: &str) -> String {
    format!(
        "<a href=\"{prefix}/clusters/{}\">{}</a>",
        esc(key),
        mono(key)
    )
}

fn turn_table(prefix: &str, turns: &[TurnLite]) -> String {
    if turns.is_empty() {
        return "<p class=\"empty\">No turns.</p>".to_string();
    }
    let mut out = String::from(
        "<div class=\"table-wrap\"><table class=\"dense-table\">\
         <tr><th>Time</th><th>Turn</th><th>Route</th><th>Verb</th>\
         <th>Status</th><th>Surface</th><th>Verdict</th><th>Actor</th></tr>",
    );
    for t in turns {
        let _ = write!(
            out,
            "<tr><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td>{}</td>\
             <td class=\"num\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&fmt_ts_us(t.ts_us)),
            turn_link(prefix, &t.turn_id),
            mono(&t.route),
            mono(&t.verb),
            t.status,
            mono(opt(&t.surface)),
            t.verdict
                .as_deref()
                .map(verdict_chip)
                .unwrap_or_else(|| "—".to_string()),
            t.actor_id
                .as_deref()
                .map(|id| actor_link(prefix, id))
                .unwrap_or_else(|| "—".to_string()),
        );
    }
    out.push_str("</table></div>");
    out
}

fn label_table(labels: &[LabelRef]) -> String {
    if labels.is_empty() {
        return "<p class=\"empty\">No labels.</p>".to_string();
    }
    let mut out = String::from(
        "<div class=\"table-wrap\"><table class=\"dense-table\">\
         <tr><th>Created</th><th>Label</th><th>Source</th><th>Confidence</th>\
         <th>Surface</th><th>Window end</th><th>Kind</th><th>Note</th></tr>",
    );
    for l in labels {
        let _ = write!(
            out,
            "<tr><td class=\"mono\">{}</td><td>{}</td><td>{}</td>\
             <td class=\"num\">{}</td><td>{}</td><td class=\"mono\">{}</td>\
             <td>{}</td><td>{}</td></tr>",
            esc(&fmt_ts_s(l.created_at)),
            label_chip(&l.label),
            mono(&l.source),
            l.confidence,
            mono(opt(&l.surface)),
            esc(&fmt_ts_us(l.window_end_ts)),
            mono(opt(&l.kind)),
            mono(opt(&l.note)),
        );
    }
    out.push_str("</table></div>");
    out
}

fn proposal_block(prefix: &str, p: &TraceProposal) -> String {
    let mut out = String::from("<dl class=\"kv\">");
    let _ = write!(
        out,
        "<dt>Label</dt><dd>{}</dd>\
         <dt>Confidence</dt><dd class=\"mono\">{}</dd>\
         <dt>Reason</dt><dd>{}</dd>\
         <dt>Signals</dt><dd>{}</dd>",
        label_chip(&p.label.label),
        p.label.confidence,
        mono(&p.reason),
        mono(opt(&p.label.signals)),
    );
    match p.call_id {
        Some(id) => {
            let _ = write!(
                out,
                "<dt>Exchange</dt><dd><a href=\"{prefix}/llm/{id}\">call {id}</a></dd>"
            );
        }
        None => out.push_str("<dt>Exchange</dt><dd>—</dd>"),
    }
    out.push_str("</dl>");
    out
}

fn score_block(s: &ScoreView, threshold: Option<f64>) -> String {
    let mut out = String::from("<dl class=\"kv\">");
    let _ = write!(
        out,
        "<dt>Windside score</dt><dd>{}</dd>\
         <dt>Windside model</dt><dd>{}</dd>\
         <dt>Surface</dt><dd>{}</dd>\
         <dt>Scored</dt><dd class=\"mono\">{}</dd>",
        score_chip(s.score, threshold),
        mono(&s.model_version),
        mono(opt(&s.surface)),
        esc(&fmt_ts_us(s.ts_us)),
    );
    if !s.top3.is_empty() {
        out.push_str("<dt>Top 3</dt><dd><div class=\"table-wrap\"><table class=\"dense-table\">");
        for (name, gain) in &s.top3 {
            let _ = write!(
                out,
                "<tr><td>{}</td><td class=\"num\">{gain:.4}</td></tr>",
                mono(name),
            );
        }
        out.push_str("</table></div></dd>");
    }
    out.push_str("</dl>");
    out
}

fn feature_block(f: &FeatureRowView) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "<h2 class=\"section-label\">Feature row ({} {})</h2>\
         <p class=\"subline\">version {} · {} · anomalies {}</p>",
        esc(&f.scope),
        mono(&f.key),
        f.version,
        esc(&fmt_ts_us(f.ts_us)),
        f.clock_anomalies,
    );
    out.push_str(
        "<div class=\"table-wrap\"><table class=\"dense-table\"><tr><th>Feature</th><th>Value</th></tr>",
    );
    for (name, v) in &f.values {
        let _ = write!(
            out,
            "<tr><td>{}</td><td class=\"num\">{v}</td></tr>",
            mono(name)
        );
    }
    out.push_str("</table></div>");
    out
}

fn decision_table(decisions: &[DecisionView], now_s: i64) -> String {
    if decisions.is_empty() {
        return "<p class=\"empty\">No sticky decisions.</p>".to_string();
    }
    let mut out = String::from(
        "<div class=\"table-wrap\"><table class=\"dense-table\">\
         <tr><th>Scope</th><th>Key</th><th>Action</th><th>Mode</th>\
         <th>Rule</th><th>Since</th><th>Expires</th><th></th></tr>",
    );
    for d in decisions {
        let live = d.expires_at > now_s;
        let _ = write!(
            out,
            "<tr><td>{}</td><td class=\"mono\">{}</td><td>{}</td><td>{}</td>\
             <td>{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{}</td></tr>",
            mono(&d.scope),
            esc(&d.key),
            verdict_chip(&d.action),
            mono(&d.mode),
            mono(&format!("{} v{}", d.rule, d.rule_version)),
            esc(&fmt_ts_s(d.created_at)),
            esc(&fmt_ts_s(d.expires_at)),
            if live {
                chip("live", "warn")
            } else {
                chip("expired", "muted")
            },
        );
    }
    out.push_str("</table></div>");
    out
}

/// `{prefix}/turns/{turn_id}`: every stored column, the probe answer, the
/// resolution, the tap join, the rows and scores it produced.
#[allow(clippy::too_many_arguments)]
pub fn turn_detail(
    t: &Turn,
    tap: &TapInfo,
    features: &[FeatureRowView],
    scores: &[ScoreView],
    thresholds: &HashMap<String, f64>,
    role: Role,
    prefix: &str,
    shell: &Shell,
) -> String {
    let title = t.turn_id.as_deref().unwrap_or("?");
    let mut body = format!(
        "<h1 class=\"headline\"><span class=\"headline-rest\">Turn </span>{}.</h1>\
         <p class=\"subline\">{} · ingest #{}</p>",
        esc(title),
        esc(&fmt_ts_us(t.ts_us)),
        t.ingest_seq
            .map(|n| n.to_string())
            .unwrap_or_else(|| "—".to_string()),
    );
    body.push_str("<h2 class=\"section-label\">Probe answer and verdict</h2><dl class=\"kv\">");
    let _ = write!(
        body,
        "<dt>Verdict</dt><dd>{}</dd>\
         <dt>Gate</dt><dd>{}</dd>\
         <dt>Rules matched</dt><dd>{}</dd>",
        t.verdict
            .as_deref()
            .map(verdict_chip)
            .unwrap_or_else(|| "—".to_string()),
        match &t.gate {
            Some(g) => format!("<pre>{}</pre>", esc(&pretty_json(g))),
            None => "—".to_string(),
        },
        match &t.rules_matched {
            Some(r) => format!("<pre>{}</pre>", esc(&pretty_json(r))),
            None => "—".to_string(),
        },
    );
    body.push_str("</dl><h2 class=\"section-label\">Resolution</h2><dl class=\"kv\">");
    let _ = write!(
        body,
        "<dt>Actor</dt><dd>{}</dd><dt>Cluster</dt><dd>{}</dd>",
        t.actor_id
            .as_deref()
            .map(|id| actor_link(prefix, id))
            .unwrap_or_else(|| "—".to_string()),
        t.cluster_key
            .as_deref()
            .map(|key| cluster_link(prefix, key))
            .unwrap_or_else(|| "—".to_string()),
    );
    body.push_str("</dl><h2 class=\"section-label\">Tap join</h2><dl class=\"kv\">");
    let _ = write!(
        body,
        "<dt>JA4</dt><dd>{}</dd><dt>JA4T</dt><dd>{}</dd>\
         <dt>Class</dt><dd>{}</dd><dt>Mismatch</dt><dd>{}</dd>",
        mono(opt(&t.ja4)),
        mono(opt(&t.ja4t)),
        mono(&tap.class),
        if tap.mismatch {
            chip("ua_vs_ja4_mismatch", "warn")
        } else {
            chip("no", "muted")
        },
    );
    body.push_str("</dl><h2 class=\"section-label\">Windside scores</h2>");
    if scores.is_empty() {
        body.push_str(
            "<p class=\"empty\">This turn scored nothing (below the floor, or Windside off).</p>",
        );
    }
    for s in scores {
        body.push_str(&score_block(
            s,
            s.surface
                .as_deref()
                .and_then(|surface| thresholds.get(surface).copied()),
        ));
    }
    for f in features {
        body.push_str(&feature_block(f));
    }
    body.push_str("<h2 class=\"section-label\">Every stored column</h2><dl class=\"kv\">");
    let hex = |b: &Option<Vec<u8>>| {
        b.as_ref()
            .map(|v| v.iter().map(|x| format!("{x:02x}")).collect::<String>())
    };
    let rows: &[(&str, String)] = &[
        (
            "turn_id",
            t.turn_id.clone().unwrap_or_else(|| "—".to_string()),
        ),
        ("ts_us", t.ts_us.to_string()),
        ("ts", t.ts.to_string()),
        ("ts_ms", opt_int(t.ts_ms)),
        ("ingest_seq", opt_int(t.ingest_seq)),
        ("session_key", t.session_key.clone()),
        ("peer_key", t.peer_key.clone()),
        ("principal", t.principal.clone()),
        ("verb", t.verb.clone()),
        ("route", t.route.clone()),
        ("status", t.status.to_string()),
        ("surface", opt(&t.surface).to_string()),
        ("is_asset", opt_int(t.is_asset)),
        ("latency_ms", t.latency_ms.to_string()),
        ("bytes_in", t.bytes_in.to_string()),
        ("bytes_out", t.bytes_out.to_string()),
        ("req_shape", t.req_shape.clone()),
        ("resp_shape", t.resp_shape.clone()),
        ("bound", t.bound.clone()),
        ("shape", opt(&t.shape).to_string()),
        ("shape_hash", opt(&t.shape_hash).to_string()),
        ("flags", opt(&t.flags).to_string()),
        ("validation_failed", opt(&t.validation_failed).to_string()),
        ("exception", opt(&t.exception).to_string()),
        ("auth_event", opt(&t.auth_event).to_string()),
        ("credential_kind", opt(&t.credential_kind).to_string()),
        ("credential_hash", opt(&t.credential_hash).to_string()),
        ("credential_status", opt(&t.credential_status).to_string()),
        ("tag_id", opt(&t.tag_id).to_string()),
        ("tag_status", opt(&t.tag_status).to_string()),
        ("ip_hash", opt(&t.ip_hash).to_string()),
        ("net_hash", opt(&t.net_hash).to_string()),
        ("asn", opt_int(t.asn)),
        ("country", opt(&t.country).to_string()),
        ("ip_trust", opt(&t.ip_trust).to_string()),
        ("ua_hash", t.ua_hash.clone()),
        ("ua_class", opt(&t.ua_class).to_string()),
        ("ja4", opt(&t.ja4).to_string()),
        ("ja4t", opt(&t.ja4t).to_string()),
        ("h2_fp", opt(&t.h2_fp).to_string()),
        ("remote_port", opt_int(t.remote_port)),
        ("actor_id", opt(&t.actor_id).to_string()),
        ("cluster_key", opt(&t.cluster_key).to_string()),
        ("verdict", opt(&t.verdict).to_string()),
        (
            "ruleset_hash",
            hex(&t.ruleset_hash).unwrap_or_else(|| "—".to_string()),
        ),
        ("dropped_since_last", t.dropped_since_last.to_string()),
    ];
    for (k, v) in rows {
        let _ = write!(body, "<dt>{k}</dt><dd>{}</dd>", mono(v));
    }
    body.push_str("</dl>");
    layout(&format!("Turn {title}"), "", &body, prefix, role, shell)
}

fn pretty_json(raw: &str) -> String {
    serde_json::from_str::<serde_json::Value>(raw)
        .map(|v| serde_json::to_string_pretty(&v).unwrap_or_else(|_| raw.to_string()))
        .unwrap_or_else(|_| raw.to_string())
}

/// `{prefix}/trace/{turn_id}`: the seven steps as a vertical list.
pub fn trace_view(
    t: &Trace,
    thresholds: &HashMap<String, f64>,
    now_s: i64,
    role: Role,
    prefix: &str,
    shell: &Shell,
) -> String {
    let title = t.turn.turn_id.as_deref().unwrap_or("?");
    let mut body = format!(
        "<h1 class=\"headline\"><span class=\"headline-rest\">Trace </span>{}.</h1>\
         <p class=\"subline\">{} · seven steps from request to decision</p>",
        esc(title),
        esc(&fmt_ts_us(t.turn.ts_us)),
    );
    // 1. turn
    body.push_str(
        "<h2 class=\"section-label\">1 · Turn</h2><p class=\"subline\">from the turns row, ingested ",
    );
    body.push_str(&esc(&fmt_ts_us(t.turn.ts_us)));
    let _ = write!(
        body,
        "</p><p>{} {} {} → {} · {}</p>",
        mono(&t.turn.verb),
        mono(&t.turn.route),
        t.turn.status,
        t.turn
            .verdict
            .as_deref()
            .map(verdict_chip)
            .unwrap_or_else(|| "—".to_string()),
        turn_link(prefix, &t.turn.turn_id),
    );
    // 2. resolution
    body.push_str("<h2 class=\"section-label\">2 · Resolution</h2><p class=\"subline\">from actor_bindings, live; the turn's identifiers replayed from its columns</p>");
    match &t.resolution.actor {
        Some(a) => {
            let _ = write!(
                body,
                "<dl class=\"kv\"><dt>Actor</dt><dd>{} {}</dd>\
                 <dt>Confirmed</dt><dd>{}</dd>\
                 <dt>Opened</dt><dd class=\"mono\">{}</dd>\
                 <dt>Turns</dt><dd class=\"mono\">{}</dd></dl>",
                actor_link(prefix, &a.id),
                id_cell(&a.id),
                if a.confirmed {
                    chip("confirmed", "good")
                } else {
                    chip("provisional", "warn")
                },
                esc(&fmt_ts_us(a.opened_us)),
                a.turns,
            );
        }
        None => {
            body.push_str("<p class=\"empty\">No actor: the turn carried no strong identifier.</p>")
        }
    }
    if let Some(c) = &t.resolution.cluster_key {
        let _ = write!(body, "<p>Cluster {}</p>", cluster_link(prefix, c));
    }
    if !t.resolution.bindings.is_empty() {
        body.push_str("<div class=\"table-wrap\"><table class=\"dense-table\"><tr><th>Kind</th><th>Value</th><th>First</th><th>Last</th><th>Returned</th><th></th></tr>");
        for b in &t.resolution.bindings {
            let _ = write!(
                body,
                "<tr><td>{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td>\
                 <td class=\"mono\">{}</td><td>{}</td><td>{}</td></tr>",
                mono(&b.kind),
                esc(&b.value),
                esc(&fmt_ts_us(b.first_seen)),
                esc(&fmt_ts_us(b.last_seen)),
                if b.returned { "yes" } else { "no" },
                if b.on_this_turn {
                    chip("on this turn", "info")
                } else {
                    String::new()
                },
            );
        }
        body.push_str("</table></div>");
    }
    // 3. features
    body.push_str(
        "<h2 class=\"section-label\">3 · Feature rows</h2><p class=\"subline\">from feature_vectors, keyed by turn</p>",
    );
    if t.features.is_empty() {
        body.push_str("<p class=\"empty\">No feature row: a provisional actor holds one turn and is noise, or the window never formed.</p>");
    }
    for f in &t.features {
        body.push_str(&feature_block(f));
    }
    // 4. scores
    body.push_str("<h2 class=\"section-label\">4 · Windside scores</h2><p class=\"subline\">from scores, keyed by turn</p>");
    if t.scores.is_empty() {
        body.push_str(
            "<p class=\"empty\">No score: below the cold-start floor, or Windside off.</p>",
        );
    }
    for s in &t.scores {
        body.push_str(&score_block(
            s,
            s.surface
                .as_deref()
                .and_then(|surface| thresholds.get(surface).copied()),
        ));
    }
    // 5. proposal
    body.push_str(
        "<h2 class=\"section-label\">5 · Proposal</h2><p class=\"subline\">the latest llm_proposed label for the subject</p>",
    );
    match &t.proposal {
        Some(p) => body.push_str(&proposal_block(prefix, p)),
        None => body.push_str("<p class=\"empty\">No proposal for this subject.</p>"),
    }
    // 6. labels
    body.push_str(
        "<h2 class=\"section-label\">6 · Labels</h2><p class=\"subline\">every label on the subject, newest first</p>",
    );
    body.push_str(&label_table(&t.labels));
    // 7. decision
    body.push_str("<h2 class=\"section-label\">7 · Decision</h2><p class=\"subline\">the verdict plus the live sticky decision on the actor</p>");
    let _ = write!(
        body,
        "<dl class=\"kv\"><dt>Verdict</dt><dd>{}</dd></dl>",
        t.decision
            .verdict
            .as_deref()
            .map(verdict_chip)
            .unwrap_or_else(|| "—".to_string()),
    );
    if let Some(g) = &t.decision.gate_pretty {
        body.push_str("<h2 class=\"section-label\">Gate answer</h2>");
        let _ = write!(body, "<pre>{}</pre>", esc(g));
    }
    if let Some(r) = &t.decision.rules_pretty {
        body.push_str("<h2 class=\"section-label\">Rules matched</h2>");
        let _ = write!(body, "<pre>{}</pre>", esc(r));
    }
    match &t.decision.actor_decision {
        Some(d) => body.push_str(&decision_table(std::slice::from_ref(d), now_s)),
        None => body.push_str("<p class=\"empty\">No live sticky decision on this actor.</p>"),
    }
    layout(&format!("Trace {title}"), "", &body, prefix, role, shell)
}

/// `{prefix}/actors`: actors by latest score.
pub fn actors_list(
    rows: &[ActorRow],
    page: i64,
    total: i64,
    thresholds: &HashMap<String, f64>,
    role: Role,
    prefix: &str,
    shell: &Shell,
) -> String {
    let mut body = String::from("<h1 class=\"headline\">Actors.</h1>");
    if rows.is_empty() {
        body.push_str("<p class=\"empty\">No actors yet.</p>");
        return layout("Actors", "/actors", &body, prefix, role, shell);
    }
    body.push_str(
        "<div class=\"table-wrap\"><table class=\"dense-table\">\
         <tr><th>Actor</th><th>Kind</th><th>Surfaces</th><th>Confirmed</th>\
         <th>Turns held</th><th>Windside score</th><th>State</th><th>Cluster</th></tr>",
    );
    for r in rows {
        let state = [
            r.blocked.then(|| chip("blocked", "bad")),
            r.proposal_pending.then(|| chip("proposal", "info")),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
        let _ = write!(
            body,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
             <td class=\"num\">{}</td><td>{}</td><td>{} {}</td><td>{}</td></tr>",
            actor_link(prefix, &r.id),
            esc(&r.kind),
            esc(&r.surfaces.join(", ")),
            if r.confirmed { "yes" } else { "no" },
            r.turns_held
                .map(|n| n.to_string())
                .unwrap_or_else(|| "—".to_string()),
            r.score
                .map(|s| score_chip(
                    s,
                    r.score_surface
                        .as_deref()
                        .and_then(|surface| thresholds.get(surface).copied()),
                ))
                .unwrap_or_else(|| "—".to_string()),
            state,
            esc(r.latest_label.as_deref().unwrap_or("")),
            r.cluster
                .as_deref()
                .map(|key| cluster_link(prefix, key))
                .unwrap_or_else(|| "—".to_string()),
        );
    }
    body.push_str("</table></div>");
    body.push_str(&pager(&format!("{prefix}/actors?"), page, total));
    layout("Actors", "/actors", &body, prefix, role, shell)
}

fn activity_block(a: &super::queries::ActivityView) -> String {
    let mut out = String::from("<dl class=\"kv\">");
    let _ = write!(
        out,
        "<dt>Turns</dt><dd class=\"mono\">{}</dd>\
         <dt>Active</dt><dd class=\"mono\">{} s</dd>\
         <dt>Assets</dt><dd class=\"mono\">{}</dd>\
         <dt>Status</dt><dd class=\"mono\">2xx {} · 3xx {} · 404 {} · 401/403 {} · 429 {} · 5xx {}</dd>\
         <dt>IRI median</dt><dd class=\"mono\">{}</dd>\
         <dt>IRI CV</dt><dd class=\"mono\">{}</dd>\
         <dt>Routes</dt><dd class=\"mono\">{}</dd>",
        a.turns,
        a.active_s,
        a.assets,
        a.ok_2xx,
        a.redirects,
        a.not_found,
        a.denied,
        a.limited,
        a.errors_5xx,
        a.iri_median_ms.map(|n| format!("{n:.0} ms")).unwrap_or_else(|| "—".to_string()),
        opt_f64(a.iri_cv),
        a.distinct_routes,
    );
    out.push_str("</dl>");
    out
}

/// Ask the draft point for a rule over the subject's cluster. The
/// draft lands in the review table on `{prefix}/rules`, never live.
fn draft_form(prefix: &str, scope: &str, id: &str, csrf: &str) -> String {
    let (action, sub) = if scope == "actor" {
        (
            format!("{prefix}/actors/{id}/draft"),
            "drafts a rule for this actor's cluster",
        )
    } else {
        (
            format!("{prefix}/clusters/{id}/draft"),
            "drafts a rule for this cluster",
        )
    };
    format!(
        "<form method=\"post\" action=\"{action}\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <button class=\"btn\" type=\"submit\">Draft a rule</button></form>\
         <p class=\"subline\">Queues one draft job; {sub}.</p>",
    )
}

fn label_form(
    prefix: &str,
    scope: &str,
    id: &str,
    window_end_ts: Option<i64>,
    csrf: &str,
) -> String {
    let action = if scope == "actor" {
        format!("{prefix}/actors/{id}/label")
    } else {
        format!("{prefix}/clusters/{id}/label")
    };
    match window_end_ts {
        Some(ts) => format!(
            "<form method=\"post\" action=\"{action}\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <input type=\"hidden\" name=\"window_end_ts\" value=\"{ts}\">\
             <label>Verdict \
             <select name=\"label\">\
             <option value=\"benign\">benign</option>\
             <option value=\"malicious\">malicious</option>\
             <option value=\"unknown\">unknown</option>\
             </select></label> \
             <label>Note <input type=\"text\" name=\"note\" size=\"40\" maxlength=\"280\"></label> \
             <button class=\"btn\" type=\"submit\">Label this window</button></form>\
             <p class=\"subline\">Appends an operator label at 1.0 on window {ts}; latest wins on read.</p>",
        ),
        None => "<p class=\"empty\">No window yet: nothing to label.</p>".to_string(),
    }
}

/// `{prefix}/actors/{id}`: everything console.md §3 lists, in plain tables.
#[allow(clippy::too_many_arguments)]
pub fn actor_detail_page(
    d: &ActorDetail,
    tap: &TapInfo,
    thresholds: &HashMap<String, f64>,
    csrf: &str,
    now_s: i64,
    role: Role,
    prefix: &str,
    shell: &Shell,
) -> String {
    let mut body = format!(
        "<h1 class=\"headline\"><span class=\"headline-rest\">Actor </span>{}.</h1>\
         <p class=\"subline\">{} · {} · {}</p>",
        esc(&d.head.id),
        esc(&d.row.kind),
        if d.head.confirmed {
            chip("confirmed", "good")
        } else {
            chip("provisional", "warn")
        },
        if d.row.blocked {
            chip("blocked", "bad")
        } else {
            chip("not blocked", "muted")
        },
    );
    body.push_str("<h2 class=\"section-label\">Header</h2><dl class=\"kv\">");
    let _ = write!(
        body,
        "<dt>Actor id</dt><dd>{}</dd>\
         <dt>First seen</dt><dd class=\"mono\">{}</dd>\
         <dt>Last seen</dt><dd class=\"mono\">{}</dd>\
         <dt>Turns</dt><dd class=\"mono\">{}</dd>\
         <dt>Turns held</dt><dd class=\"mono\">{}</dd>\
         <dt>Surfaces</dt><dd>{}</dd>",
        id_cell(&d.head.id),
        esc(&fmt_ts_us(d.head.opened_us)),
        esc(&fmt_ts_us(d.head.last_us)),
        d.head.turns,
        d.row
            .turns_held
            .map(|n| n.to_string())
            .unwrap_or_else(|| "—".to_string()),
        esc(&d.row.surfaces.join(", ")),
    );
    if !d.merged_from.is_empty() {
        body.push_str("<dt>Merged from</dt><dd>");
        for (i, m) in d.merged_from.iter().enumerate() {
            if i > 0 {
                body.push_str(" · ");
            }
            body.push_str(&actor_link(prefix, m));
        }
        body.push_str("</dd>");
    }
    body.push_str("</dl><h2 class=\"section-label\">Bindings</h2>");
    if d.bindings.is_empty() {
        body.push_str("<p class=\"empty\">No bindings stored.</p>");
    } else {
        body.push_str("<div class=\"table-wrap\"><table class=\"dense-table\"><tr><th>Kind</th><th>Value</th><th>First</th><th>Last</th><th>Expires</th><th>State</th></tr>");
        for b in &d.bindings {
            let _ = write!(
                body,
                "<tr><td>{}</td><td>{}</td><td class=\"mono\">{}</td>\
                 <td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{} {}</td></tr>",
                mono(&b.kind),
                id_cell(&b.value),
                esc(&fmt_ts_us(b.first_seen)),
                esc(&fmt_ts_us(b.last_seen)),
                esc(&fmt_ts_us(b.expires_at)),
                if b.provisional {
                    chip("provisional", "warn")
                } else {
                    chip("strong", "muted")
                },
                if b.returned {
                    chip("returned", "good")
                } else {
                    String::new()
                },
            );
        }
        body.push_str("</table></div>");
    }
    body.push_str("<h2 class=\"section-label\">Client</h2><dl class=\"kv\">");
    let _ = write!(
        body,
        "<dt>UA class</dt><dd>{}</dd>\
         <dt>JA4</dt><dd>{} ({})</dd>\
         <dt>JA4T</dt><dd>{}</dd>\
         <dt>Mismatch</dt><dd>{}</dd>\
         <dt>Shape</dt><dd>{} ({} distinct)</dd>\
         <dt>Flag rates</dt><dd class=\"mono\">{}</dd>",
        mono(opt(&d.client.ua_class)),
        mono(opt(&d.client.ja4)),
        mono(&tap.class),
        mono(opt(&d.client.ja4t)),
        if tap.mismatch {
            chip("ua_vs_ja4_mismatch", "warn")
        } else {
            chip("no", "muted")
        },
        mono(opt(&d.client.shape_prefix)),
        d.client.shape_count,
        if d.client.flag_rates.is_empty() {
            "—".to_string()
        } else {
            d.client
                .flag_rates
                .iter()
                .map(|(f, r)| format!("{f} {r:.2}"))
                .collect::<Vec<_>>()
                .join(" · ")
        },
    );
    body.push_str("</dl><h2 class=\"section-label\">Cluster</h2>");
    match &d.row.cluster {
        Some(c) => {
            let _ = write!(
                body,
                "<p>{} · {} actors</p>",
                cluster_link(prefix, c),
                d.cluster_actors
            );
        }
        None => body.push_str("<p class=\"empty\">No cluster key on this actor's turns.</p>"),
    }
    body.push_str("<h2 class=\"section-label\">Activity</h2>");
    body.push_str(&activity_block(&d.activity));
    body.push_str("<h2 class=\"section-label\">Windside scores</h2>");
    match &d.scores.latest {
        Some(s) => {
            body.push_str(&score_block(
                s,
                s.surface
                    .as_deref()
                    .and_then(|surface| thresholds.get(surface).copied()),
            ));
            let _ = write!(body, "<p>{}</p>", esc(&d.scores.explanation));
        }
        None => body.push_str("<p class=\"empty\">No scores yet.</p>"),
    }
    if !d.scores.history.is_empty() {
        body.push_str("<h2 class=\"section-label\">Score history</h2><div class=\"table-wrap\"><table class=\"dense-table\"><tr><th>Time</th><th>Windside score</th></tr>");
        for (ts, v) in &d.scores.history {
            let _ = write!(
                body,
                "<tr><td class=\"mono\">{}</td><td class=\"num\">{v:.4}</td></tr>",
                esc(&fmt_ts_us(*ts)),
            );
        }
        body.push_str("</table></div>");
    }
    body.push_str("<h2 class=\"section-label\">Explanation</h2>");
    match &d.explanation {
        Some(e) => {
            let _ = write!(
                body,
                "<blockquote>{}</blockquote>\
                 <p class=\"subline\">score {score:.4} on turn {turn} · {ts}</p>",
                esc(&e.text),
                turn = turn_link(prefix, &Some(e.turn_id.clone())),
                ts = esc(&fmt_ts_us(e.ts_us)),
                score = e.score,
            );
        }
        None => body.push_str("<p class=\"empty\">No explanation for this actor yet.</p>"),
    }
    body.push_str("<h2 class=\"section-label\">Labels</h2>");
    body.push_str(&label_table(&d.labels));
    body.push_str("<h2 class=\"section-label\">Pending proposal</h2>");
    match &d.proposal {
        Some(p) => body.push_str(&proposal_block(prefix, p)),
        None => body.push_str("<p class=\"empty\">No proposal for this actor.</p>"),
    }
    if role == Role::Admin {
        body.push_str("<h2 class=\"section-label\">Label verdicts</h2>");
        body.push_str(&label_form(
            prefix,
            "actor",
            &d.head.id,
            d.window_end_ts,
            csrf,
        ));
        body.push_str("<h2 class=\"section-label\">Draft a rule</h2>");
        if d.row.cluster.is_some() {
            body.push_str(&draft_form(prefix, "actor", &d.head.id, csrf));
        } else {
            body.push_str(
                "<p class=\"empty\">No cluster on this actor's turns: nothing to draft over.</p>",
            );
        }
    }
    body.push_str("<h2 class=\"section-label\">Decisions</h2>");
    body.push_str(&decision_table(&d.decisions, now_s));
    if role == Role::Admin {
        if d.row.blocked {
            let _ = write!(
                body,
                "<form method=\"post\" action=\"{prefix}/actors/{}/unblock\">\
                 <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                 <button class=\"btn\" type=\"submit\">Unblock this actor</button></form>",
                d.head.id,
            );
        } else {
            let _ = write!(
                body,
                "<form method=\"post\" action=\"{prefix}/actors/{}/block\">\
                 <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                 <button class=\"btn btn-warn\" type=\"submit\">Block this actor for 24 h</button></form>\
                 <p class=\"subline\">A sticky actor-scope block, rule “operator”; it answers only in enforce mode.</p>",
                d.head.id,
            );
        }
    }
    body.push_str("<h2 class=\"section-label\">Similar actors</h2>");
    if d.similar.is_empty() {
        body.push_str("<p class=\"empty\">No other actor shares this cluster.</p>");
    } else {
        body.push_str("<div class=\"table-wrap\"><table class=\"dense-table\"><tr><th>Actor</th><th>Kind</th><th>Windside score</th><th>Turns</th><th>Last seen</th></tr>");
        for s in &d.similar {
            let _ = write!(
                body,
                "<tr><td>{}</td><td>{}</td><td class=\"num\">{}</td>\
                 <td class=\"num\">{}</td><td class=\"mono\">{}</td></tr>",
                actor_link(prefix, &s.id),
                esc(&s.kind),
                s.score
                    .map(|v| format!("{v:.4}"))
                    .unwrap_or_else(|| "—".to_string()),
                s.turns,
                esc(&fmt_ts_us(s.last_us)),
            );
        }
        body.push_str("</table></div>");
    }
    body.push_str("<h2 class=\"section-label\">Turns</h2>");
    body.push_str(&turn_table(prefix, &d.turns));
    body.push_str(&pager(
        &format!("{prefix}/actors/{}?", d.head.id),
        d.page,
        d.turn_total,
    ));
    layout(
        &format!("Actor {}", d.head.id),
        "/actors",
        &body,
        prefix,
        role,
        shell,
    )
}

/// `{prefix}/clusters`: clusters by latest score.
pub fn clusters_list(
    rows: &[ClusterRow],
    page: i64,
    total: i64,
    thresholds: &HashMap<String, f64>,
    role: Role,
    prefix: &str,
    shell: &Shell,
) -> String {
    let mut body = String::from("<h1 class=\"headline\">Clusters.</h1>");
    if rows.is_empty() {
        body.push_str("<p class=\"empty\">No clusters yet.</p>");
        return layout("Clusters", "/clusters", &body, prefix, role, shell);
    }
    body.push_str(
        "<div class=\"table-wrap\"><table class=\"dense-table\">\
         <tr><th>Cluster</th><th>Turns</th><th>Actors</th><th>Surfaces</th>\
         <th>Windside score</th><th>State</th></tr>",
    );
    for r in rows {
        let _ = write!(
            body,
            "<tr><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td>{}</td>\
             <td>{}</td><td>{} {}</td></tr>",
            cluster_link(prefix, &r.key),
            r.turns,
            r.actors,
            esc(&r.surfaces.join(", ")),
            r.score
                .map(|s| score_chip(
                    s,
                    r.score_surface
                        .as_deref()
                        .and_then(|surface| thresholds.get(surface).copied()),
                ))
                .unwrap_or_else(|| "—".to_string()),
            if r.proposal_pending {
                chip("proposal", "info")
            } else {
                String::new()
            },
            esc(r.latest_label.as_deref().unwrap_or("")),
        );
    }
    body.push_str("</table></div>");
    body.push_str(&pager(&format!("{prefix}/clusters?"), page, total));
    layout("Clusters", "/clusters", &body, prefix, role, shell)
}

/// `{prefix}/clusters/{key}`: the cluster scope in the same shape.
pub fn cluster_detail_page(
    d: &ClusterDetail,
    thresholds: &HashMap<String, f64>,
    csrf: &str,
    role: Role,
    prefix: &str,
    shell: &Shell,
) -> String {
    let mut body = format!(
        "<h1 class=\"headline\"><span class=\"headline-rest\">Cluster </span>{}.</h1>\
         <p class=\"subline\">{} turns · {} actors</p>",
        esc(&d.row.key),
        d.row.turns,
        d.row.actors,
    );
    body.push_str("<dl class=\"kv\">");
    let _ = write!(
        body,
        "<dt>Key</dt><dd>{}</dd>\
         <dt>Surfaces</dt><dd>{}</dd>\
         <dt>Last activity</dt><dd class=\"mono\">{}</dd>",
        id_cell(&d.row.key),
        esc(&d.row.surfaces.join(", ")),
        esc(&fmt_ts_us(d.row.last_us)),
    );
    body.push_str("</dl><h2 class=\"section-label\">Actors</h2>");
    if d.actor_ids.is_empty() {
        body.push_str("<p class=\"empty\">No actor bound any of this cluster's turns.</p>");
    } else {
        body.push_str("<p>");
        for (i, a) in d.actor_ids.iter().enumerate() {
            if i > 0 {
                body.push_str(" · ");
            }
            body.push_str(&actor_link(prefix, a));
        }
        body.push_str("</p>");
    }
    body.push_str("<h2 class=\"section-label\">Activity</h2>");
    body.push_str(&activity_block(&d.activity));
    body.push_str("<h2 class=\"section-label\">Windside scores</h2>");
    match &d.scores.latest {
        Some(s) => {
            body.push_str(&score_block(
                s,
                s.surface
                    .as_deref()
                    .and_then(|surface| thresholds.get(surface).copied()),
            ));
            let _ = write!(body, "<p>{}</p>", esc(&d.scores.explanation));
        }
        None => body.push_str("<p class=\"empty\">No scores yet.</p>"),
    }
    body.push_str("<h2 class=\"section-label\">Labels</h2>");
    body.push_str(&label_table(&d.labels));
    body.push_str("<h2 class=\"section-label\">Pending proposal</h2>");
    match &d.proposal {
        Some(p) => body.push_str(&proposal_block(prefix, p)),
        None => body.push_str("<p class=\"empty\">No proposal for this cluster.</p>"),
    }
    if role == Role::Admin {
        body.push_str("<h2 class=\"section-label\">Label verdicts</h2>");
        body.push_str(&label_form(
            prefix,
            "cluster",
            &d.row.key,
            d.window_end_ts,
            csrf,
        ));
        body.push_str("<h2 class=\"section-label\">Draft a rule</h2>");
        body.push_str(&draft_form(prefix, "cluster", &d.row.key, csrf));
    }
    body.push_str("<h2 class=\"section-label\">Turns</h2>");
    body.push_str(&turn_table(prefix, &d.turns));
    body.push_str(&pager(
        &format!("{prefix}/clusters/{}?", d.row.key),
        d.page,
        d.turn_total,
    ));
    layout(
        &format!("Cluster {}", d.row.key),
        "/clusters",
        &body,
        prefix,
        role,
        shell,
    )
}

/// `{prefix}/review`: the queue in the CLI's order, with `why_in_queue`.
pub fn review_list(
    rows: &[ReviewFull],
    thresholds: &HashMap<String, f64>,
    csrf: &str,
    role: Role,
    prefix: &str,
    shell: &Shell,
) -> String {
    let mut body = String::from("<h1 class=\"headline\">Review.</h1><p class=\"subline\">Disagreements first, then uncertain, unlabelled proposals, and the rest, as the CLI orders them. Decided rows leave until new evidence re-queues them.</p>");
    if rows.is_empty() {
        body.push_str("<p class=\"empty\">Nothing scored yet: no queue.</p>");
        return layout("Review", "/review", &body, prefix, role, shell);
    }
    for r in rows {
        let subject = if r.row.scope == "cluster" {
            cluster_link(prefix, &r.row.scope_id)
        } else {
            actor_link(prefix, &r.row.scope_id)
        };
        let _ = write!(
            body,
            "<h2 class=\"section-label\">{} <span class=\"mono\">{}</span></h2><p class=\"subline\">{}</p>",
            subject,
            esc(&r.row.scope),
            esc(&r.why.join(" · ")),
        );
        body.push_str("<dl class=\"kv\">");
        let _ = write!(
            body,
            "<dt>Windside score</dt><dd>{}</dd>\
             <dt>Surface</dt><dd>{}</dd>\
             <dt>Top features</dt><dd>{}</dd>\
             <dt>Turns held</dt><dd class=\"mono\">{}</dd>\
             <dt>Window end</dt><dd class=\"mono\">{}</dd>",
            score_chip(
                r.row.score,
                r.row
                    .surface
                    .as_deref()
                    .and_then(|s| thresholds.get(s).copied()),
            ),
            mono(opt(&r.row.surface)),
            esc(&r.row.top.join(", ")),
            r.row.held,
            esc(&fmt_ts_us(r.row.window_end_ts)),
        );
        body.push_str("</dl>");
        match &r.row.proposal {
            Some(p) => {
                let _ = write!(
                    body,
                    "<dl class=\"kv\"><dt>Proposal</dt><dd>{} {:.2}</dd>\
                     <dt>Signals</dt><dd>{}</dd>\
                     <dt>Cites</dt><dd class=\"mono\">{}</dd>\
                     <dt>Reason</dt><dd>{}</dd></dl>",
                    label_chip(&p.label),
                    p.confidence,
                    esc(&p.signals.join(", ")),
                    if p.cited_turns.is_empty() {
                        "-".to_string()
                    } else {
                        p.cited_turns
                            .iter()
                            .map(usize::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    },
                    mono(&p.reason),
                );
            }
            None => body.push_str("<p class=\"empty\">No proposal for this subject.</p>"),
        }
        if let Some(o) = &r.operator {
            let _ = write!(
                body,
                "<p>Operator: {} {} <span class=\"mono\">{}</span></p>",
                label_chip(&o.label),
                mono(opt(&o.note)),
                esc(&fmt_ts_s(o.created_at)),
            );
        }
        // Decide is actor-only until the console round reworks it;
        // cluster rows decide in the CLI.
        if role == Role::Admin && r.row.scope == "actor" {
            let _ = write!(
                body,
                "<form method=\"post\" action=\"{prefix}/review/decide\">\
                 <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                 <input type=\"hidden\" name=\"scope_id\" value=\"{}\">\
                 <input type=\"hidden\" name=\"window_end_ts\" value=\"{}\">",
                esc(&r.row.scope_id),
                r.row.window_end_ts,
            );
            if r.row.proposal.is_some() {
                body.push_str("<button class=\"btn\" type=\"submit\" name=\"verdict\" value=\"confirm\">confirm</button> ");
            }
            body.push_str(
                "<button class=\"btn\" type=\"submit\" name=\"verdict\" value=\"benign\">benign</button> \
                 <button class=\"btn\" type=\"submit\" name=\"verdict\" value=\"malicious\">malicious</button> \
                 <button class=\"btn\" type=\"submit\" name=\"verdict\" value=\"unknown\">unknown</button></form>",
            );
        } else if role == Role::Viewer && r.row.scope == "actor" {
            body.push_str("<p class=\"empty\">Deciding needs an admin session.</p>");
        } else {
            body.push_str("<p class=\"empty\">Cluster rows decide in the CLI for now.</p>");
        }
    }
    layout("Review", "/review", &body, prefix, role, shell)
}

/// `{prefix}/labels`: every label, with source and value filters.
#[allow(clippy::too_many_arguments)]
pub fn labels_list(
    labels: &[LabelRef],
    sources: &[String],
    source: Option<&str>,
    label: Option<&str>,
    page: i64,
    total: i64,
    role: Role,
    prefix: &str,
    shell: &Shell,
) -> String {
    let mut body = String::from("<h1 class=\"headline\">Labels.</h1><p class=\"subline\">Source: ");
    let link = |text: &str, href: Option<String>| {
        href.map(|h| format!("<a href=\"{h}\">{text}</a>"))
            .unwrap_or_else(|| format!("<strong>{text}</strong>"))
    };
    let base = |s: Option<&str>, l: Option<&str>| {
        let mut q = format!("{prefix}/labels?");
        if let Some(s) = s {
            q.push_str(&format!("source={s}&"));
        }
        if let Some(l) = l {
            q.push_str(&format!("label={l}&"));
        }
        q
    };
    body.push_str(&link(
        "all",
        (source.is_some() || label.is_some()).then(|| base(None, label)),
    ));
    for s in sources {
        body.push_str(" · ");
        let active = source == Some(s.as_str());
        body.push_str(&link(s, (!active).then(|| base(Some(s), label))));
    }
    body.push_str("<br>Label: ");
    body.push_str(&link("all", label.map(|_| base(source, None))));
    for v in ["benign", "malicious", "unknown"] {
        body.push_str(" · ");
        let active = label == Some(v);
        body.push_str(&link(v, (!active).then(|| base(source, Some(v)))));
    }
    body.push_str("</p>");
    if labels.is_empty() {
        body.push_str("<p class=\"empty\">No labels under these filters.</p>");
        return layout("Labels", "/labels", &body, prefix, role, shell);
    }
    body.push_str(
        "<div class=\"table-wrap\"><table class=\"dense-table\">\
         <tr><th>Created</th><th>Subject</th><th>Scope</th><th>Source</th>\
         <th>Label</th><th>Confidence</th><th>Kind</th><th>Surface</th><th>Signals</th><th>Note</th></tr>",
    );
    for l in labels {
        let subject = if l.scope == "actor" {
            actor_link(prefix, &l.scope_id)
        } else {
            cluster_link(prefix, &l.scope_id)
        };
        let _ = write!(
            body,
            "<tr><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td>{}</td>\
             <td>{}</td><td class=\"num\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&fmt_ts_s(l.created_at)),
            subject,
            mono(&l.scope),
            mono(&l.source),
            label_chip(&l.label),
            l.confidence,
            mono(opt(&l.kind)),
            mono(opt(&l.surface)),
            mono(opt(&l.signals)),
            mono(opt(&l.note)),
        );
    }
    body.push_str("</table></div>");
    body.push_str(&pager(&base(source, label), page, total));
    layout("Labels", "/labels", &body, prefix, role, shell)
}

/// `{prefix}/rules`: the install set and the overrides, plus what the
/// draft point wrote. Drafts are read-only here: one becomes a rule
/// through the overrides file, never through the page.
pub fn rules_list(
    rules: &[RuleView],
    drafts: &[DraftView],
    csrf: &str,
    role: Role,
    prefix: &str,
    shell: &Shell,
) -> String {
    let mut body = String::from("<h1 class=\"headline\">Rules.</h1><p class=\"subline\">The flag is per app and reversible; retire stays as removal from the overrides file.</p>");
    if rules.is_empty() {
        body.push_str("<p class=\"empty\">No rules installed.</p>");
    } else {
        body.push_str(
            "<div class=\"table-wrap\"><table class=\"dense-table\">\
             <tr><th>Id</th><th>Version</th><th>State</th><th>Mode</th><th>Action</th>\
             <th>Origin</th><th>Note</th><th>Matched 24h</th><th>Would act</th><th>Acted</th>\
             <th>Enabled</th><th></th></tr>",
        );
        for r in rules {
            let action = if r.enabled { "disable" } else { "enable" };
            let flip = if role == Role::Admin {
                format!(
                    "<form class=\"inline\" method=\"post\" action=\"{prefix}/rules/{}/{action}\">\
                     <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                     <button class=\"btn\" type=\"submit\">{action}</button></form>",
                    esc(&r.id),
                )
            } else {
                String::new()
            };
            let _ = write!(
                body,
                "<tr><td>{}</td><td class=\"num\">{}</td><td>{}</td><td>{}</td><td>{}</td>\
                 <td>{}</td><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td>\
                 <td class=\"num\">{}</td><td>{}</td><td>{}</td></tr>",
                mono(&r.id),
                r.version,
                mono(&r.state),
                mono(&r.mode),
                mono(&r.action),
                mono(&r.origin_kind),
                esc(&r.note),
                r.matched_24h,
                r.would_act_24h,
                r.acted_24h,
                if r.enabled {
                    chip("enabled", "good")
                } else {
                    chip("disabled", "muted")
                },
                flip,
            );
        }
        body.push_str("</table></div>");
    }
    body.push_str("<h2 class=\"section-label\">Drafts</h2>");
    if drafts.is_empty() {
        body.push_str("<p class=\"empty\">No drafts yet.</p>");
    } else {
        for d in drafts {
            let parse = if d.parse_ok {
                chip("parses", "good")
            } else {
                chip("rejected", "bad")
            };
            let call = d
                .call_id
                .map(|c| format!("<a href=\"{prefix}/llm/{c}\">call {c}</a>"))
                .unwrap_or_else(|| "—".to_string());
            let _ = write!(
                body,
                "<h3 class=\"section-label\">draft {} · {}</h3>\
                 <dl class=\"kv\">\
                 <dt>Cluster</dt><dd>{}</dd>\
                 <dt>Rule text</dt><dd>{}</dd>\
                 <dt>Reason</dt><dd>{}</dd>\
                 <dt>Status</dt><dd>{} · {}</dd>\
                 <dt>Call</dt><dd>{}</dd>\
                 <dt>Written</dt><dd class=\"mono\">{}</dd>\
                 </dl>",
                d.id,
                parse,
                cluster_link(prefix, &d.cluster_key),
                mono(&d.rule),
                esc(&d.reason),
                mono(&d.status),
                match &d.parse_error {
                    Some(e) => esc(e),
                    None => "—".to_string(),
                },
                call,
                esc(&fmt_ts_s(d.created_at)),
            );
        }
    }
    layout("Rules", "/rules", &body, prefix, role, shell)
}

/// `{prefix}/payloads`: the observed request patterns and what the
/// classify point made of them.
pub fn payloads_list(
    rows: &[PayloadRow],
    page: i64,
    total: i64,
    role: Role,
    prefix: &str,
    shell: &Shell,
) -> String {
    let mut body = String::from(
        "<h1 class=\"headline\">Payloads.</h1><p class=\"subline\">One row per distinct request pattern; the class is the classify point's verdict.</p>",
    );
    if rows.is_empty() {
        body.push_str("<p class=\"empty\">No payload patterns observed.</p>");
    } else {
        body.push_str(
            "<div class=\"table-wrap\"><table class=\"dense-table\">\
             <tr><th>Pattern</th><th>Method</th><th>Turns</th>\
             <th>Class</th><th>Confidence</th><th>Last seen</th></tr>",
        );
        for r in rows {
            let _ = write!(
                body,
                "<tr><td><a href=\"{prefix}/payloads/{}\">{}</a></td><td>{}</td>\
                 <td class=\"num\">{}</td><td>{}</td><td class=\"num\">{}</td>\
                 <td class=\"mono\">{}</td></tr>",
                esc(&r.pattern_hash),
                mono(&r.pattern),
                mono(&r.method),
                r.turns,
                match &r.category {
                    Some(c) => mono(c),
                    None => "—".to_string(),
                },
                r.confidence
                    .map(|v| format!("{v:.2}"))
                    .unwrap_or_else(|| "—".to_string()),
                esc(&fmt_ts_s(r.last_seen_s)),
            );
        }
        body.push_str("</table></div>");
        body.push_str(&pager(&format!("{prefix}/payloads?"), page, total));
    }
    layout("Payloads", "/payloads", &body, prefix, role, shell)
}

/// `{prefix}/payloads/{hash}`: one pattern and its class.
pub fn payload_detail_page(r: &PayloadRow, role: Role, prefix: &str, shell: &Shell) -> String {
    let call = r
        .call_id
        .map(|c| format!("<a href=\"{prefix}/llm/{c}\">call {c}</a>"))
        .unwrap_or_else(|| "—".to_string());
    let mut body = format!(
        "<h1 class=\"headline\"><span class=\"headline-rest\">Pattern </span>{}.</h1>\
         <p class=\"subline\">{} {}</p>",
        esc(&r.pattern_hash),
        mono(&r.method),
        mono(&r.pattern),
    );
    let _ = write!(
        body,
        "<dl class=\"kv\">\
         <dt>Class</dt><dd>{}</dd>\
         <dt>Confidence</dt><dd class=\"mono\">{}</dd>\
         <dt>Classified by</dt><dd>{}</dd>\
         <dt>Turns</dt><dd class=\"mono\">{}</dd>\
         <dt>First seen</dt><dd class=\"mono\">{}</dd>\
         <dt>Last seen</dt><dd class=\"mono\">{}</dd>\
         </dl>",
        match &r.category {
            Some(c) => mono(c),
            None => "not classified yet".to_string(),
        },
        r.confidence
            .map(|v| format!("{v:.2}"))
            .unwrap_or_else(|| "—".to_string()),
        call,
        r.turns,
        esc(&fmt_ts_s(r.first_seen_s)),
        esc(&fmt_ts_s(r.last_seen_s)),
    );
    layout("Payloads", "/payloads", &body, prefix, role, shell)
}

/// `{prefix}/model`: version, mode, thresholds, manifest, shadow report.
pub fn model_page(m: &ModelView, role: Role, prefix: &str, shell: &Shell) -> String {
    let mut body = String::from("<h1 class=\"headline\">Windside model.</h1><dl class=\"kv\">");
    let _ = write!(
        body,
        "<dt>Windside mode</dt><dd>{}</dd>\
         <dt>Model version</dt><dd>{}</dd>\
         <dt>Features version</dt><dd class=\"mono\">{}</dd>",
        mono(&m.windside_mode),
        mono(m.model_version.as_deref().unwrap_or("—")),
        m.features_version
            .map(|v| v.to_string())
            .unwrap_or_else(|| "—".to_string()),
    );
    body.push_str("</dl><h2 class=\"section-label\">Thresholds</h2>");
    if m.thresholds.is_empty() {
        body.push_str("<p class=\"empty\">No model loaded: no thresholds.</p>");
    } else {
        body.push_str("<div class=\"table-wrap\"><table class=\"dense-table\"><tr><th>Surface</th><th>Threshold</th></tr>");
        let mut ts = m.thresholds.clone();
        ts.sort_by(|a, b| a.0.cmp(&b.0));
        for (s, t) in ts {
            let _ = write!(
                body,
                "<tr><td>{}</td><td class=\"num\">{t}</td></tr>",
                mono(&s)
            );
        }
        body.push_str("</table></div>");
    }
    body.push_str("<h2 class=\"section-label\">Manifest metrics</h2>");
    match &m.manifest_pretty {
        Some(manifest) => {
            let _ = write!(body, "<pre>{}</pre>", esc(manifest));
        }
        None => body.push_str("<p class=\"empty\">No manifest on disk.</p>"),
    }
    body.push_str("<h2 class=\"section-label\">Shadow report</h2>");
    if let Some(e) = &m.shadow_error {
        let _ = write!(body, "<p class=\"error\">{}</p>", esc(e));
    }
    match &m.shadow {
        None => body.push_str("<p class=\"empty\">No shadow report.</p>"),
        Some(r) => {
            let _ = write!(
                body,
                "<dl class=\"kv\"><dt>Since</dt><dd class=\"mono\">{}</dd>\
                 <dt>Windside model</dt><dd>{}</dd>\
                 <dt>Agreement</dt><dd class=\"mono\">{} of {}</dd>\
                 <dt>Above without block</dt><dd class=\"mono\">{}</dd>\
                 <dt>Below with block</dt><dd class=\"mono\">{}</dd>\
                 <dt>Rows without threshold</dt><dd class=\"mono\">{}</dd></dl>",
                esc(&fmt_ts_us(r.since_us)),
                mono(r.model_version.as_deref().unwrap_or("—")),
                r.agreement.0,
                r.agreement.1,
                r.above_without_block,
                r.below_with_block,
                r.rows_without_threshold,
            );
            if !r.fp_by_surface.is_empty() {
                body.push_str("<h2 class=\"section-label\">Verified-credential FP by surface</h2><div class=\"table-wrap\"><table class=\"dense-table\"><tr><th>Surface</th><th>Above</th><th>Rows</th><th>Threshold</th></tr>");
                for (s, fp) in &r.fp_by_surface {
                    let _ = write!(
                        body,
                        "<tr><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td>\
                         <td class=\"num\">{}</td></tr>",
                        mono(s),
                        fp.above,
                        fp.rows,
                        fp.threshold
                            .map(|t| t.to_string())
                            .unwrap_or_else(|| "—".to_string()),
                    );
                }
                body.push_str("</table></div>");
            }
            if !r.by_scope.is_empty() {
                body.push_str("<h2 class=\"section-label\">Rows by scope</h2><div class=\"table-wrap\"><table class=\"dense-table\"><tr><th>Scope</th><th>Feature rows</th><th>Scored</th><th>Skipped</th></tr>");
                for (s, c) in &r.by_scope {
                    let _ = write!(
                        body,
                        "<tr><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td>\
                         <td class=\"num\">{}</td></tr>",
                        mono(s),
                        c.feature_rows,
                        c.scored,
                        c.skipped,
                    );
                }
                body.push_str("</table></div>");
            }
            if !r.disagreements.is_empty() {
                body.push_str("<h2 class=\"section-label\">Disagreements</h2><div class=\"table-wrap\"><table class=\"dense-table\"><tr><th>Actor</th><th>Surface</th><th>Windside score</th><th></th><th>Rule</th></tr>");
                for d in &r.disagreements {
                    let _ = write!(
                        body,
                        "<tr><td>{}</td><td>{}</td><td class=\"num\">{:.4}</td><td>{}</td><td>{}</td></tr>",
                        actor_link(prefix, &d.scope_id),
                        mono(opt(&d.surface)),
                        d.score,
                        if d.above_without_block { "above, no block" } else { "below, blocked" },
                        mono(opt(&d.rule)),
                    );
                }
                body.push_str("</table></div>");
                if r.disagreements_total > r.disagreements.len() {
                    let _ = write!(
                        body,
                        "<p class=\"subline\">{} more not shown.</p>",
                        r.disagreements_total - r.disagreements.len()
                    );
                }
            }
        }
    }
    layout("Windside model", "/model", &body, prefix, role, shell)
}

/// `{prefix}/features`: the feature names in order, with descriptions.
pub fn features_page(
    table: &[(String, String)],
    role: Role,
    prefix: &str,
    shell: &Shell,
) -> String {
    let mut body = String::from(
        "<h1 class=\"headline\">Features.</h1><p class=\"subline\">v2 vector, in stored order, from the code's table.</p>",
    );
    body.push_str("<div class=\"table-wrap\"><table class=\"dense-table\"><tr><th>#</th><th>Name</th><th>Description</th></tr>");
    for (i, (n, d)) in table.iter().enumerate() {
        let _ = write!(
            body,
            "<tr><td class=\"num\">{}</td><td>{}</td><td>{}</td></tr>",
            i,
            mono(n),
            esc(d),
        );
    }
    body.push_str("</table></div>");
    layout("Features", "/features", &body, prefix, role, shell)
}

pub fn settings_page(
    v: &SettingsView,
    csrf: &str,
    role: Role,
    prefix: &str,
    shell: &Shell,
) -> String {
    let mut body = String::from("<h1 class=\"headline\">Settings.</h1><div class=\"panels\">");
    // Protection panel: the global mode and the two big buttons.
    let _ = write!(
        body,
        "<section class=\"panel\" aria-label=\"Protection\">\
         <h3 class=\"panel-title\">Protection</h3><dl class=\"kv\">\
         <dt>Global mode</dt><dd>{}</dd>\
         <dt>Enforcement</dt><dd>{}</dd></dl>",
        mono(&v.mode),
        if v.enforce_allowed {
            "allowed".to_string()
        } else {
            "pinned off by LEESIDED_ENFORCE=false".to_string()
        },
    );
    if role == Role::Admin {
        let _ = write!(
            body,
            "<form method=\"post\" action=\"{prefix}/settings/mode\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <label>Global mode <select name=\"mode\">\
             <option value=\"monitor\"{}>monitor</option>\
             <option value=\"shadow\"{}>shadow</option>\
             <option value=\"enforce\"{}>enforce</option>\
             </select></label> \
             <button class=\"btn\" type=\"submit\">Set mode</button></form>",
            selected(&v.mode, "monitor"),
            selected(&v.mode, "shadow"),
            selected(&v.mode, "enforce"),
        );
        let _ = write!(
            body,
            "<form class=\"inline\" method=\"post\" action=\"{prefix}/settings/enforce\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <button class=\"btn btn-primary\" type=\"submit\">Turn enforcement on</button></form> \
             <form class=\"inline\" method=\"post\" action=\"{prefix}/settings/monitor\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <button class=\"btn\" type=\"submit\">Monitor only</button></form>\
             <p class=\"subline\">Turn enforcement on sets the global mode to enforce and \
             promotes the install rules to their file ceilings. Monitor only is the \
             kill switch: it sets the global mode back to monitor.</p>",
        );
    }
    body.push_str("</section>");
    // Assistant panel: autopilot and its thresholds.
    let _ = write!(
        body,
        "<section class=\"panel\" aria-label=\"Assistant\">\
         <h3 class=\"panel-title\">Assistant</h3><dl class=\"kv\">\
         <dt>Autopilot</dt><dd>{}</dd>\
         <dt>Minimum confidence</dt><dd class=\"mono\">{}</dd>\
         <dt>Block hours</dt><dd class=\"mono\">{}</dd></dl>",
        mono(&v.autopilot),
        esc(&v.min_confidence),
        esc(&v.block_hours),
    );
    if role == Role::Admin {
        let _ = write!(
            body,
            "<form method=\"post\" action=\"{prefix}/settings/autopilot\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <label>Autopilot <select name=\"autopilot\">\
             <option value=\"off\"{}>off</option>\
             <option value=\"block\"{}>block</option>\
             <option value=\"block+rules\"{}>block+rules</option>\
             </select></label> \
             <label>Minimum confidence \
             <input name=\"min_confidence\" size=\"6\" value=\"{}\"></label> \
             <label>Block hours <input name=\"block_hours\" size=\"6\" value=\"{}\"></label> \
             <button class=\"btn btn-primary\" type=\"submit\">Save assistant</button></form>\
             <p class=\"subline\">Applies at once, no restart. Off by default.</p>",
            selected(&v.autopilot, "off"),
            selected(&v.autopilot, "block"),
            selected(&v.autopilot, "block+rules"),
            esc(&v.min_confidence),
            esc(&v.block_hours),
        );
    }
    body.push_str("</section>");
    // Env-file rows, read-only and masked where secret.
    body.push_str(
        "<section class=\"panel\" aria-label=\"Environment\">\
         <h3 class=\"panel-title\">Environment</h3>\
         <p class=\"subline\">Read-only: edit the env file and restart leesided to change these.</p>\
         <dl class=\"kv\">",
    );
    for (name, display) in &v.env {
        let _ = write!(body, "<dt>{}</dt><dd>{}</dd>", mono(name), mono(display));
    }
    body.push_str("</dl></section></div>");
    layout("Settings", "/settings", &body, prefix, role, shell)
}

fn selected(current: &str, option: &str) -> &'static str {
    if current == option {
        " selected"
    } else {
        ""
    }
}

/// The "Turn enforcement on" confirmation step: the operator sees
/// what the button does before it happens.
pub fn settings_enforce_confirm(csrf: &str, role: Role, prefix: &str, shell: &Shell) -> String {
    let body = format!(
        "<h1 class=\"headline\">Turn enforcement on?</h1>\
         <p>This sets the global mode to enforce and promotes every install rule \
         to the mode its file names. Rules start acting on the next probe.</p>\
         <form class=\"inline\" method=\"post\" action=\"{prefix}/settings/enforce\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <input type=\"hidden\" name=\"confirm\" value=\"1\">\
         <button class=\"btn btn-primary\" type=\"submit\">Yes, turn enforcement on</button></form> \
         <a href=\"{prefix}/settings\">Cancel</a>",
    );
    layout(
        "Confirm enforcement",
        "/settings",
        &body,
        prefix,
        role,
        shell,
    )
}

/// What "Turn enforcement on" did, per rule: promoted, skipped, or failed.
pub fn settings_enforce_result(
    mode: &str,
    rows: &[(String, Result<String, String>)],
    role: Role,
    prefix: &str,
    shell: &Shell,
) -> String {
    let mut body = format!(
        "<h1 class=\"headline\">Enforcement on.</h1><p>Global mode is now {}.</p>\
         <div class=\"table-wrap\"><table class=\"dense-table\"><tr><th>Rule</th><th>Result</th></tr>",
        mono(mode),
    );
    for (id, r) in rows {
        let cell = match r {
            Ok(detail) => format!("{} {}", chip("promoted", "good"), esc(detail)),
            Err(e) => format!("{} {}", chip("failed", "bad"), esc(e)),
        };
        let _ = write!(body, "<tr><td>{}</td><td>{cell}</td></tr>", mono(id));
    }
    body.push_str("</table></div>");
    let _ = write!(
        body,
        "<p><a href=\"{prefix}/settings\">Back to Settings</a> · \
         <a href=\"{prefix}/rules\">Rules</a></p>"
    );
    layout("Enforcement on", "/settings", &body, prefix, role, shell)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_render_both_forms() {
        assert_eq!(
            fmt_ts_us(0),
            "1970-01-01 00:00:00.000000 UTC · 1970-01-01T00:00:00.000000Z"
        );
        assert_eq!(
            fmt_ts_us(1_793_525_899_584_489),
            "2026-11-01 09:38:19.584489 UTC · 2026-11-01T09:38:19.584489Z"
        );
        // A leap day, through the seconds form.
        assert_eq!(
            fmt_ts_s(1_709_208_000),
            "2024-02-29 12:00:00.000000 UTC · 2024-02-29T12:00:00.000000Z"
        );
    }

    #[test]
    fn escaping_covers_markup_and_attributes() {
        assert_eq!(
            esc("<a href=\"x\">a&b's</a>"),
            "&lt;a href=&quot;x&quot;&gt;a&amp;b&#39;s&lt;/a&gt;"
        );
    }
}
