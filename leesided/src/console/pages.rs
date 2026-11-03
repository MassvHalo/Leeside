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
    TapInfo, Trace, TraceProposal, Turn, TurnLite,
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

const STYLE: &str = r#"
:root {
  --ground: #0E1316; --surface: #161C21; --line: #222B33; --line2: #2B3640;
  --text: #E6EBEF; --sec: #AAB5BF; --faint: #7D8893;
  --accent: #63B6BF; --warn: #F0B983; --good: #8FD8B4; --bad: #F2A3A3;
}
* { box-sizing: border-box; }
body {
  background: var(--ground); color: var(--text);
  font: 14px/1.5 Manrope, system-ui, -apple-system, "Segoe UI", sans-serif;
  margin: 0; padding: 0 24px 48px;
}
header.top {
  display: flex; align-items: baseline; gap: 24px;
  border-bottom: 1px solid var(--line2); padding: 16px 0; margin-bottom: 24px;
}
header.top .brand { font-size: 17px; font-weight: 400; }
header.top .brand a { color: var(--text); text-decoration: none; }
header.top nav { display: flex; gap: 16px; font-size: 13px; }
header.top nav a { color: var(--sec); text-decoration: none; }
header.top nav a.on { color: var(--accent); }
header.top nav a:hover { color: var(--text); }
h1 { font-size: 20px; font-weight: 400; margin: 0 0 4px; }
h2 { font-weight: 400; color: var(--sec); margin: 28px 0 8px;
     font-family: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
     font-size: 13px; }
p.sub { color: var(--sec); margin: 0 0 16px; font-size: 13px; }
a { color: var(--accent); }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--line);
         vertical-align: top; }
th { color: var(--faint); font-weight: 400; font-size: 12px; }
tr:hover td { background: #131a1f; }
.mono, td.num, pre, code {
  font-family: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12.5px;
}
td.num { text-align: right; white-space: nowrap; }
pre {
  background: var(--surface); border: 1px solid var(--line); border-radius: 6px;
  padding: 12px 14px; overflow-x: auto; white-space: pre-wrap; word-break: break-word;
  margin: 8px 0 16px;
}
.chip {
  display: inline-block; font-size: 12px; padding: 1px 9px; border-radius: 20px;
  border: 1px solid var(--line2); color: var(--sec); white-space: nowrap;
}
.chip.good { color: var(--good); border-color: #2c4a3e; }
.chip.warn { color: var(--warn); border-color: #4d3f2c; }
.chip.bad { color: var(--bad); border-color: #4d2e2e; }
.chip.info { color: var(--accent); border-color: #23484d; }
.chip.muted { color: var(--faint); }
.cols { display: grid; grid-template-columns: 1fr; gap: 0 24px; }
@media (min-width: 1400px) { .cols { grid-template-columns: 1fr 1fr 1fr; } }
.cols > section { min-width: 0; }
.kv { display: grid; grid-template-columns: 160px 1fr; gap: 4px 12px;
      font-size: 13px; margin: 0 0 8px; }
.kv dt { color: var(--faint); }
.kv dd { margin: 0; overflow-wrap: anywhere; }
button.copy, button.btn, input.btn {
  background: transparent; color: var(--faint); border: 1px solid var(--line2);
  border-radius: 4px; font-size: 11.5px; padding: 1px 8px; cursor: pointer;
  font-family: inherit;
}
button.copy:hover, button.btn:hover, input.btn:hover { color: var(--text); border-color: var(--faint); }
button.btn-warn { color: var(--warn); border-color: #4d3f2c; }
form.inline { display: inline; }
form.login, form.plain { max-width: 420px; }
form.login input[type=password], form.plain input[type=text] {
  width: 100%; background: var(--surface); border: 1px solid var(--line2);
  color: var(--text); border-radius: 4px; padding: 8px 10px; font-size: 14px;
  margin: 8px 0 12px;
}
.pager { margin: 16px 0; color: var(--sec); font-size: 13px; }
.pager a { margin: 0 8px; }
p.error { color: var(--bad); }
p.empty { color: var(--faint); }
.idcell { display: inline-flex; align-items: center; gap: 8px; }
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

/// The nav only links pages that exist; later steps extend it.
/// `active` is the path suffix (`/actors`), empty when none matches.
fn nav(prefix: &str, active: &str) -> String {
    let mut out = String::from("<nav>");
    for (suffix, name) in [
        ("/", "Overview"),
        ("/review", "Review"),
        ("/actors", "Actors"),
        ("/clusters", "Clusters"),
        ("/labels", "Labels"),
        ("/llm", "LLM calls"),
        ("/jobs", "Jobs"),
        ("/rules", "Rules"),
        ("/payloads", "Payloads"),
        ("/model", "Windside model"),
        ("/features", "Features"),
    ] {
        let on = if active == suffix {
            " class=\"on\""
        } else {
            ""
        };
        let _ = write!(out, "<a href=\"{prefix}{suffix}\"{on}>{name}</a>");
    }
    out.push_str("</nav>");
    out
}

fn layout(title: &str, active: &str, body: &str, prefix: &str, role: Option<Role>) -> String {
    let badge = role.map(|r| chip(r.as_str(), "muted")).unwrap_or_default();
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{} · Windside</title><style>{STYLE}</style></head>\
         <body><header class=\"top\"><span class=\"brand\">\
         <a href=\"{prefix}/llm\">Windside</a></span>{badge}{}</header>\
         <main>{body}</main>{COPY_SCRIPT}</body></html>",
        esc(title),
        nav(prefix, active),
    )
}

pub fn login_page(next: &str, error: Option<&str>, prefix: &str) -> String {
    let mut body =
        String::from("<h1>Log in to Windside</h1><p class=\"sub\">Operator or viewer token.</p>");
    if let Some(e) = error {
        let _ = write!(body, "<p class=\"error\">{}</p>", esc(e));
    }
    let _ = write!(
        body,
        "<form class=\"login\" method=\"post\" action=\"{prefix}/login\">\
         <input type=\"hidden\" name=\"next\" value=\"{}\">\
         <label>Token<br><input type=\"password\" name=\"token\" autofocus></label><br>\
         <input class=\"btn\" type=\"submit\" value=\"Log in\"></form>",
        esc(next),
    );
    layout("Log in", "", &body, prefix, None)
}

pub fn error_page(status: u16, title: &str, detail: &str, prefix: &str) -> String {
    let back = format!("{prefix}/llm");
    layout(
        title,
        "",
        &format!(
            "<h1>{status} · {}</h1><p>{}</p><p><a href=\"{back}\">Back to LLM calls</a></p>",
            esc(title),
            esc(detail)
        ),
        prefix,
        None,
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
pub fn llm_list(calls: &[CallRow], page: i64, total: i64, role: Role, prefix: &str) -> String {
    let mut body = String::from("<h1>LLM calls</h1>");
    if calls.is_empty() {
        body.push_str("<p class=\"empty\">No calls logged yet.</p>");
        return layout("LLM calls", "/llm", &body, prefix, Some(role));
    }
    body.push_str(
        "<table><tr><th>Time</th><th>Point</th><th>Subject</th><th>Model</th>\
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
    body.push_str("</table>");
    body.push_str(&pager(&format!("{prefix}/llm?"), page, total));
    layout("LLM calls", "/llm", &body, prefix, Some(role))
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
        out.push_str("<h2>Parsed</h2>");
        let _ = write!(out, "<pre>{}</pre>", esc(p));
    }
    out.push_str(
        "<h2>Faithfulness</h2>\
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
pub fn llm_detail(c: &Call, csrf: &str, role: Role, prefix: &str) -> String {
    let mut head = format!(
        "<h1>Call {}</h1><p class=\"sub\">{} · {} · {}</p>",
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

    let mut sent = String::from("<section><h2>Sent</h2>");
    sent.push_str("<h2>System prompt</h2>");
    match &c.system_prompt {
        Some(p) => {
            let _ = write!(sent, "<pre>{}</pre>", esc(p));
        }
        None => sent.push_str("<p class=\"empty\">No system prompt in the stored request.</p>"),
    }
    sent.push_str("<h2>Envelope</h2>");
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

    let mut received = String::from("<section><h2>Received</h2>");
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
    received.push_str("<h2>Content</h2>");
    match &c.content_pretty {
        Some(t) => {
            let _ = write!(received, "<pre>{}</pre>", esc(t));
        }
        None => received.push_str("<p class=\"empty\">No content in the stored response.</p>"),
    }
    received.push_str("<h2>Reasoning</h2>");
    match &c.reasoning_full {
        Some(r) => {
            let _ = write!(received, "<pre>{}</pre>", esc(r));
        }
        None => received.push_str("<p class=\"empty\">No reasoning in the stored response.</p>"),
    }
    received.push_str("</section>");

    let mut interp = String::from("<section><h2>Interpreted</h2>");
    interp.push_str(&validation_block(c));
    // Only the label point produces a label and feeds the review
    // queue; the other points land an explanation, a class or a draft.
    if c.point == "label" {
        interp.push_str("<h2>Produced label</h2>");
        match &c.produced_label {
            Some(l) => interp.push_str(&label_block(l)),
            None => interp.push_str("<p class=\"empty\">This call produced no label.</p>"),
        }
        interp.push_str("<h2>What happened next</h2>");
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
        interp.push_str("<h2>Retries on this subject</h2><table>");
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
        interp.push_str("</table>");
    }
    interp.push_str("</section>");

    let mut tail = String::new();
    if role == Role::Admin {
        tail = format!(
            "<section><h2>Re-send</h2>\
             <p class=\"sub\">Same point, same subject, fresh budget; \
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
        Some(role),
    )
}

/// `{prefix}/jobs`: the queue, newest first, with retry and cancel forms.
pub fn jobs_list(
    jobs: &[Job],
    status: Option<&str>,
    page: i64,
    total: i64,
    csrf: &str,
    role: Role,
    prefix: &str,
) -> String {
    let mut body = String::from("<h1>Jobs</h1><p class=\"sub\">Filter: ");
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
        return layout("Jobs", "/jobs", &body, prefix, Some(role));
    }
    body.push_str(
        "<table><tr><th>Id</th><th>Point</th><th>Subject</th><th>Status</th>\
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
    body.push_str("</table>");
    let base = match status {
        Some(s) => format!("{prefix}/jobs?status={s}&"),
        None => format!("{prefix}/jobs?"),
    };
    body.push_str(&pager(&base, page, total));
    layout("Jobs", "/jobs", &body, prefix, Some(role))
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
        "<table><tr><th>Time</th><th>Turn</th><th>Route</th><th>Verb</th>\
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
    out.push_str("</table>");
    out
}

fn label_table(labels: &[LabelRef]) -> String {
    if labels.is_empty() {
        return "<p class=\"empty\">No labels.</p>".to_string();
    }
    let mut out = String::from(
        "<table><tr><th>Created</th><th>Label</th><th>Source</th><th>Confidence</th>\
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
    out.push_str("</table>");
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
        out.push_str("<dt>Top 3</dt><dd><table>");
        for (name, gain) in &s.top3 {
            let _ = write!(
                out,
                "<tr><td>{}</td><td class=\"num\">{gain:.4}</td></tr>",
                mono(name),
            );
        }
        out.push_str("</table></dd>");
    }
    out.push_str("</dl>");
    out
}

fn feature_block(f: &FeatureRowView) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "<h2>Feature row ({} {})</h2>\
         <p class=\"sub\">version {} · {} · anomalies {}</p>",
        esc(&f.scope),
        mono(&f.key),
        f.version,
        esc(&fmt_ts_us(f.ts_us)),
        f.clock_anomalies,
    );
    out.push_str("<table><tr><th>Feature</th><th>Value</th></tr>");
    for (name, v) in &f.values {
        let _ = write!(
            out,
            "<tr><td>{}</td><td class=\"num\">{v}</td></tr>",
            mono(name)
        );
    }
    out.push_str("</table>");
    out
}

fn decision_table(decisions: &[DecisionView], now_s: i64) -> String {
    if decisions.is_empty() {
        return "<p class=\"empty\">No sticky decisions.</p>".to_string();
    }
    let mut out = String::from(
        "<table><tr><th>Scope</th><th>Key</th><th>Action</th><th>Mode</th>\
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
    out.push_str("</table>");
    out
}

/// `{prefix}/turns/{turn_id}`: every stored column, the probe answer, the
/// resolution, the tap join, the rows and scores it produced.
pub fn turn_detail(
    t: &Turn,
    tap: &TapInfo,
    features: &[FeatureRowView],
    scores: &[ScoreView],
    thresholds: &HashMap<String, f64>,
    role: Role,
    prefix: &str,
) -> String {
    let title = t.turn_id.as_deref().unwrap_or("?");
    let mut body = format!(
        "<h1>Turn {}</h1><p class=\"sub\">{} · ingest #{}</p>",
        mono(title),
        esc(&fmt_ts_us(t.ts_us)),
        t.ingest_seq
            .map(|n| n.to_string())
            .unwrap_or_else(|| "—".to_string()),
    );
    body.push_str("<h2>Probe answer and verdict</h2><dl class=\"kv\">");
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
    body.push_str("</dl><h2>Resolution</h2><dl class=\"kv\">");
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
    body.push_str("</dl><h2>Tap join</h2><dl class=\"kv\">");
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
    body.push_str("</dl><h2>Windside scores</h2>");
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
    body.push_str("<h2>Every stored column</h2><dl class=\"kv\">");
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
    layout(&format!("Turn {title}"), "", &body, prefix, Some(role))
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
) -> String {
    let title = t.turn.turn_id.as_deref().unwrap_or("?");
    let mut body = format!(
        "<h1>Trace {}</h1><p class=\"sub\">{} · seven steps from request to decision</p>",
        mono(title),
        esc(&fmt_ts_us(t.turn.ts_us)),
    );
    // 1. turn
    body.push_str("<h2>1 · Turn</h2><p class=\"sub\">from the turns row, ingested ");
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
    body.push_str("<h2>2 · Resolution</h2><p class=\"sub\">from actor_bindings, live; the turn's identifiers replayed from its columns</p>");
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
        body.push_str("<table><tr><th>Kind</th><th>Value</th><th>First</th><th>Last</th><th>Returned</th><th></th></tr>");
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
        body.push_str("</table>");
    }
    // 3. features
    body.push_str(
        "<h2>3 · Feature rows</h2><p class=\"sub\">from feature_vectors, keyed by turn</p>",
    );
    if t.features.is_empty() {
        body.push_str("<p class=\"empty\">No feature row: a provisional actor holds one turn and is noise, or the window never formed.</p>");
    }
    for f in &t.features {
        body.push_str(&feature_block(f));
    }
    // 4. scores
    body.push_str("<h2>4 · Windside scores</h2><p class=\"sub\">from scores, keyed by turn</p>");
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
        "<h2>5 · Proposal</h2><p class=\"sub\">the latest llm_proposed label for the subject</p>",
    );
    match &t.proposal {
        Some(p) => body.push_str(&proposal_block(prefix, p)),
        None => body.push_str("<p class=\"empty\">No proposal for this subject.</p>"),
    }
    // 6. labels
    body.push_str(
        "<h2>6 · Labels</h2><p class=\"sub\">every label on the subject, newest first</p>",
    );
    body.push_str(&label_table(&t.labels));
    // 7. decision
    body.push_str("<h2>7 · Decision</h2><p class=\"sub\">the verdict plus the live sticky decision on the actor</p>");
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
        body.push_str("<h2>Gate answer</h2>");
        let _ = write!(body, "<pre>{}</pre>", esc(g));
    }
    if let Some(r) = &t.decision.rules_pretty {
        body.push_str("<h2>Rules matched</h2>");
        let _ = write!(body, "<pre>{}</pre>", esc(r));
    }
    match &t.decision.actor_decision {
        Some(d) => body.push_str(&decision_table(std::slice::from_ref(d), now_s)),
        None => body.push_str("<p class=\"empty\">No live sticky decision on this actor.</p>"),
    }
    layout(&format!("Trace {title}"), "", &body, prefix, Some(role))
}

/// `{prefix}/actors`: actors by latest score.
pub fn actors_list(
    rows: &[ActorRow],
    page: i64,
    total: i64,
    thresholds: &HashMap<String, f64>,
    role: Role,
    prefix: &str,
) -> String {
    let mut body = String::from("<h1>Actors</h1>");
    if rows.is_empty() {
        body.push_str("<p class=\"empty\">No actors yet.</p>");
        return layout("Actors", "/actors", &body, prefix, Some(role));
    }
    body.push_str(
        "<table><tr><th>Actor</th><th>Kind</th><th>Surfaces</th><th>Confirmed</th>\
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
    body.push_str("</table>");
    body.push_str(&pager(&format!("{prefix}/actors?"), page, total));
    layout("Actors", "/actors", &body, prefix, Some(role))
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
         <p class=\"sub\">Queues one draft job; {sub}.</p>",
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
             <p class=\"sub\">Appends an operator label at 1.0 on window {ts}; latest wins on read.</p>",
        ),
        None => "<p class=\"empty\">No window yet: nothing to label.</p>".to_string(),
    }
}

/// `{prefix}/actors/{id}`: everything console.md §3 lists, in plain tables.
pub fn actor_detail_page(
    d: &ActorDetail,
    tap: &TapInfo,
    thresholds: &HashMap<String, f64>,
    csrf: &str,
    now_s: i64,
    role: Role,
    prefix: &str,
) -> String {
    let mut body = format!(
        "<h1>Actor {}</h1><p class=\"sub\">{} · {} · {}</p>",
        mono(&d.head.id),
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
    body.push_str("<h2>Header</h2><dl class=\"kv\">");
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
    body.push_str("</dl><h2>Bindings</h2>");
    if d.bindings.is_empty() {
        body.push_str("<p class=\"empty\">No bindings stored.</p>");
    } else {
        body.push_str("<table><tr><th>Kind</th><th>Value</th><th>First</th><th>Last</th><th>Expires</th><th>State</th></tr>");
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
        body.push_str("</table>");
    }
    body.push_str("<h2>Client</h2><dl class=\"kv\">");
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
    body.push_str("</dl><h2>Cluster</h2>");
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
    body.push_str("<h2>Activity</h2>");
    body.push_str(&activity_block(&d.activity));
    body.push_str("<h2>Windside scores</h2>");
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
        body.push_str("<h2>Score history</h2><table><tr><th>Time</th><th>Windside score</th></tr>");
        for (ts, v) in &d.scores.history {
            let _ = write!(
                body,
                "<tr><td class=\"mono\">{}</td><td class=\"num\">{v:.4}</td></tr>",
                esc(&fmt_ts_us(*ts)),
            );
        }
        body.push_str("</table>");
    }
    body.push_str("<h2>Explanation</h2>");
    match &d.explanation {
        Some(e) => {
            let _ = write!(
                body,
                "<blockquote>{}</blockquote>\
                 <p class=\"sub\">score {score:.4} on turn {turn} · {ts}</p>",
                esc(&e.text),
                turn = turn_link(prefix, &Some(e.turn_id.clone())),
                ts = esc(&fmt_ts_us(e.ts_us)),
                score = e.score,
            );
        }
        None => body.push_str("<p class=\"empty\">No explanation for this actor yet.</p>"),
    }
    body.push_str("<h2>Labels</h2>");
    body.push_str(&label_table(&d.labels));
    body.push_str("<h2>Pending proposal</h2>");
    match &d.proposal {
        Some(p) => body.push_str(&proposal_block(prefix, p)),
        None => body.push_str("<p class=\"empty\">No proposal for this actor.</p>"),
    }
    if role == Role::Admin {
        body.push_str("<h2>Label verdicts</h2>");
        body.push_str(&label_form(
            prefix,
            "actor",
            &d.head.id,
            d.window_end_ts,
            csrf,
        ));
        body.push_str("<h2>Draft a rule</h2>");
        if d.row.cluster.is_some() {
            body.push_str(&draft_form(prefix, "actor", &d.head.id, csrf));
        } else {
            body.push_str(
                "<p class=\"empty\">No cluster on this actor's turns: nothing to draft over.</p>",
            );
        }
    }
    body.push_str("<h2>Decisions</h2>");
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
                 <p class=\"sub\">A sticky actor-scope block, rule “operator”; it answers only in enforce mode.</p>",
                d.head.id,
            );
        }
    }
    body.push_str("<h2>Similar actors</h2>");
    if d.similar.is_empty() {
        body.push_str("<p class=\"empty\">No other actor shares this cluster.</p>");
    } else {
        body.push_str("<table><tr><th>Actor</th><th>Kind</th><th>Windside score</th><th>Turns</th><th>Last seen</th></tr>");
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
        body.push_str("</table>");
    }
    body.push_str("<h2>Turns</h2>");
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
        Some(role),
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
) -> String {
    let mut body = String::from("<h1>Clusters</h1>");
    if rows.is_empty() {
        body.push_str("<p class=\"empty\">No clusters yet.</p>");
        return layout("Clusters", "/clusters", &body, prefix, Some(role));
    }
    body.push_str(
        "<table><tr><th>Cluster</th><th>Turns</th><th>Actors</th><th>Surfaces</th>\
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
    body.push_str("</table>");
    body.push_str(&pager(&format!("{prefix}/clusters?"), page, total));
    layout("Clusters", "/clusters", &body, prefix, Some(role))
}

/// `{prefix}/clusters/{key}`: the cluster scope in the same shape.
pub fn cluster_detail_page(
    d: &ClusterDetail,
    thresholds: &HashMap<String, f64>,
    csrf: &str,
    role: Role,
    prefix: &str,
) -> String {
    let mut body = format!(
        "<h1>Cluster {}</h1><p class=\"sub\">{} turns · {} actors</p>",
        mono(&d.row.key),
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
    body.push_str("</dl><h2>Actors</h2>");
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
    body.push_str("<h2>Activity</h2>");
    body.push_str(&activity_block(&d.activity));
    body.push_str("<h2>Windside scores</h2>");
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
    body.push_str("<h2>Labels</h2>");
    body.push_str(&label_table(&d.labels));
    body.push_str("<h2>Pending proposal</h2>");
    match &d.proposal {
        Some(p) => body.push_str(&proposal_block(prefix, p)),
        None => body.push_str("<p class=\"empty\">No proposal for this cluster.</p>"),
    }
    if role == Role::Admin {
        body.push_str("<h2>Label verdicts</h2>");
        body.push_str(&label_form(
            prefix,
            "cluster",
            &d.row.key,
            d.window_end_ts,
            csrf,
        ));
        body.push_str("<h2>Draft a rule</h2>");
        body.push_str(&draft_form(prefix, "cluster", &d.row.key, csrf));
    }
    body.push_str("<h2>Turns</h2>");
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
        Some(role),
    )
}

/// `{prefix}/review`: the queue in the CLI's order, with `why_in_queue`.
pub fn review_list(
    rows: &[ReviewFull],
    thresholds: &HashMap<String, f64>,
    csrf: &str,
    role: Role,
    prefix: &str,
) -> String {
    let mut body = String::from("<h1>Review</h1><p class=\"sub\">Disagreements first, then uncertain, unlabelled proposals, and the rest, as the CLI orders them. Decided rows leave until new evidence re-queues them.</p>");
    if rows.is_empty() {
        body.push_str("<p class=\"empty\">Nothing scored yet: no queue.</p>");
        return layout("Review", "/review", &body, prefix, Some(role));
    }
    for r in rows {
        let subject = if r.row.scope == "cluster" {
            cluster_link(prefix, &r.row.scope_id)
        } else {
            actor_link(prefix, &r.row.scope_id)
        };
        let _ = write!(
            body,
            "<h2>{} <span class=\"mono\">{}</span></h2><p class=\"sub\">{}</p>",
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
    layout("Review", "/review", &body, prefix, Some(role))
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
) -> String {
    let mut body = String::from("<h1>Labels</h1><p class=\"sub\">Source: ");
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
        return layout("Labels", "/labels", &body, prefix, Some(role));
    }
    body.push_str(
        "<table><tr><th>Created</th><th>Subject</th><th>Scope</th><th>Source</th>\
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
    body.push_str("</table>");
    body.push_str(&pager(&base(source, label), page, total));
    layout("Labels", "/labels", &body, prefix, Some(role))
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
) -> String {
    let mut body = String::from("<h1>Rules</h1><p class=\"sub\">The flag is per app and reversible; retire stays as removal from the overrides file.</p>");
    if rules.is_empty() {
        body.push_str("<p class=\"empty\">No rules installed.</p>");
    } else {
        body.push_str(
            "<table><tr><th>Id</th><th>Version</th><th>State</th><th>Mode</th><th>Action</th>\
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
        body.push_str("</table>");
    }
    body.push_str("<h2>Drafts</h2>");
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
                "<h3>draft {} · {}</h3>\
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
    layout("Rules", "/rules", &body, prefix, Some(role))
}

/// `{prefix}/payloads`: the observed request patterns and what the
/// classify point made of them.
pub fn payloads_list(
    rows: &[PayloadRow],
    page: i64,
    total: i64,
    role: Role,
    prefix: &str,
) -> String {
    let mut body = String::from(
        "<h1>Payloads</h1><p class=\"sub\">One row per distinct request pattern; the class is the classify point's verdict.</p>",
    );
    if rows.is_empty() {
        body.push_str("<p class=\"empty\">No payload patterns observed.</p>");
    } else {
        body.push_str(
            "<table><tr><th>Pattern</th><th>Method</th><th>Turns</th>\
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
        body.push_str("</table>");
        body.push_str(&pager(&format!("{prefix}/payloads?"), page, total));
    }
    layout("Payloads", "/payloads", &body, prefix, Some(role))
}

/// `{prefix}/payloads/{hash}`: one pattern and its class.
pub fn payload_detail_page(r: &PayloadRow, role: Role, prefix: &str) -> String {
    let call = r
        .call_id
        .map(|c| format!("<a href=\"{prefix}/llm/{c}\">call {c}</a>"))
        .unwrap_or_else(|| "—".to_string());
    let mut body = format!(
        "<h1>Pattern {}</h1><p class=\"sub\">{} {}</p>",
        mono(&r.pattern_hash),
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
    layout("Payloads", "/payloads", &body, prefix, Some(role))
}

/// `{prefix}/model`: version, mode, thresholds, manifest, shadow report.
pub fn model_page(m: &ModelView, role: Role, prefix: &str) -> String {
    let mut body = String::from("<h1>Windside model</h1><dl class=\"kv\">");
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
    body.push_str("</dl><h2>Thresholds</h2>");
    if m.thresholds.is_empty() {
        body.push_str("<p class=\"empty\">No model loaded: no thresholds.</p>");
    } else {
        body.push_str("<table><tr><th>Surface</th><th>Threshold</th></tr>");
        let mut ts = m.thresholds.clone();
        ts.sort_by(|a, b| a.0.cmp(&b.0));
        for (s, t) in ts {
            let _ = write!(
                body,
                "<tr><td>{}</td><td class=\"num\">{t}</td></tr>",
                mono(&s)
            );
        }
        body.push_str("</table>");
    }
    body.push_str("<h2>Manifest metrics</h2>");
    match &m.manifest_pretty {
        Some(manifest) => {
            let _ = write!(body, "<pre>{}</pre>", esc(manifest));
        }
        None => body.push_str("<p class=\"empty\">No manifest on disk.</p>"),
    }
    body.push_str("<h2>Shadow report</h2>");
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
                body.push_str("<h2>Verified-credential FP by surface</h2><table><tr><th>Surface</th><th>Above</th><th>Rows</th><th>Threshold</th></tr>");
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
                body.push_str("</table>");
            }
            if !r.by_scope.is_empty() {
                body.push_str("<h2>Rows by scope</h2><table><tr><th>Scope</th><th>Feature rows</th><th>Scored</th><th>Skipped</th></tr>");
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
                body.push_str("</table>");
            }
            if !r.disagreements.is_empty() {
                body.push_str("<h2>Disagreements</h2><table><tr><th>Actor</th><th>Surface</th><th>Windside score</th><th></th><th>Rule</th></tr>");
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
                body.push_str("</table>");
                if r.disagreements_total > r.disagreements.len() {
                    let _ = write!(
                        body,
                        "<p class=\"sub\">{} more not shown.</p>",
                        r.disagreements_total - r.disagreements.len()
                    );
                }
            }
        }
    }
    layout("Windside model", "/model", &body, prefix, Some(role))
}

/// `{prefix}/features`: the feature names in order, with descriptions.
pub fn features_page(table: &[(String, String)], role: Role, prefix: &str) -> String {
    let mut body = String::from(
        "<h1>Features</h1><p class=\"sub\">v2 vector, in stored order, from the code's table.</p>",
    );
    body.push_str("<table><tr><th>#</th><th>Name</th><th>Description</th></tr>");
    for (i, (n, d)) in table.iter().enumerate() {
        let _ = write!(
            body,
            "<tr><td class=\"num\">{}</td><td>{}</td><td>{}</td></tr>",
            i,
            mono(n),
            esc(d),
        );
    }
    body.push_str("</table>");
    layout("Features", "/features", &body, prefix, Some(role))
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
