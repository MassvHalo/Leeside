//! The inspector's pages (docs/inspector.md): server-rendered HTML,
//! one inlined stylesheet, no JavaScript beyond `<details>` toggles
//! and a copy button. Everything from the store is HTML-escaped on
//! the way out: turns carry attacker text.
//!
//! Tokens are `docs/console.md` section 5, dark first. Fonts fall back
//! to the system stacks; the box carries no webfonts.

use super::queries::{Call, CallRow, Job, LabelRef, Outcome};
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
fn nav(active: &str) -> String {
    let mut out = String::from("<nav>");
    for (path, name) in [("/ui/llm", "LLM calls"), ("/ui/jobs", "Jobs")] {
        let on = if active == path { " class=\"on\"" } else { "" };
        let _ = write!(out, "<a href=\"{path}\"{on}>{name}</a>");
    }
    out.push_str("</nav>");
    out
}

fn layout(title: &str, active: &str, body: &str) -> String {
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{} · leeside inspector</title><style>{STYLE}</style></head>\
         <body><header class=\"top\"><span class=\"brand\">\
         <a href=\"/ui/llm\">leeside inspector</a></span>{}</header>\
         <main>{body}</main>{COPY_SCRIPT}</body></html>",
        esc(title),
        nav(active),
    )
}

pub fn login_page(next: &str, error: Option<&str>) -> String {
    let mut body = String::from("<h1>Log in</h1><p class=\"sub\">The operator token.</p>");
    if let Some(e) = error {
        let _ = write!(body, "<p class=\"error\">{}</p>", esc(e));
    }
    let _ = write!(
        body,
        "<form class=\"login\" method=\"post\" action=\"/ui/login\">\
         <input type=\"hidden\" name=\"next\" value=\"{}\">\
         <label>Operator token<br><input type=\"password\" name=\"token\" autofocus></label><br>\
         <input class=\"btn\" type=\"submit\" value=\"Log in\"></form>",
        esc(next),
    );
    layout("Log in", "", &body)
}

pub fn error_page(status: u16, title: &str, detail: &str) -> String {
    layout(
        title,
        "",
        &format!(
            "<h1>{status} · {}</h1><p>{}</p><p><a href=\"/ui/llm\">Back to LLM calls</a></p>",
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

/// `/ui/llm`: every call, newest first.
pub fn llm_list(calls: &[CallRow], page: i64, total: i64) -> String {
    let mut body = String::from("<h1>LLM calls</h1>");
    if calls.is_empty() {
        body.push_str("<p class=\"empty\">No calls logged yet.</p>");
        return layout("LLM calls", "/ui/llm", &body);
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
             <td><a href=\"/ui/llm/{}\">open</a></td></tr>",
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
    body.push_str(&pager("/ui/llm?", page, total));
    layout("LLM calls", "/ui/llm", &body)
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

/// `/ui/llm/{id}`: one exchange in three columns, verbatim.
pub fn llm_detail(c: &Call, csrf: &str) -> String {
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
            "<dt>Job</dt><dd><a href=\"/ui/jobs#{}\">job {}</a> ({}) {}</dd>",
            j.id,
            j.id,
            esc(&j.point),
            status_chip(&j.status),
        );
    }
    if let Some(r) = &c.resend_parent {
        let _ = write!(
            head,
            "<dt>Re-send of</dt><dd><a href=\"/ui/llm/{r}\">call {r}</a></dd>"
        );
    }
    if !c.resend_children.is_empty() {
        head.push_str("<dt>Re-sent by</dt><dd>");
        for (i, r) in c.resend_children.iter().enumerate() {
            if i > 0 {
                head.push_str(" · ");
            }
            let _ = write!(head, "<a href=\"/ui/llm/{r}\">call {r}</a>");
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
        None => interp.push_str("<p class=\"empty\">No operator decision on that label yet.</p>"),
    }
    if !c.siblings.is_empty() {
        interp.push_str("<h2>Retries on this subject</h2><table>");
        for s in &c.siblings {
            let _ = write!(
                interp,
                "<tr><td><a href=\"/ui/llm/{}\">call {}</a>{}</td>\
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

    let mut tail = format!(
        "<section><h2>Re-send</h2>\
         <p class=\"sub\">Admin only. Same point, same subject, fresh budget; \
         the new call links back to this one.</p>\
         <form method=\"post\" action=\"/ui/llm/{}/resend\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{}\">\
         <button class=\"btn btn-warn\" type=\"submit\">Re-send this call</button>\
         </form></section>",
        c.id, csrf,
    );
    if c.siblings.iter().any(|s| !s.is_self && s.id > c.id) {
        tail.push_str("<p class=\"empty\">Note: a newer attempt exists on this subject.</p>");
    }

    layout(
        &format!("Call {}", c.id),
        "/ui/llm",
        &format!("{head}<div class=\"cols\">{sent}{received}{interp}</div>{tail}"),
    )
}

/// `/ui/jobs`: the queue, newest first, with retry and cancel forms.
pub fn jobs_list(jobs: &[Job], status: Option<&str>, page: i64, total: i64, csrf: &str) -> String {
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
            let _ = write!(body, "<a href=\"/ui/jobs?{q}\">{name}</a>");
        }
    }
    body.push_str("</p>");
    if jobs.is_empty() {
        body.push_str("<p class=\"empty\">No jobs in this state.</p>");
        return layout("Jobs", "/ui/jobs", &body);
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
                |id| format!("<a href=\"/ui/llm/{id}\">call {id}</a>"),
            ),
        );
        if j.status == "failed" {
            let _ = write!(
                body,
                "<form class=\"inline\" method=\"post\" action=\"/ui/jobs/{}/retry\">\
                 <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                 <button class=\"btn\" type=\"submit\">retry</button></form>",
                j.id,
            );
        }
        if j.status == "queued" {
            let _ = write!(
                body,
                "<form class=\"inline\" method=\"post\" action=\"/ui/jobs/{}/cancel\">\
                 <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                 <button class=\"btn btn-warn\" type=\"submit\">cancel</button></form>",
                j.id,
            );
        }
        body.push_str("</td></tr>");
    }
    body.push_str("</table>");
    let base = match status {
        Some(s) => format!("/ui/jobs?status={s}&"),
        None => "/ui/jobs?".to_string(),
    };
    body.push_str(&pager(&base, page, total));
    layout("Jobs", "/ui/jobs", &body)
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
