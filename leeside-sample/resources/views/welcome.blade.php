<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Leeside Sample Portal</title>
    <style>
        :root {
            --ink: #1e2a24;
            --muted: #5a6a63;
            --line: #dfe5e1;
            --paper: #f2f4f2;
            --card: #ffffff;
            --accent: #0f766e;
            --accent-dark: #115e59;
            --danger: #b3261e;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            background: var(--paper);
            color: var(--ink);
            font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
            line-height: 1.5;
        }
        .wrap { max-width: 880px; margin: 0 auto; padding: 24px 20px 40px; }
        header.top {
            display: flex;
            align-items: baseline;
            justify-content: space-between;
            gap: 12px;
            padding: 18px 0;
            border-bottom: 2px solid var(--ink);
            margin-bottom: 24px;
        }
        header.top h1 { font-size: 1.35rem; margin: 0; letter-spacing: -0.01em; }
        header.top h1 span { color: var(--accent-dark); }
        .badge {
            font-size: 0.75rem;
            color: var(--muted);
            border: 1px solid var(--line);
            background: var(--card);
            border-radius: 999px;
            padding: 2px 10px;
            white-space: nowrap;
        }
        .grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        @media (max-width: 640px) { .grid { grid-template-columns: 1fr; } }
        section.card {
            background: var(--card);
            border: 1px solid var(--line);
            border-radius: 10px;
            padding: 20px 22px;
        }
        section.card h2 { font-size: 1rem; margin: 0 0 4px; }
        section.card p.sub { font-size: 0.85rem; color: var(--muted); margin: 0 0 14px; }
        ul.venues { list-style: none; margin: 0; padding: 0; }
        ul.venues li {
            display: flex;
            justify-content: space-between;
            gap: 10px;
            padding: 8px 0;
            border-top: 1px solid var(--line);
            font-size: 0.92rem;
        }
        ul.venues li:first-child { border-top: 0; }
        ul.venues a { color: var(--accent-dark); text-decoration: none; font-weight: 600; }
        ul.venues a:hover { text-decoration: underline; }
        ul.venues .city { color: var(--muted); font-size: 0.85rem; }
        label { display: block; font-size: 0.82rem; font-weight: 600; margin: 10px 0 4px; }
        input {
            width: 100%;
            font: inherit;
            font-size: 0.95rem;
            padding: 8px 10px;
            border: 1px solid var(--line);
            border-radius: 6px;
            background: var(--paper);
            color: var(--ink);
        }
        input:focus { outline: 2px solid var(--accent); outline-offset: 1px; border-color: var(--accent); }
        button {
            margin-top: 14px;
            font: inherit;
            font-weight: 600;
            font-size: 0.92rem;
            color: #fff;
            background: var(--accent-dark);
            border: 0;
            border-radius: 6px;
            padding: 9px 16px;
            cursor: pointer;
        }
        button:hover { background: var(--accent); }
        #login-result {
            margin-top: 12px;
            font-size: 0.85rem;
            font-family: ui-monospace, monospace;
            min-height: 1.4em;
            word-break: break-word;
        }
        #login-result.ok { color: var(--accent-dark); }
        #login-result.err { color: var(--danger); }
        .hint { font-size: 0.8rem; color: var(--muted); margin-top: 10px; }
        footer {
            margin-top: 28px;
            padding-top: 14px;
            border-top: 1px solid var(--line);
            font-size: 0.82rem;
            color: var(--muted);
            display: flex;
            justify-content: space-between;
            gap: 12px;
            flex-wrap: wrap;
        }
        footer a { color: var(--accent-dark); }
    </style>
</head>
<body>
<div class="wrap">
    <header class="top">
        <h1>Leeside <span>Sample Portal</span></h1>
        <span class="badge">demo harness · nothing here is production code</span>
    </header>

    <div class="grid">
        <section class="card">
            <h2>Demo venues</h2>
            <p class="sub">Route-model binding; unknown ids 404.</p>
            <ul class="venues">
                @foreach ($venues as $venue)
                    <li>
                        <a href="{{ route('venues.show', $venue) }}">{{ $venue->name }}</a>
                        <span class="city">{{ $venue->city }}</span>
                    </li>
                @endforeach
            </ul>
        </section>

        <section class="card">
            <h2>Portal sign-in</h2>
            <p class="sub">Phone + OTP, validated by <code>portal.login</code>.</p>
            <form id="login-form" autocomplete="off">
                <label for="phone">Phone (10 digits)</label>
                <input id="phone" name="phone" inputmode="numeric" maxlength="10" required>
                <label for="otp">One-time passcode (6 digits)</label>
                <input id="otp" name="otp" inputmode="numeric" maxlength="6" required>
                <button type="submit">Sign in</button>
            </form>
            <p id="login-result" aria-live="polite"></p>
            <p class="hint">Demo OTP is <code>123456</code>; anything else 401s. Malformed input 422s.</p>
        </section>
    </div>

    <footer>
        <span>Every request emits a PII-free turn event to the Leeside tap.</span>
        <span><a href="{{ route('api.venues.index') }}">/api/venues</a> · Laravel v{{ app()->version() }}</span>
    </footer>
</div>

<script>
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const out = document.getElementById('login-result');
    out.className = '';
    out.textContent = '…';
    try {
        const res = await fetch('{{ route('portal.login') }}', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                phone: document.getElementById('phone').value,
                otp: document.getElementById('otp').value,
            }),
        });
        out.textContent = res.status + ' ' + (await res.text());
        out.className = res.ok ? 'ok' : 'err';
    } catch {
        out.textContent = 'request failed';
        out.className = 'err';
    }
});
</script>
</body>
</html>
