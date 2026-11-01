// Benign page walk (docs/windside.md section 4): real browser, page views
// with asset loads, think time, back navigation, a form login and a
// logged-in session. Prints a one-line JSON summary; exits nonzero when
// any navigation fails.
import { chromium, firefox, webkit } from 'playwright';

const args = Object.fromEntries(
    process.argv.slice(2).reduce((acc, a, i, all) => {
        if (a.startsWith('--')) acc.push([a.slice(2), all[i + 1]]);
        return acc;
    }, []),
);
const browserName = args.browser || 'chromium';
const base = (args.base || 'http://127.0.0.1:8766').replace(/\/$/, '');
const views = parseInt(args.views || '100', 10);
const sentFile = args['sent-file'] || null;

const engines = { chromium, firefox, webkit };
const engine = engines[browserName];
if (!engine) {
    console.error(`unknown browser: ${browserName}`);
    process.exit(1);
}

const pages = ['/', '/about', '/venues/1', '/venues/2', '/venues/3', '/venues/4', '/venues/5', '/venues/6'];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Think time, 2 to 20 s: usually a few seconds, sometimes a long pause.
const think = () =>
    Math.random() < 0.1
        ? 10000 + Math.random() * 10000
        : 2000 + Math.random() * 3000;

const browser = await engine.launch({ headless: true });
const context = await browser.newContext();
const page = await context.newPage();
let assets = 0;
let documents = 0;
page.on('response', (r) => {
    if (/\.css(\?|$)/.test(r.url()) || /\.js(\?|$)/.test(r.url())) assets++;
    if (r.request().resourceType() === 'document') documents++;
});

let done = 0;
let loggedIn = false;
for (let i = 0; i < views; i++) {
    const res = await page.goto(base + pages[i % pages.length], { waitUntil: 'load' });
    if (!res || res.status() >= 500) throw new Error(`navigation ${i} failed: ${res && res.status()}`);
    done++;
    if (i === 9) {
        // The portal login form, with the demo OTP: the rest of the walk
        // runs in a logged-in session.
        await page.goto(base + '/', { waitUntil: 'load' });
        await page.fill('#phone', '0661111111');
        await page.fill('#otp', '123456');
        await page.click('#login-form button[type=submit]');
        await page.waitForFunction(
            () => document.getElementById('login-result').textContent.startsWith('200'),
            null,
            { timeout: 10000 },
        );
        loggedIn = true;
    }
    if (i > 0 && i % 8 === 0) await page.goBack({ waitUntil: 'load' }).catch(() => {});
    await sleep(think());
}

await browser.close();
// Requests that hit the network and became turns: document loads plus the
// login POST (assets serve statically and never reach PHP).
const requests = documents + (loggedIn ? 1 : 0);
if (sentFile) {
    const { writeFileSync } = await import('node:fs');
    writeFileSync(sentFile, String(requests) + '\n');
}
console.log(JSON.stringify({ browser: browserName, views: done, assets, loggedIn, requests }));
