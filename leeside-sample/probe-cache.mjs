import { chromium } from 'playwright';
const browser = await chromium.launch({ headless: true });
const page = await (await browser.newContext()).newPage();
page.on('request', (r) => { if (r.resourceType() === 'document') console.log('REQ', r.url()); });
page.on('response', (r) => { if (r.request().resourceType() === 'document') console.log('RES', r.url(), r.status()); });
await page.goto('http://127.0.0.1:8766/', { waitUntil: 'load' });
await page.goto('http://127.0.0.1:8766/about', { waitUntil: 'load' });
await page.goBack({ waitUntil: 'load' }).catch(() => {});
await browser.close();
