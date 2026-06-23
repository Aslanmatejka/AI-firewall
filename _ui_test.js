const puppeteer = require('puppeteer');
(async () => {
  const browser = await puppeteer.launch({headless:'new'});
  const page = await browser.newPage();
  const logs = [];
  page.on('console', m => logs.push('console:' + m.type() + ':' + m.text()));
  page.on('pageerror', e => logs.push('pageerror:' + e.message));
  await page.goto('http://127.0.0.1:9470/', {waitUntil:'networkidle2', timeout:30000});
  await page.waitForFunction(() => typeof navigate === 'function' && typeof act === 'function', {timeout:10000});
  await page.click('[data-page="settings"]');
  await page.waitForFunction(() => document.getElementById('page-settings')?.classList.contains('active'), {timeout:5000});
  await page.evaluate(() => act('/api/restore-defaults'));
  await new Promise(r => setTimeout(r, 3000));
  const toast = await page.evaluate(() => document.getElementById('toast')?.textContent || '');
  const active = await page.evaluate(() => document.querySelector('.page.active')?.id || '');
  console.log(JSON.stringify({active, toast, logs: logs.slice(-15)}, null, 2));
  await browser.close();
})().catch(e => { console.error('FAIL', e.message); process.exit(1); });
