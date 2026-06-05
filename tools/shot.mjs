// 用 CDP(无需安装依赖)截图:可在页面里执行 JS 再截,用于捕捉后台/交互态。
// 用法: node tools/shot.mjs <out.png> "<在页面执行的JS>" [额外等待ms]
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';

const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const URL = 'http://127.0.0.1:8000/';
const out = process.argv[2] || 'shot.png';
const evalJs = process.argv[3] || '';
const extraWait = Number(process.argv[4] || 1500);
const PORT = 9333;

const sleep = ms => new Promise(r => setTimeout(r, ms));

const chrome = spawn(CHROME, [
  '--headless=new', '--disable-gpu', '--hide-scrollbars',
  `--remote-debugging-port=${PORT}`, '--window-size=1440,1000',
  '--user-data-dir=' + process.env.TEMP + '\\cdp-shot', 'about:blank'
]);

async function cdp(ws, method, params = {}, id) {
  return new Promise((resolve) => {
    const handler = (ev) => {
      const m = JSON.parse(ev.data);
      if (m.id === id) { ws.removeEventListener('message', handler); resolve(m.result); }
    };
    ws.addEventListener('message', handler);
    ws.send(JSON.stringify({ id, method, params }));
  });
}

try {
  await sleep(1800);
  // 找到一个可用 page target
  let list;
  for (let i = 0; i < 20; i++) {
    try { list = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json(); if (list.some(t => t.type === 'page')) break; } catch {}
    await sleep(300);
  }
  const page = list.find(t => t.type === 'page');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise(r => ws.addEventListener('open', r, { once: true }));
  let id = 1;
  await cdp(ws, 'Page.enable', {}, id++);
  await cdp(ws, 'Runtime.enable', {}, id++);
  await cdp(ws, 'Page.navigate', { url: URL }, id++);
  await sleep(3000); // 等 init() 拉数据渲染
  if (evalJs) { await cdp(ws, 'Runtime.evaluate', { expression: evalJs }, id++); await sleep(extraWait); }
  const { data } = await cdp(ws, 'Page.captureScreenshot', { format: 'png' }, id++);
  writeFileSync(out, Buffer.from(data, 'base64'));
  console.log('saved', out);
  ws.close();
} catch (e) {
  console.error('ERR', e.message);
} finally {
  chrome.kill();
}
