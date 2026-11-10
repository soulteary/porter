// Isolated Chromium acceptance test. Provider navigation is intercepted locally;
// no real OAuth application or external authentication request is used.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const [origin, chrome] = process.argv.slice(2);
const profile = await mkdtemp(join(tmpdir(), 'porter-browser-'));
const child = spawn(chrome, [
  '--headless=new', '--no-sandbox', '--no-first-run', '--disable-background-networking',
  '--disable-default-apps', '--ignore-certificate-errors', '--remote-debugging-port=0',
  `--user-data-dir=${profile}`, 'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe'] });
let chromeLog = '';
child.stderr.on('data', chunk => { chromeLog = (chromeLog + chunk).slice(-4000); });
let chromeExit;
child.on('exit', code => { chromeExit = code; });
child.on('error', error => { chromeLog += error.message; chromeExit = -1; });
let socket;
async function waitFor(fn, label, timeout = 10000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const result = await fn();
    if (result) return result;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error(`Timed out: ${label}`);
}
try {
  const port = await waitFor(async () => {
    if (chromeExit !== undefined) throw new Error(`Chromium exited ${chromeExit}: ${chromeLog}`);
    try { return (await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]; }
    catch { return false; }
  }, 'Chromium debugging port', 30000);
  const target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: 'PUT' })).json();
  socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
  let next = 0, interceptionError;
  const pending = new Map(), intercepted = [];
  function call(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = ++next;
      const timer = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 5000);
      pending.set(id, { resolve, reject, timer });
      socket.send(JSON.stringify({ id, method, params }));
    });
  }
  socket.onmessage = event => {
    const message = JSON.parse(event.data);
    if (message.id) {
      const entry = pending.get(message.id);
      if (!entry) return;
      pending.delete(message.id); clearTimeout(entry.timer);
      if (message.error) entry.reject(new Error(JSON.stringify(message.error)));
      else entry.resolve(message.result);
    } else if (message.method === 'Fetch.requestPaused') {
      (async () => {
        const { requestId, request } = message.params;
        const url = new URL(request.url);
        const provider = ({ 'github.com': 'github', 'accounts.google.com': 'google',
          'open.weixin.qq.com': 'wechat', 'graph.qq.com': 'qq' })[url.hostname];
        assert.ok(provider, 'Unexpected provider navigation');
        assert.ok(url.searchParams.get('state'), 'Missing browser transaction state');
        intercepted.push(provider);
        const callback = `${origin}/callback/${provider}?state=${encodeURIComponent(url.searchParams.get('state'))}&code=browser-fixture`;
        await call('Fetch.fulfillRequest', { requestId, responseCode: 200,
          responseHeaders: [{ name: 'Content-Type', value: 'text/html' }, { name: 'Referrer-Policy', value: 'no-referrer' }],
          body: Buffer.from(`<meta http-equiv="refresh" content="0;url=${callback.replaceAll('&', '&amp;')}">`).toString('base64') });
      })().catch(error => { interceptionError = error; });
    }
  };
  await call('Page.enable'); await call('Runtime.enable'); await call('Network.enable');
  await call('Fetch.enable', { patterns: ['https://github.com/login/oauth/authorize*', 'https://accounts.google.com/o/oauth2/v2/auth*',
    'https://open.weixin.qq.com/connect/qrconnect*', 'https://graph.qq.com/oauth2.0/authorize*']
    .map(urlPattern => ({ urlPattern, requestStage: 'Request' })) });
  function navigationRace(error) {
    return /"code":-32000/.test(error.message) &&
      /Inspected target navigated or closed|Execution context was destroyed|Cannot find context with specified id/.test(error.message);
  }
  async function evaluate(expression) {
    if (interceptionError) throw interceptionError;
    try {
      const result = await call('Runtime.evaluate', { expression, returnByValue: true, userGesture: true });
      if (result.exceptionDetails) throw new Error('Browser expression failed');
      return result.result?.value;
    } catch (error) {
      // A navigation can destroy the old document before CDP answers. Polling
      // reads the next document; form submission is never repeated. Its caller
      // still requires the expected destination and session/revocation result.
      if (navigationRace(error)) return false;
      throw error;
    }
  }
  async function loginPage() {
    await call('Page.navigate', { url: `${origin}/login` });
    await waitFor(() => evaluate(`location.pathname === '/login' && !!document.querySelector('form[action="/logout"]')`), 'login page');
  }
  for (const provider of ['github', 'google', 'wechat', 'qq']) {
    await loginPage();
    // Submit the actual HTML form. Do not synthesize Origin or follow redirects
    // with an HTTP client: both miss browser Referrer-Policy/CSP enforcement.
    await evaluate(`document.querySelector('form[action="/login/${provider}"]').requestSubmit(); true`);
    await waitFor(() => evaluate(`location.pathname === '/app' && document.body.textContent === 'Signed in: ${provider}'`), `${provider} callback`);
    const cookies = (await call('Network.getCookies', { urls: [origin] })).cookies;
    const session = cookies.find(cookie => cookie.name === '__Host-porter_session');
    assert.ok(session?.secure && session.httpOnly && session.sameSite === 'Lax', 'Missing secure session');
    assert.equal(session.domain, new URL(origin).hostname, 'Session must be host-only');
    await loginPage();
    await evaluate(`document.querySelector('form[action="/logout"]').requestSubmit(); true`);
    await waitFor(async () => {
      const cookies = (await call('Network.getCookies', { urls: [origin] })).cookies;
      return !cookies.some(cookie => cookie.name === '__Host-porter_session');
    }, `${provider} logout`);
    await call('Page.navigate', { url: `${origin}/app` });
    await waitFor(() => evaluate(`document.body.textContent === 'Login required'`), 'session revoked');
  }
  assert.deepEqual(intercepted, ['github', 'google', 'wechat', 'qq']);
  console.log('PASS: Chromium HTML forms, four provider navigations, secure cookies, callbacks and logout');
} finally {
  socket?.close();
  if (chromeExit === undefined) {
    const closed = new Promise(resolve => child.once('close', resolve));
    child.kill('SIGKILL');
    await closed;
  }
  await rm(profile, { recursive: true, force: true });
}
