#!/usr/bin/env node
'use strict';

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');
const AdmZip = require('adm-zip');
const { spawn, execFileSync } = require('child_process');

/* ============================== 配置 ============================== */
const env = (k, d = '') => String(process.env[k] ?? d).trim();
const bool = (v) => ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase());
const num = (v, d) => (Number.isInteger(parseInt(v, 10)) ? parseInt(v, 10) : d);

const C = {
  UPLOAD_URL: env('UPLOAD_URL'),
  PROJECT_URL: env('PROJECT_URL'),
  AUTO_ACCESS: bool(env('AUTO_ACCESS', 'false')),
  FILE_PATH: env('FILE_PATH', '.npm'),
  SUB_PATH: env('SUB_PATH'),
  PORT: num(env('SERVER_PORT') || env('PORT'), 3000),
  UUID: env('UUID'),
  NEZHA_SERVER: env('NEZHA_SERVER'),
  NEZHA_PORT: env('NEZHA_PORT'),
  NEZHA_KEY: env('NEZHA_KEY'),
  NEZHA_ALLOW_EXEC: bool(env('NEZHA_ALLOW_EXEC', 'false')),
  NEZHA_INSECURE_TLS: bool(env('NEZHA_INSECURE_TLS', 'false')),
  ARGO_DOMAIN: env('ARGO_DOMAIN'),
  ARGO_AUTH: env('ARGO_AUTH'),
  ARGO_PORT: num(env('ARGO_PORT'), 8001),
  S5_PORT: env('S5_PORT'),
  HY2_PORT: env('HY2_PORT'),
  REALITY_PORT: env('REALITY_PORT'),
  CFIP: env('CFIP', '104.17.142.146'),
  CFPORT: num(env('CFPORT'), 443),
  NAME: env('NAME'),
  CHAT_ID: env('CHAT_ID'),
  BOT_TOKEN: env('BOT_TOKEN'),
  SHOW_LOG: !['false', 'disable', 'no'].includes(env('SHOW_LOG', 'true').toLowerCase()),
  KEEP_FILES: bool(env('KEEP_FILES', 'false')),     // true: 不在 90 秒后删除运行文件
  CHILD_LOG: bool(env('CHILD_LOG', 'false')),       // true: 输出 xray/cloudflared 日志，排错用

  // 官方 Release 版本，latest 或固定版本号（如 v25.10.15 / 2025.9.1）
  XRAY_VERSION: env('XRAY_VERSION', 'latest'),
  CLOUDFLARED_VERSION: env('CLOUDFLARED_VERSION', 'latest'),
  NEZHA_VERSION: env('NEZHA_VERSION'),              // 留空: v1 用 latest，v0 用 v0.20.5
  // 手动指定 SHA256 时优先于自动获取的校验值
  SHA256_WEB: env('SHA256_WEB').toLowerCase(),
  SHA256_BOT: env('SHA256_BOT').toLowerCase(),
  SHA256_NEZHA: env('SHA256_NEZHA').toLowerCase(),
  STRICT_VERIFY: bool(env('STRICT_VERIFY', 'false')), // true: 拿不到校验值就拒绝运行
};

const log = (...a) => C.SHOW_LOG && console.log(...a);
const err = (...a) => C.SHOW_LOG && console.error(...a);
const always = (msg) => process.stdout.write(msg + '\n');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const validPort = (p) => { const n = parseInt(p, 10); return Number.isInteger(n) && n >= 1 && n <= 65535; };

/* ============================== 路径与状态 ============================== */
fs.mkdirSync(C.FILE_PATH, { recursive: true });
const P = (f) => path.resolve(C.FILE_PATH, f);
const rnd = () => crypto.randomBytes(4).toString('hex');

const paths = {
  nezha: P(rnd()), web: P(rnd()), bot: P(rnd()),
  sub: P('sub.txt'), list: P('list.txt'), bootLog: P('boot.log'),
  config: P('config.json'), nezhaCfg: P('config.yaml'),
  cert: P('cert.pem'), key: P('private.key'), state: P('state.json'),
  tunnelJson: P('tunnel.json'), tunnelYml: P('tunnel.yml'),
};
const PERSIST = new Set(['state.json']);

function writeSecret(file, data) {
  fs.writeFileSync(file, data, { mode: 0o600 });
}

function loadState() {
  let s = {};
  try { s = JSON.parse(fs.readFileSync(paths.state, 'utf8')); } catch { /* 首次运行 */ }
  let dirty = false;
  if (!s.uuid) { s.uuid = crypto.randomUUID(); dirty = true; }
  if (!s.reality) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
    s.reality = {
      privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('base64url'),
      publicKey: publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64url'),
      shortId: crypto.randomBytes(8).toString('hex'),
    };
    dirty = true;
  }
  if (dirty) writeSecret(paths.state, JSON.stringify(s, null, 2));
  return s;
}

function cleanupOldFiles() {
  for (const f of fs.readdirSync(C.FILE_PATH)) {
    if (PERSIST.has(f)) continue;
    try {
      const fp = path.join(C.FILE_PATH, f);
      if (fs.statSync(fp).isFile()) fs.unlinkSync(fp);
    } catch { /* ignore */ }
  }
}

const state = (() => { cleanupOldFiles(); return loadState(); })();
const UUID = C.UUID || state.uuid;
const SUB_PATH = C.SUB_PATH || crypto.createHash('sha256').update(UUID + ':sub').digest('hex').slice(0, 16);
if (!C.SUB_PATH) always(`SUB_PATH 未设置，已自动生成订阅路径: /${SUB_PATH}`);

/* ============================== 子进程管理 ============================== */
const children = [];
function launch(bin, args) {
  const child = spawn(bin, args, { stdio: C.CHILD_LOG ? ['ignore', 'inherit', 'inherit'] : 'ignore' });
  child.on('error', (e) => err(`spawn ${path.basename(bin)} failed:`, e.message));
  child.on('exit', (code, sig) => { if (!child.expected) err(`${path.basename(bin)} exited (${code ?? sig})`); });
  children.push(child);
  return child;
}
function shutdown() {
  for (const c of children) { c.expected = true; try { c.kill('SIGTERM'); } catch { /* ignore */ } }
  setTimeout(() => process.exit(0), 300).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

/* ============================== TLS 证书（Hysteria2） ============================== */
function ensureTlsCertificates() {
  if (fs.existsSync(paths.cert) && fs.existsSync(paths.key)) return true;
  try {
    execFileSync('openssl', ['ecparam', '-genkey', '-name', 'prime256v1', '-out', paths.key], { stdio: 'ignore' });
    execFileSync('openssl', ['req', '-new', '-x509', '-days', '3650', '-key', paths.key, '-out', paths.cert, '-subj', '/CN=bing.com'], { stdio: 'ignore' });
    fs.chmodSync(paths.key, 0o600);
    return true;
  } catch {
    err('openssl 不可用，已跳过 Hysteria2。请安装 openssl 后重试。');
    return false;
  }
}

function certFingerprint() {
  try {
    const pem = fs.readFileSync(paths.cert, 'utf8');
    const m = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/);
    if (!m) return '';
    const der = Buffer.from(m[1].replace(/\s/g, ''), 'base64');
    return crypto.createHash('sha256').update(der).digest('hex').match(/../g).join(':').toUpperCase();
  } catch { return ''; }
}

/* ============================== Xray 配置 ============================== */
let hy2Enabled = false;

function generateConfig() {
  const A = C.ARGO_PORT;
  const ws = (tag, port, protocol, settings, p) => ({
    tag, port, listen: '127.0.0.1', protocol, settings,
    streamSettings: { network: 'ws', security: 'none', wsSettings: { path: p } },
    sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], metadataOnly: false },
  });

  const config = {
    log: C.CHILD_LOG
      ? { loglevel: 'warning' }
      : { access: 'none', error: 'none', loglevel: 'none' },
    inbounds: [
      {
        tag: 'vless-fallback-in', port: A, listen: '::', protocol: 'vless',
        settings: {
          clients: [{ id: UUID, flow: 'xtls-rprx-vision' }], decryption: 'none',
          fallbacks: [{ dest: 3001 }, { path: '/vless-argo', dest: 3002 }, { path: '/vmess-argo', dest: 3003 }, { path: '/trojan-argo', dest: 3004 }],
        },
        streamSettings: { network: 'tcp' },
      },
      {
        tag: 'vless-tcp-in', port: 3001, listen: '127.0.0.1', protocol: 'vless',
        settings: { clients: [{ id: UUID }], decryption: 'none' },
        streamSettings: { network: 'tcp', security: 'none' },
      },
      ws('vless-ws-in', 3002, 'vless', { clients: [{ id: UUID, level: 0 }], decryption: 'none' }, '/vless-argo'),
      ws('vmess-ws-in', 3003, 'vmess', { clients: [{ id: UUID, alterId: 0 }] }, '/vmess-argo'),
      ws('trojan-ws-in', 3004, 'trojan', { clients: [{ password: UUID }] }, '/trojan-argo'),
    ],
    dns: { servers: ['https+local://8.8.8.8/dns-query'] },
    outbounds: [{ protocol: 'freedom', tag: 'direct' }, { protocol: 'blackhole', tag: 'block' }],
  };

  if (validPort(C.REALITY_PORT)) {
    config.inbounds.push({
      tag: 'vless-in', listen: '::', port: +C.REALITY_PORT, protocol: 'vless',
      settings: { clients: [{ id: UUID, flow: 'xtls-rprx-vision' }], decryption: 'none' },
      streamSettings: {
        network: 'raw', security: 'reality',
        realitySettings: {
          show: false, dest: 'www.iij.ad.jp:443', xver: 0, serverNames: ['www.iij.ad.jp'],
          privateKey: state.reality.privateKey, shortIds: [state.reality.shortId],
        },
      },
    });
  }

  if (validPort(C.HY2_PORT) && (hy2Enabled = ensureTlsCertificates())) {
    config.inbounds.push({
      tag: 'hysteria-in', listen: '::', port: +C.HY2_PORT, protocol: 'hysteria',
      settings: { version: 2, clients: [{ auth: UUID }] },
      streamSettings: {
        network: 'hysteria',
        hysteriaSettings: { version: 2, masquerade: { type: 'proxy', url: 'https://bing.com' } },
        security: 'tls',
        tlsSettings: { alpn: ['h3'], certificates: [{ certificateFile: paths.cert, keyFile: paths.key }] },
      },
    });
  }

  if (validPort(C.S5_PORT)) {
    config.inbounds.push({
      tag: 's5-in', listen: '::', port: +C.S5_PORT, protocol: 'socks',
      settings: { auth: 'password', accounts: [{ user: UUID.slice(0, 8), pass: UUID.slice(-12) }], udp: true },
    });
  }

  writeSecret(paths.config, JSON.stringify(config, null, 2));
}

/* ============================== 官方二进制下载 ============================== */
const isArm = ['arm', 'arm64', 'aarch64'].includes(os.arch());
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

const releaseUrl = (repo, version, asset) => (version === 'latest'
  ? `https://github.com/${repo}/releases/latest/download/${asset}`
  : `https://github.com/${repo}/releases/download/${version}/${asset}`);

async function fetchBuf(url) {
  const r = await axios.get(url, { responseType: 'arraybuffer', timeout: 120000, maxContentLength: 200 * 1024 * 1024 });
  return Buffer.from(r.data);
}
async function fetchText(url, opts = {}) {
  const r = await axios.get(url, { responseType: 'text', timeout: 15000, ...opts });
  return String(r.data);
}
async function retry(fn, times = 3) {
  let last;
  for (let i = 1; i <= times; i++) {
    try { return await fn(); } catch (e) { last = e; err(`尝试 ${i}/${times} 失败: ${e.message}`); await sleep(1500 * i); }
  }
  throw last;
}

// 各组件的下载描述：url、校验值获取方式、zip 内要提取的文件名
function binarySpecs() {
  const specs = [];

  const xrayAsset = `Xray-linux-${isArm ? 'arm64-v8a' : '64'}.zip`;
  const xrayUrl = releaseUrl('XTLS/Xray-core', C.XRAY_VERSION, xrayAsset);
  specs.push({
    name: 'xray', file: paths.web, url: xrayUrl, zipEntry: 'xray', manualSha: C.SHA256_WEB,
    fetchHash: async () => {
      const t = await fetchText(`${xrayUrl}.dgst`);
      const m = t.match(/SHA2-256=\s*([0-9a-f]{64})/i);
      return m ? m[1].toLowerCase() : '';
    },
  });

  const cfAsset = `cloudflared-linux-${isArm ? 'arm64' : 'amd64'}`;
  const cfUrl = releaseUrl('cloudflare/cloudflared', C.CLOUDFLARED_VERSION, cfAsset);
  specs.push({
    name: 'cloudflared', file: paths.bot, url: cfUrl, manualSha: C.SHA256_BOT,
    fetchHash: async () => {
      const api = C.CLOUDFLARED_VERSION === 'latest'
        ? 'https://api.github.com/repos/cloudflare/cloudflared/releases/latest'
        : `https://api.github.com/repos/cloudflare/cloudflared/releases/tags/${C.CLOUDFLARED_VERSION}`;
      const r = await axios.get(api, { timeout: 15000, headers: { Accept: 'application/vnd.github+json' } });
      const m = String(r.data.body || '').match(new RegExp(`${cfAsset}:\\s*([0-9a-f]{64})`, 'i'));
      return m ? m[1].toLowerCase() : '';
    },
  });

  if (C.NEZHA_SERVER && C.NEZHA_KEY) {
    const version = C.NEZHA_VERSION || (C.NEZHA_PORT ? 'v0.20.5' : 'latest');
    const nzAsset = `nezha-agent_linux_${isArm ? 'arm64' : 'amd64'}.zip`;
    const nzUrl = releaseUrl('nezhahq/agent', version, nzAsset);
    specs.push({
      name: 'nezha-agent', file: paths.nezha, url: nzUrl, zipEntry: 'nezha-agent', manualSha: C.SHA256_NEZHA,
      fetchHash: async () => {
        const t = await fetchText(releaseUrl('nezhahq/agent', version, 'checksums.txt'));
        const line = t.split('\n').find((l) => l.trim().endsWith(nzAsset));
        const m = line && line.match(/^([0-9a-f]{64})/i);
        return m ? m[1].toLowerCase() : '';
      },
    });
  }
  return specs;
}

async function installBinary(spec) {
  const buf = await retry(() => fetchBuf(spec.url));

  let expected = spec.manualSha;
  if (!expected) {
    try { expected = await retry(spec.fetchHash, 2); } catch (e) { err(`${spec.name} 获取校验值失败: ${e.message}`); }
  }
  if (expected) {
    const actual = sha256(buf);
    if (actual !== expected) throw new Error(`${spec.name} SHA256 不匹配，期望 ${expected}，实际 ${actual}`);
    log(`${spec.name} SHA256 校验通过`);
  } else if (C.STRICT_VERIFY) {
    throw new Error(`${spec.name} 无校验值且 STRICT_VERIFY=true，拒绝运行`);
  } else {
    err(`警告: ${spec.name} 未做 SHA256 校验`);
  }

  let out = buf;
  if (spec.zipEntry) {
    const zip = new AdmZip(buf);
    const entry = zip.getEntries().find((e) => !e.isDirectory && path.basename(e.entryName) === spec.zipEntry);
    if (!entry) throw new Error(`${spec.name} 压缩包内找不到 ${spec.zipEntry}`);
    out = entry.getData();
  }
  fs.writeFileSync(spec.file, out, { mode: 0o755 });
  log(`${spec.name} 已安装`);
}

/* ============================== 启动各组件 ============================== */
function argoSetup() {
  const { ARGO_AUTH, ARGO_DOMAIN, ARGO_PORT } = C;
  if (!ARGO_AUTH || !ARGO_DOMAIN) return log('使用临时隧道 (quick tunnel)');
  if (ARGO_AUTH.includes('TunnelSecret')) {
    writeSecret(paths.tunnelJson, ARGO_AUTH);
    let tunnelId = '';
    try { tunnelId = JSON.parse(ARGO_AUTH).TunnelID; } catch { /* ignore */ }
    fs.writeFileSync(paths.tunnelYml, [
      `tunnel: ${tunnelId}`, `credentials-file: ${paths.tunnelJson}`, 'protocol: http2', '',
      'ingress:', `  - hostname: ${ARGO_DOMAIN}`, `    service: http://localhost:${ARGO_PORT}`,
      '    originRequest:', '      noTLSVerify: true', '  - service: http_status:404', '',
    ].join('\n'));
  } else {
    log(`使用 token 连接隧道，请在 Cloudflare 后台把服务设为 http://localhost:${ARGO_PORT}`);
  }
}

function startNezha() {
  if (!(C.NEZHA_SERVER && C.NEZHA_KEY)) return log('NEZHA 变量为空，跳过');
  const tlsPorts = new Set(['443', '8443', '2096', '2087', '2083', '2053']);

  if (C.NEZHA_PORT) {  // v0
    const args = ['-s', `${C.NEZHA_SERVER}:${C.NEZHA_PORT}`, '-p', C.NEZHA_KEY, '--disable-auto-update', '--report-delay', '4', '--skip-conn', '--skip-procs'];
    if (tlsPorts.has(C.NEZHA_PORT)) args.push('--tls');
    if (!C.NEZHA_ALLOW_EXEC) args.push('--disable-command-execute');
    launch(paths.nezha, args);
  } else {             // v1
    const port = C.NEZHA_SERVER.includes(':') ? C.NEZHA_SERVER.split(':').pop() : '';
    writeSecret(paths.nezhaCfg, [
      `client_secret: ${C.NEZHA_KEY}`, 'debug: false', 'disable_auto_update: true',
      `disable_command_execute: ${!C.NEZHA_ALLOW_EXEC}`, 'disable_force_update: true',
      'disable_nat: false', 'disable_send_query: false', 'gpu: false',
      `insecure_tls: ${C.NEZHA_INSECURE_TLS}`, 'ip_report_period: 1800', 'report_delay: 4',
      `server: ${C.NEZHA_SERVER}`, 'skip_connection_count: true', 'skip_procs_count: true',
      'temperature: false', `tls: ${tlsPorts.has(port)}`, 'use_gitee_to_upgrade: false',
      'use_ipv6_country_code: false', `uuid: ${UUID}`, '',
    ].join('\n'));
    launch(paths.nezha, ['-c', paths.nezhaCfg]);
  }
}

function argoArgs() {
  const { ARGO_AUTH, ARGO_PORT } = C;
  if (/^[A-Za-z0-9=]{120,250}$/.test(ARGO_AUTH)) {
    return ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', 'http2', 'run', '--token', ARGO_AUTH];
  }
  if (ARGO_AUTH.includes('TunnelSecret')) {
    return ['tunnel', '--edge-ip-version', 'auto', '--config', paths.tunnelYml, 'run'];
  }
  return ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', 'http2',
    '--logfile', paths.bootLog, '--loglevel', 'info', '--url', `http://localhost:${ARGO_PORT}`];
}

async function downloadAndRun() {
  await Promise.all(binarySpecs().map(installBinary));
  startNezha();
  await sleep(1000);
  launch(paths.web, ['run', '-c', paths.config]);
  await sleep(1000);
  launch(paths.bot, argoArgs());
  await sleep(2000);
}

/* ============================== 域名与节点生成 ============================== */
async function waitForQuickTunnelDomain(timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const m = fs.readFileSync(paths.bootLog, 'utf8').match(/https?:\/\/([^\s/]*trycloudflare\.com)/);
      if (m) return m[1];
    } catch { /* 日志尚未生成 */ }
    await sleep(1000);
  }
  return '';
}

async function getArgoDomain(retries = 2) {
  if (C.ARGO_AUTH && C.ARGO_DOMAIN) return C.ARGO_DOMAIN;
  for (let i = 0; i <= retries; i++) {
    const d = await waitForQuickTunnelDomain();
    if (d) return d;
    if (i < retries) {
      err('未获取到临时隧道域名，重启 cloudflared 重试');
      const old = children.find((c) => c.spawnfile === paths.bot);
      if (old) { old.expected = true; old.kill('SIGTERM'); }
      fs.rmSync(paths.bootLog, { force: true });
      await sleep(3000);
      launch(paths.bot, argoArgs());
    }
  }
  return '';
}

async function getMetaInfo() {
  const opts = { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 3000 };
  try {
    const { data } = await axios.get('https://api.ip.sb/geoip', opts);
    if (data?.country_code && data?.isp) return `${data.country_code}-${data.isp}`.replace(/\s+/g, '_');
  } catch {
    try {
      const { data } = await axios.get('http://ip-api.com/json', opts);
      if (data?.status === 'success') return `${data.countryCode}-${data.org}`.replace(/\s+/g, '_');
    } catch { /* ignore */ }
  }
  return 'Unknown';
}

async function getServerIP() {
  for (const [url, wrap] of [['https://ipv4.ip.sb', (x) => x], ['https://ipv6.ip.sb', (x) => `[${x}]`]]) {
    try { return wrap((await axios.get(url, { timeout: 3000, responseType: 'text' })).data.trim()); } catch { /* next */ }
  }
  return '';
}

let subContent = null;

async function generateLinks(argoDomain) {
  const [isp, serverIP] = await Promise.all([getMetaInfo(), getServerIP()]);
  const nodeName = C.NAME ? `${C.NAME}-${isp}` : isp;
  const tag = encodeURIComponent(nodeName);
  const { CFIP, CFPORT } = C;

  const vmess = {
    v: '2', ps: nodeName, add: CFIP, port: CFPORT, id: UUID, aid: '0', scy: 'auto', net: 'ws', type: 'none',
    host: argoDomain, path: '/vmess-argo?ed=2560', tls: 'tls', sni: argoDomain, alpn: '', fp: 'firefox',
  };

  const lines = [
    `vless://${UUID}@${CFIP}:${CFPORT}?encryption=none&security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Fvless-argo%3Fed%3D2560#${tag}`,
    `vmess://${Buffer.from(JSON.stringify(vmess)).toString('base64')}`,
    `trojan://${UUID}@${CFIP}:${CFPORT}?security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Ftrojan-argo%3Fed%3D2560#${tag}`,
  ];

  if (hy2Enabled) {
    const fp = certFingerprint();
    lines.push(`hysteria2://${UUID}@${serverIP}:${C.HY2_PORT}/?sni=www.bing.com&insecure=0&alpn=h3&obfs=none${fp ? `&pinSHA256=${encodeURIComponent(fp)}` : ''}#${tag}`);
  }
  if (validPort(C.REALITY_PORT)) {
    lines.push(`vless://${UUID}@${serverIP}:${C.REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.iij.ad.jp&fp=firefox&pbk=${state.reality.publicKey}&sid=${state.reality.shortId}&type=tcp&headerType=none#${tag}`);
  }
  if (validPort(C.S5_PORT)) {
    const auth = Buffer.from(`${UUID.slice(0, 8)}:${UUID.slice(-12)}`).toString('base64');
    lines.push(`socks://${auth}@${serverIP}:${C.S5_PORT}#${tag}`);
  }

  const text = lines.join('\n\n') + '\n';
  subContent = Buffer.from(text).toString('base64');
  writeSecret(paths.sub, subContent);
  writeSecret(paths.list, text);
  log(`${paths.sub} saved`);
  return lines;
}

/* ============================== 上传 / 推送 / 保活 ============================== */
const NODE_RE = /^(vless|vmess|trojan|hysteria2|socks):\/\//;

async function deleteNodes() {
  if (!C.UPLOAD_URL || !fs.existsSync(paths.sub)) return;
  try {
    const nodes = Buffer.from(fs.readFileSync(paths.sub, 'utf8'), 'base64').toString().split('\n').filter((l) => NODE_RE.test(l));
    if (nodes.length) await axios.post(`${C.UPLOAD_URL}/api/delete-nodes`, { nodes }, { timeout: 10000 });
  } catch { /* ignore */ }
}

async function uploadNodes(lines) {
  if (!C.UPLOAD_URL) return;
  try {
    if (C.PROJECT_URL) {
      await axios.post(`${C.UPLOAD_URL}/api/add-subscriptions`, { subscription: [`${C.PROJECT_URL}/${SUB_PATH}`] }, { timeout: 10000 });
      log('Subscription uploaded');
    } else {
      const nodes = lines.filter((l) => NODE_RE.test(l));
      if (nodes.length) { await axios.post(`${C.UPLOAD_URL}/api/add-nodes`, { nodes }, { timeout: 10000 }); log('Nodes uploaded'); }
    }
  } catch (e) { err('Upload failed:', e.message); }
}

const mdEscape = (s) => s.replace(/[_*[\]()~`>#+=|{}.!\\-]/g, '\\$&');

async function sendTelegram() {
  if (!C.BOT_TOKEN || !C.CHAT_ID) return log('TG 变量为空，跳过推送');
  try {
    await axios.post(`https://api.telegram.org/bot${C.BOT_TOKEN}/sendMessage`, {
      chat_id: C.CHAT_ID,
      text: `*${mdEscape(C.NAME || 'Node')} 节点推送*\n\`\`\`\n${subContent}\n\`\`\``,
      parse_mode: 'MarkdownV2',
    }, { timeout: 10000 });
    log('Telegram message sent');
  } catch (e) { err('Telegram failed:', e.message); }
}

async function addVisitTask() {
  if (!C.AUTO_ACCESS || !C.PROJECT_URL) return log('跳过自动保活');
  try {
    await axios.post('https://oooo.serv00.net/add-url', { url: C.PROJECT_URL }, { timeout: 10000 });
    log('automatic access task added');
  } catch (e) { err('Add access task failed:', e.message); }
}

function scheduleCleanup() {
  if (C.KEEP_FILES) return;
  setTimeout(() => {
    const files = [paths.bootLog, paths.config, paths.nezhaCfg, paths.nezha, paths.web, paths.bot,
      paths.list, paths.cert, paths.key, paths.tunnelJson, paths.tunnelYml];
    for (const f of files) fs.rmSync(f, { force: true });
    if (C.SHOW_LOG && !C.CHILD_LOG) console.clear();
    always('App is running');
  }, 90000).unref();
}

/* ============================== HTTP 服务 ============================== */
const server = http.createServer(async (req, res) => {
  const urlPath = req.url.split('?')[0];
  const send = (code, type, body) => { res.writeHead(code, { 'Content-Type': `${type}; charset=utf-8` }); res.end(body); };

  if (urlPath === `/${SUB_PATH}`) {
    if (subContent) return send(200, 'text/plain', subContent);
    try { return send(200, 'text/plain', fs.readFileSync(paths.sub, 'utf8')); }
    catch { return send(503, 'text/plain', 'Subscription not ready, please try again later.'); }
  }
  if (urlPath === '/') {
    try { return send(200, 'text/html', await fs.promises.readFile(path.join(__dirname, 'index.html'), 'utf8')); }
    catch { return send(200, 'text/html', 'Hello world!'); }
  }
  send(404, 'text/plain', 'Not Found');
});

/* ============================== 主流程 ============================== */
async function main() {
  server.listen(C.PORT, () => always(`http server is running on ${C.PORT}!`));

  argoSetup();
  await deleteNodes();
  generateConfig();
  await downloadAndRun();

  const domain = await getArgoDomain();
  if (!domain) return err('无法获取 Argo 域名，节点未生成');
  log('ArgoDomain:', domain);

  const lines = await generateLinks(domain);
  await Promise.all([uploadNodes(lines), sendTelegram(), addVisitTask()]);
  scheduleCleanup();
}

main().catch((e) => err('Fatal error:', e));
