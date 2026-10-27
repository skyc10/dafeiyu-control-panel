'use strict';

/** 当前轮询中的任务 id（null 表示没有进行中的任务） */
let activeJobId = null;
let pollTimer = null;
let statusTimer = null;

const QQ_BADGE = {
  online: { cls: 'ok', text: '在线' },
  offline: { cls: 'bad', text: '已离线' },
  not_running: { cls: 'unknown', text: '未启动' },
  waiting_scan: { cls: 'warn', text: '等待扫码' },
  unknown: { cls: 'unknown', text: '未知' },
};

/** 统一的 API 请求：POST 自动带防跨站标记头。 */
async function api(path, options = {}) {
  const init = { credentials: 'same-origin', headers: {} };
  if (options.method === 'POST') {
    init.method = 'POST';
    init.headers['Content-Type'] = 'application/json';
    init.headers['X-Panel-Action'] = '1';
    init.body = JSON.stringify(options.body || {});
  }
  const response = await fetch(path, init);
  let data = null;
  try {
    data = await response.json();
  } catch (err) {
    data = null;
  }
  if (!response.ok) {
    const message = (data && data.error) || `请求失败（HTTP ${response.status}）`;
    throw new Error(message);
  }
  return data;
}

/* ── 状态渲染 ───────────────────────────────────────────── */

function setItem(id, tone, value, detail) {
  const node = document.getElementById(id);
  if (!node) return;
  node.classList.remove('ok', 'warn', 'bad', 'unknown');
  node.classList.add(tone);
  node.querySelector('.status-value').textContent = value;
  node.querySelector('.status-detail').textContent = detail || '';
}

function containerTone(info) {
  if (!info) return ['unknown', '未知', ''];
  if (info.state === 'missing') return ['bad', '缺失', '容器不存在，需按部署文档修复'];
  if (info.running) return ['ok', '运行中', info.detail || ''];
  if (info.state === 'unknown') return ['unknown', '未知', info.detail || ''];
  const code = info.exitCode;
  return ['warn', '已停止', code === null ? info.detail || '' : `退出码 ${code} · ${info.detail || ''}`];
}

function renderStatus(data) {
  const docker = data.docker || {};
  if (docker.available) {
    setItem('st-docker', 'ok', '可用', `版本 ${docker.version || '未知'}`);
  } else {
    setItem('st-docker', 'bad', '不可用', docker.error || '未连接');
  }

  const containers = data.containers || {};
  const [sTone, sVal, sDetail] = containerTone(containers.snowluma);
  setItem('st-snowluma', sTone, sVal, sDetail);
  const [fTone, fVal, fDetail] = containerTone(containers['fish-bot']);
  setItem('st-fishbot', fTone, fVal, fDetail);

  const services = data.services || {};
  const dsh = services.dsh || {};
  if (!containers['fish-bot'] || !containers['fish-bot'].running) {
    setItem('st-dsh', 'unknown', '未运行', 'AI 容器未启动，无法探测');
  } else if (dsh.reachable) {
    setItem('st-dsh', 'ok', '已响应', `HTTP ${dsh.httpStatus}`);
  } else {
    setItem('st-dsh', 'warn', '无响应', dsh.note || '端口 18080 未响应');
  }

  const bridge = services.bridge || {};
  if (!containers['fish-bot'] || !containers['fish-bot'].running) {
    setItem('st-bridge', 'unknown', '未运行', 'AI 容器未启动，无法探测');
  } else if (bridge.reachable) {
    const ready = bridge.dshReady;
    setItem(
      'st-bridge',
      'ok',
      '已就绪',
      ready === true ? '控制台在线，DSH 已连接' : ready === false ? '控制台在线，DSH 未连接' : '控制台在线'
    );
  } else {
    setItem('st-bridge', 'warn', '无响应', bridge.note || '端口 13100 未响应');
  }

  const qq = data.qq || { status: 'unknown', detail: '' };
  const meta = QQ_BADGE[qq.status] || QQ_BADGE.unknown;
  setItem('st-qq', meta.cls, meta.text, qq.detail || '');

  const consoles = data.consoles || {};
  document.querySelectorAll('.card-state').forEach((node) => {
    const key = node.getAttribute('data-state');
    const ready = Boolean(consoles[key]);
    node.textContent = ready ? '● 可打开' : '○ 当前不可用';
    node.classList.toggle('ok', ready);
    node.classList.toggle('off', !ready);
  });

  document.getElementById('last-update').textContent = `状态更新于 ${data.time || '—'}`;

  renderPlugins(data.plugins || []);
}

/* ── 插件入口 ───────────────────────────────────────────── */

/** 只在插件列表变化时重建卡片，避免每次轮询都打断点击。 */
let lastPluginSig = '';

function renderPlugins(plugins) {
  const wrap = document.getElementById('plugin-cards');
  const empty = document.getElementById('plugins-empty');
  const sig = plugins.map((p) => `${p.id}:${p.ready}`).join('|');
  if (!wrap || sig === lastPluginSig) return;
  lastPluginSig = sig;

  wrap.innerHTML = '';
  empty.hidden = plugins.length > 0;

  plugins.forEach((plugin) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'card';
    button.dataset.pluginId = plugin.id;

    const name = document.createElement('span');
    name.className = 'card-tag';
    name.textContent = plugin.name;

    const port = document.createElement('span');
    port.className = 'card-port';
    port.textContent = `127.0.0.1:${plugin.port}`;

    button.appendChild(name);
    if (plugin.desc) {
      const desc = document.createElement('span');
      desc.className = 'card-desc';
      desc.textContent = plugin.desc;
      button.appendChild(desc);
    }
    button.appendChild(port);

    const state = document.createElement('span');
    state.className = 'card-state ' + (plugin.ready ? 'ok' : 'off');
    state.textContent = plugin.ready ? '可打开' : '当前不可用';
    button.appendChild(state);

    button.addEventListener('click', () => openConsole(plugin.id, button));
    wrap.appendChild(button);
  });
}

/* ── 任务进度 ───────────────────────────────────────────── */

const JOB_STATE_LABEL = { queued: '排队中', running: '进行中', done: '已完成', failed: '失败' };

function renderJob(job) {
  const panel = document.getElementById('job-panel');
  const title = document.getElementById('job-title');
  const badge = document.getElementById('job-badge');
  const steps = document.getElementById('job-steps');
  const error = document.getElementById('job-error');

  panel.hidden = false;
  title.textContent = `${job.label} · ${job.id.slice(0, 6)}`;
  badge.textContent = JOB_STATE_LABEL[job.status] || job.status;
  badge.className = 'badge ' + (job.status === 'running' || job.status === 'queued' ? 'running' : job.status === 'done' ? 'done' : 'failed');

  steps.innerHTML = '';
  (job.steps || []).forEach((step) => {
    const li = document.createElement('li');
    li.dataset.state = step.state;
    li.textContent = step.label;
    if (step.detail) {
      const span = document.createElement('span');
      span.className = 'st';
      span.textContent = step.detail;
      li.appendChild(span);
    }
    steps.appendChild(li);
  });

  if (job.error) {
    error.hidden = false;
    error.textContent = `失败原因：${job.error}`;
  } else {
    error.hidden = true;
  }
}

function setButtonsBusy(busy) {
  document.querySelectorAll('[data-action]').forEach((btn) => {
    btn.disabled = busy;
  });
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
  activeJobId = null;
  setButtonsBusy(false);
}

async function pollJob() {
  if (!activeJobId) return;
  try {
    const job = await api(`/api/jobs/${activeJobId}`);
    renderJob(job);
    if (job.status === 'done' || job.status === 'failed') {
      stopPolling();
      await refreshStatus();
    }
  } catch (err) {
    // 404：面板重启后任务丢失。不重放旧操作，只提示并恢复按钮
    stopPolling();
    const error = document.getElementById('job-error');
    const panel = document.getElementById('job-panel');
    panel.hidden = false;
    document.getElementById('job-badge').textContent = '已中断';
    document.getElementById('job-badge').className = 'badge failed';
    error.hidden = false;
    error.textContent = `${err.message}（面板可能已重启；请以当前状态为准，必要时重新操作）`;
  }
}

function startPolling(jobId) {
  activeJobId = jobId;
  setButtonsBusy(true);
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(pollJob, 1200);
  pollJob();
}

async function runAction(action) {
  const button = document.querySelector(`[data-action="${action}"]`);
  if (button) button.disabled = true;
  try {
    const result = await api('/api/actions', { method: 'POST', body: { action } });
    renderJob(result.job);
    if (result.reused) {
      const error = document.getElementById('job-error');
      error.hidden = true;
    }
    if (result.job.status === 'done' || result.job.status === 'failed') {
      setButtonsBusy(false);
      await refreshStatus();
    } else {
      startPolling(result.job.id);
    }
  } catch (err) {
    setButtonsBusy(false);
    const panel = document.getElementById('job-panel');
    const error = document.getElementById('job-error');
    panel.hidden = false;
    document.getElementById('job-title').textContent = '操作未被接受';
    const badge = document.getElementById('job-badge');
    badge.textContent = '未执行';
    badge.className = 'badge failed';
    document.getElementById('job-steps').innerHTML = '';
    error.hidden = false;
    error.textContent = err.message;
  }
}

/* ── 控制台跳转 ─────────────────────────────────────────── */

async function openConsole(id, trigger) {
  // 先同步打开占位窗口，避免异步后再 window.open 被拦截
  const placeholder = window.open('about:blank', '_blank');
  if (trigger) trigger.disabled = true;
  try {
    const result = await api(`/api/consoles/${id}/open`, { method: 'POST', body: {} });
    if (placeholder && !placeholder.closed) {
      placeholder.location.replace(result.url);
      placeholder.opener = null;
    } else {
      window.open(result.url, '_blank', 'noopener');
    }
    // 提示分流：插件显示在插件区，其余走控制台入口区
    if (trigger && trigger.dataset && trigger.dataset.pluginId) {
      showPluginNote(result.note || '', false);
    } else if (result.note) {
      showConsoleNote(result.note);
    }
  } catch (err) {
    if (placeholder && !placeholder.closed) placeholder.close();
    const message = `无法打开：${err.message}`;
    // 插件入口的失败信息显示在插件区内，避免串到扫码提示上
    if (document.querySelector(`#plugin-cards button[data-plugin-id="${id}"]`)) {
      showPluginNote(message, true);
    } else if (id === 'novnc') {
      const hint = document.getElementById('aux-hint');
      if (hint) {
        hint.textContent = message;
        hint.style.color = '#dc2626';
      }
    } else {
      window.alert(message);
    }
  } finally {
    if (trigger) trigger.disabled = false;
  }
}

/** 在入口区显示一行提示（例如 SnowLuma 初始密码提醒）。 */
function showConsoleNote(text) {
  const hint = document.getElementById('aux-hint');
  if (!hint) return;
  hint.textContent = text;
  hint.style.color = text.includes('修改') ? '#b45309' : '';
}

/** 插件区的状态提示。 */
function showPluginNote(text, isError) {
  const hint = document.getElementById('plugin-hint');
  if (!hint) return;
  hint.hidden = false;
  hint.textContent = text;
  hint.style.color = isError ? '#dc2626' : '';
}

/* ── 最近操作 ───────────────────────────────────────────── */

function renderRecent(items) {
  const list = document.getElementById('recent-list');
  list.innerHTML = '';
  if (!items || items.length === 0) {
    const li = document.createElement('li');
    li.className = 'recent-empty';
    li.textContent = '暂无操作记录';
    list.appendChild(li);
    return;
  }
  items.forEach((item) => {
    const li = document.createElement('li');
    const head = document.createElement('div');
    head.className = 'row-head';
    const name = document.createElement('strong');
    name.textContent = item.label;
    const state = document.createElement('span');
    state.textContent = JOB_STATE_LABEL[item.status] || item.status;
    state.style.color =
      item.status === 'done' ? '#3fb950' : item.status === 'failed' ? '#f85149' : '#93a4b5';
    head.appendChild(name);
    head.appendChild(state);
    li.appendChild(head);

    const detail = document.createElement('div');
    detail.className = 'row-detail';
    const when = item.finishedAt || item.startedAt || '';
    const steps = (item.steps || []).filter((s) => s.detail).map((s) => s.detail);
    detail.textContent = [when, steps.join(' / ')].filter(Boolean).join(' · ');
    li.appendChild(detail);

    if (item.error) {
      const err = document.createElement('div');
      err.className = 'row-error';
      err.textContent = item.error;
      li.appendChild(err);
    }
    list.appendChild(li);
  });
}

/* ── 刷新与初始化 ───────────────────────────────────────── */

async function refreshStatus() {
  try {
    const data = await api('/api/status');
    renderStatus(data);
    renderRecent(data.recent);

    // 面板刷新后：如有进行中的任务，自动接管进度
    const running = (data.jobs || [])[0];
    if (running && !activeJobId) {
      renderJob({ label: running.label, id: running.id, status: 'running', steps: [] });
      startPolling(running.id);
    }
  } catch (err) {
    document.getElementById('last-update').textContent = `状态获取失败：${err.message}`;
  }
}

function tickClock() {
  const now = new Date();
  document.getElementById('clock').textContent = now.toLocaleString('zh-CN', { hour12: false });
}

function init() {
  tickClock();
  setInterval(tickClock, 1000);

  document.getElementById('refresh').addEventListener('click', refreshStatus);

  document.querySelectorAll('[data-console]').forEach((node) => {
    node.addEventListener('click', () => openConsole(node.getAttribute('data-console'), node));
  });

  document.querySelectorAll('[data-action]').forEach((node) => {
    node.addEventListener('click', () => {
      const action = node.getAttribute('data-action');
      if (action === 'stop_all' && !window.confirm('将依次停止 fish-bot 与 snowluma。\n容器与数据卷保留，下次启动可能需要重新扫码。\n\n继续？')) {
        return;
      }
      runAction(action);
    });
  });

  refreshStatus();
  statusTimer = setInterval(refreshStatus, 5000);
}

document.addEventListener('DOMContentLoaded', init);
