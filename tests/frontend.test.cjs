const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
function context(fetch, stubRender = true) {
  const nodes = new Map();
  const node = id => {
    if (!nodes.has(id)) nodes.set(id, { textContent: '', className: '', querySelector(selector) { return node(id + selector); }, classList: { values: new Set(), toggle(value, enabled) { if(enabled) this.values.add(value); else this.values.delete(value); }, add(...v) { v.forEach(x=>this.values.add(x)); }, remove(...v) { v.forEach(x=>this.values.delete(x)); } } });
    return nodes.get(id);
  };
  const ctx = vm.createContext({ fetch, AbortSignal, Date, console, document: { getElementById: node, querySelectorAll: () => [], addEventListener() {} }, setInterval() {}, clearInterval() {} });
  vm.runInContext(fs.readFileSync('static/app.js','utf8'), ctx);
  vm.runInContext('renderRecent = () => {}; renderPlugins = () => {};', ctx);
  if (stubRender) vm.runInContext('renderStatus = () => {};', ctx);
  return { ctx, node };
}
test('overlapping status refreshes issue one request', async () => {
  let resolve; let calls = 0;
  const pending = new Promise(r=>resolve=r);
  const {ctx} = context(async()=>{calls++;return pending;});
  const first = vm.runInContext('refreshStatus()',ctx);
  await vm.runInContext('refreshStatus()',ctx);
  assert.equal(calls,1);
  resolve({ok:true,json:async()=>({time:'now',jobs:[],recent:[]})});
  await first;
});
test('failed status refresh marks previous data stale and permits retry', async () => {
  let calls = 0;
  const {ctx,node} = context(async()=>{calls++; throw new Error('offline');});
  await vm.runInContext('refreshStatus()',ctx);
  assert.equal(node('overall-label').textContent, '状态已过期');
  assert.equal(node('overview').classList.values.has('stale'), true);
  assert.equal(node('overall-badge').className, 'badge failed');
  await vm.runInContext('refreshStatus()',ctx);
  assert.equal(calls,2);
});

test('real status renderer separates DSH HTTP reachability from authenticated readiness', () => {
  const {ctx,node} = context(async()=>{}, false);
  const data = {containers:{'fish-bot':{running:true},snowluma:{running:true}},services:{dsh:{reachable:true,httpStatus:401},bridge:{reachable:true,reporting:true,ready:false,dshReady:false,errorLabel:'DSH 鉴权失败'}},qq:{status:'online'},overall:{state:'degraded',label:'连接异常'}};
  ctx.fixture = data;
  vm.runInContext('renderStatus(fixture)',ctx);
  assert.equal(node('st-dsh').classList.values.has('warn'),true);
  assert.equal(node('st-bridge').classList.values.has('ok'),false);
  data.services.bridge.ready=true;
  data.services.bridge.dshReady=true;
  data.services.bridge.errorLabel='';
  vm.runInContext('renderStatus(fixture)',ctx);
  assert.equal(node('st-dsh.status-value').textContent,'已就绪');
  assert.equal(node('st-dsh.status-detail').textContent,'鉴权与事件流正常');
  assert.equal(node('st-bridge').classList.values.has('ok'),true);
});
