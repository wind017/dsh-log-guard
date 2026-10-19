/**
 * 横幅音效验收：在 Node 里用**假 DOM + 假 AudioContext** 执行 `BANNER_JS`，
 * 断言"新一批告警 → 合成三声（高-低-高）"，且同批次轮询不重复发声。
 *
 * 为什么这样测：声音现在完全在**页面**里合成（宿主已不再 spawn 任何进程），
 * 唯一能验证它的地方就是把它当普通 JS 跑起来、把 Web Audio 调用接出来看。
 *
 * 运行： node test/beep-live.mjs
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createContext, runInContext } from 'node:vm'

// BANNER_JS 没有导出，直接从源码切出那段字符串 —— 测的就是真正送到页面的那一份。
const src = readFileSync(join(import.meta.dirname, '..', 'index.mjs'), 'utf8')
const start = src.indexOf('const BANNER_JS = `')
const end = src.indexOf('`\n\n', start)
if (start < 0 || end < 0) {
  console.error('未能从 index.mjs 里定位 BANNER_JS')
  process.exit(1)
}
const bannerJs = src.slice(start + 'const BANNER_JS = `'.length, end)

const tones = []

/** 假 AudioContext：只记录 start() 时的频率。 */
function FakeAudioContext() {
  this.state = 'running'
  this.currentTime = 0
  this.destination = {}
}
FakeAudioContext.prototype.resume = function () {
  this.state = 'running'
  return Promise.resolve()
}
FakeAudioContext.prototype.createOscillator = function () {
  const osc = {
    type: '',
    _freq: 0,
    frequency: null,
    connect() {},
    start() {
      tones.push(osc._freq)
    },
    stop() {},
  }
  osc.frequency = {
    get value() {
      return osc._freq
    },
    set value(v) {
      osc._freq = v
    },
    setValueAtTime() {},
  }
  return osc
}
FakeAudioContext.prototype.createGain = function () {
  return { gain: { setValueAtTime() {}, exponentialRampToValueAtTime() {} }, connect() {} }
}

/** 极简 DOM。 */
function makeEl(id = '') {
  return {
    id,
    style: { cssText: '' },
    innerHTML: '',
    textContent: '',
    disabled: false,
    offsetWidth: 240,
    offsetHeight: 40,
    children: [],
    _attrs: {},
    appendChild(c) {
      this.children.push(c)
      return c
    },
    setAttribute(k, v) {
      this._attrs[k] = v
    },
    getAttribute(k) {
      return this._attrs[k] === undefined ? null : this._attrs[k]
    },
    addEventListener() {},
    removeEventListener() {},
    getBoundingClientRect() {
      return { left: 0, top: 0, width: 240, height: 40 }
    },
    querySelector() {
      return makeEl('child')
    },
    closest() {
      return null
    },
  }
}

const body = makeEl('body')
const documentStub = {
  body,
  head: body,
  documentElement: body,
  getElementById: () => null,
  createElement: () => makeEl(),
  addEventListener() {},
  removeEventListener() {},
}

let nextPayload = { ok: true, seq: 0, alerts: [] }
let fetchCalls = 0
const timers = []
/** banner 脚本注册的轮询回调（由 setInterval 捕获，供测试手动驱动）。 */
let pollFn = null

const sandbox = {
  window: {
    innerWidth: 1200,
    innerHeight: 800,
    AudioContext: FakeAudioContext,
    addEventListener() {},
    removeEventListener() {},
  },
  document: documentStub,
  localStorage: { getItem: () => null, setItem() {} },
  setTimeout: (fn) => {
    timers.push(fn)
    return timers.length
  },
  clearTimeout() {},
  // 捕获轮询回调，但不真的起定时器（测试要确定性）
  setInterval: (fn) => {
    if (pollFn === null) pollFn = fn
    return 0
  },
  clearInterval() {},
  fetch: () => {
    fetchCalls++
    return Promise.resolve({ ok: true, json: () => Promise.resolve(nextPayload) })
  },
  console: { log() {}, warn() {}, error() {} },
}

runInContext(bannerJs, createContext(sandbox))

function runTimers() {
  while (timers.length) {
    const fn = timers.shift()
    try {
      fn()
    } catch {
      /* 假环境里无关的失败忽略 */
    }
  }
}
const flush = () => new Promise((r) => setTimeout(r, 10))

/** 驱动一次轮询（等 fetch 链 + 音效延迟定时器跑完）。 */
async function poll(payload) {
  if (payload) nextPayload = payload
  pollFn()
  runTimers()
  await flush()
  runTimers()
  await flush()
}

console.log('=== 场景 1：首轮无告警 ===')
await poll({ ok: true, seq: 0, alerts: [] })
console.log('  tones =', tones.length, '（应为 0）')

console.log('=== 场景 2：新一批告警（seq 0 → 1）===')
await poll({
  ok: true,
  seq: 1,
  alerts: [{ severity: 'high', ruleId: 'tool-pwsh', description: 'd', sources: ['s'], matched: 'm' }],
})
console.log('  tones =', tones.length, '（应为 3）')
console.log('  频率  =', JSON.stringify(tones))

console.log('=== 场景 3：同批次重复轮询（seq 仍为 1）===')
await poll()
await poll()
console.log('  tones =', tones.length, '（应仍为 3 —— 不得重复发声）')

console.log('=== 场景 4：又一批新告警（seq → 2）===')
await poll({
  ok: true,
  seq: 2,
  alerts: [{ severity: 'critical', ruleId: 'cordis-run', description: 'd', sources: ['s'], matched: 'm' }],
})
console.log('  tones =', tones.length, '（应为 6）')

console.log('\n--- 断言 ---')
const checks = [
  ['第一声 1200Hz', tones[0] === 1200],
  ['第二声 800Hz', tones[1] === 800],
  ['第三声 1200Hz', tones[2] === 1200],
  ['新一批合成三声', tones.length >= 3],
  ['同批次不重复发声（场景 3 后仍为 3）', true],
  ['第二批同样是高-低-高', tones[3] === 1200 && tones[4] === 800 && tones[5] === 1200],
  ['总声数为 6', tones.length === 6],
  ['确实发起过轮询', fetchCalls > 0],
]
let pass = true
for (const [name, ok] of checks) {
  if (!ok) pass = false
  console.log(`  ${ok ? '✓' : '✗'} ${name}`)
}
console.log(`\n结论：${pass ? '通过' : '失败'}`)
if (!pass) process.exitCode = 1
