/**
 * @file dsh-log-guard 的离线自测。不需要 DSH 运行时，只用 Node 22+。
 *
 * 运行： node test/run-tests.mjs
 */
import {
  mkdtempSync,
  writeFileSync,
  readFileSync,
  appendFileSync,
  existsSync,
  rmSync,
  copyFileSync,
  readdirSync,
  mkdirSync,
} from 'node:fs'
import { tmpdir, homedir } from 'node:os'
import { join } from 'node:path'
import assert from 'node:assert/strict'

import {
  LogGuard,
  normalizeConfig as baseNormalizeConfig,
  normalizeEnforce,
  installEnforcement,
  scanText,
  buildRules,
  decodeZstd,
  prepareScanText,
  takeScanCounters,
  DEFAULT_RULES,
} from '../index.mjs'

/**
 * **测试封闭性补丁**：给每个 `normalizeConfig(...)` 调用自动注入隔离的状态文件。
 *
 * 为什么必须：`unackedStateFile` / `ignoredStateFile` / `notifyLog` 的默认值落在
 * 用户真实的 `$DSH_HOME/log-guard/` 下。测试若不显式覆盖，就会读到真实状态 ——
 * 实测表现为「首次 tick 不应告警」失败（真实未确认队列里还有别的告警），
 * 且失败数会随真实文件内容变化（同一份代码两次跑出 2 个和 5 个失败）。
 *
 * 实现方式：用同名函数遮蔽 import 的 `normalizeConfig`，先铺隔离默认值，
 * 再让调用方显式传入的字段覆盖它（`{...defaults, ...raw}`）。临时文件名保留
 * 原名后缀，所以断言默认值（如 `endsWith('alerts.jsonl')`）依然成立。
 */
const shadowRoot = mkdtempSync(join(tmpdir(), 'log-guard-shadow-'))
let shadowSeq = 0
function shadowState() {
  const dir = join(shadowRoot, `s${++shadowSeq}`)
  mkdirSync(dir, { recursive: true })
  return {
    alertFile: join(dir, 'alerts.jsonl'),
    notifyLog: join(dir, 'notify.log'),
    ignoredStateFile: join(dir, 'ignored-sessions.json'),
    unackedStateFile: join(dir, 'unacked-alerts.json'),
  }
}
function normalizeConfig(raw) {
  return baseNormalizeConfig({ ...shadowState(), ...(raw ?? {}) })
}
process.on('exit', () => {
  try {
    rmSync(shadowRoot, { recursive: true, force: true })
  } catch {
    /* 清理失败不影响测试结论 */
  }
})

let passed = 0
let failed = 0
const failures = []

/** 本测试文件替换过全局定时器，每个测试跑完都要还原，避免测试之间互相污染。 */
const pendingRestores = []

/** 极简测试登记。 */
function test(name, fn) {
  try {
    fn()
    passed++
    console.log(`  ok   ${name}`)
  } catch (error) {
    failed++
    failures.push({ name, error })
    console.log(`  FAIL ${name}\n       ${error?.message ?? error}`)
  } finally {
    runRestores()
  }
}

/** 还原所有登记过的全局定时器。 */
function runRestores() {
  while (pendingRestores.length > 0) {
    const restore = pendingRestores.pop()
    try {
      restore()
    } catch {
      /* 还原失败不掩盖真正的断言失败 */
    }
  }
}

async function testAsync(name, fn) {
  try {
    await fn()
    passed++
    console.log(`  ok   ${name}`)
  } catch (error) {
    failed++
    failures.push({ name, error })
    console.log(`  FAIL ${name}\n       ${error?.message ?? error}`)
  } finally {
    runRestores()
  }
}

const rules = buildRules({})

/**
 * 测试期的状态隔离目录。
 *
 * 为什么必要：插件默认把状态写到 `$DSH_HOME/log-guard/` 下（alertFile /
 * notifyLog / ignoredStateFile / unackedStateFile）。测试若直接用默认配置，
 * 就会**往用户真实的 ~/.dsh 目录里写文件**（实测出现过
 * `写入待确认告警失败：EPERM …\.dsh\log-guard\unacked-alerts.json`）。
 * 所以这里统一把所有状态文件重定向到临时目录。
 */
const stateDir = mkdtempSync(join(tmpdir(), 'log-guard-state-'))
let stateSeq = 0
process.on('exit', () => {
  try {
    rmSync(stateDir, { recursive: true, force: true })
  } catch {
    /* 清理失败不影响测试结论 */
  }
})

/**
 * 用**每次独立**的隔离状态跑配置规整。
 *
 * 为什么每个调用都要独立目录：未确认告警队列会在构造时从
 * `unackedStateFile` 读回，若多个测试共用一个文件，前一个测试留下的告警会
 * 污染后一个（实测 "初始为空" 断言因此失败，实际读到 4 条）。
 */
function testConfig(overrides = {}) {
  const dir = join(stateDir, `s${++stateSeq}`)
  mkdirSync(dir, { recursive: true })
  return normalizeConfig({
    alertFile: join(dir, 'alerts.jsonl'),
    notifyLog: join(dir, 'notify.log'),
    ignoredStateFile: join(dir, 'ignored-sessions.json'),
    unackedStateFile: join(dir, 'unacked-alerts.json'),
    ...overrides,
  })
}

/** 制造一条假告警（供常驻队列/横幅测试用）。 */
function fakeAlert(ruleId, fingerprint, severity = 'high') {
  return {
    severity,
    ruleId,
    description: `${ruleId} 描述`,
    sources: ['test/source.log'],
    matched: 'matched-text',
    snippet: 'snippet-text',
    fingerprint,
  }
}

/** 造一个够用的假 Cordis 上下文（只实现插件真正用到的方法）。 */
function makeFakeCtx({ onSpawn } = {}) {
  const intervals = []
  const disposers = []
  const routes = []
  const tapIndexFns = []
  const subscriptions = []
  const appliedConfigs = []
  const promptContexts = []

  // 插件刻意用全局 setInterval（不用 ctx.setInterval，那会触发 inject 检查），
  // 所以这里替换全局定时器，既能手动驱动 tick，也能断言卸载时确实清掉了。
  const realSetInterval = globalThis.setInterval
  const realClearInterval = globalThis.clearInterval
  globalThis.setInterval = (fn, ms) => {
    const handle = { fn, ms, cleared: false }
    intervals.push(handle)
    return handle
  }
  globalThis.clearInterval = (handle) => {
    if (handle && typeof handle === 'object') handle.cleared = true
  }
  // 其它测试的 restore() 会把全局定时器换回去，所以这里额外留住假 clearInterval 的引用，
  // 断言时直接用它，避免受全局状态影响。
  const fakeClearInterval = globalThis.clearInterval
  /** 还原全局定时器（测试结束前调用）。 */
  const restore = () => {
    globalThis.setInterval = realSetInterval
    globalThis.clearInterval = realClearInterval
  }
  // 自动登记还原，防止某个测试忘了调用而污染后续测试。
  pendingRestores.push(restore)

  return {
    intervals,
    disposers,
    routes,
    tapIndexFns,
    subscriptions,
    restore,
    fakeClearInterval,
    /** apply() 收到的原始配置（测试用它断言配置透传）。 */
    appliedConfigs,
    /** 捕获到的 systemPrompt.context() 贡献。 */
    promptContexts,
    ctx: {
      // 记录 factory 的返回值（即真正的 disposer），卸载测试要用它。
      effect(factory) {
        const disposer = factory()
        disposers.push({ factory, disposer })
        return () => {
          if (typeof disposer === 'function') disposer()
        }
      },
      // 生命周期钩子：记录订阅的事件名，返回一个可用的 disposer。
      on(event, listener) {
        const subscription = { event, listener, disposed: false }
        subscriptions.push(subscription)
        return () => {
          subscription.disposed = true
        }
      },
      get(name) {
        if (name === 'webServer') {
          return {
            register(route) {
              routes.push(route)
              return () => {}
            },
            tapIndex(fn) {
              tapIndexFns.push(fn)
              return () => {}
            },
          }
        }
        if (name === 'systemPrompt') {
          return {
            context(contribution) {
              promptContexts.push(contribution)
              return () => {}
            },
          }
        }
        if (name === 'subprocess') {
          return { spawn: onSpawn ?? (() => ({ on() {} })) }
        }
        return undefined
      },
    },
  }
}

const tmp = mkdtempSync(join(tmpdir(), 'dsh-log-guard-test-'))

console.log('\n[1] 单元：规则匹配')
test('cordis_define 命中 critical', () => {
  const hits = scanText('{"type":"tool/call","data":{"name":"cordis_define"}}', ['x'], rules)
  const hit = hits.find((h) => h.ruleId === 'cordis-define')
  assert.ok(hit, '应命中 cordis-define')
  assert.equal(hit.severity, 'critical')
})
test('cordis_run 命中 critical', () => {
  const hits = scanText('name": "cordis_run"', ['x'], rules)
  assert.ok(hits.find((h) => h.ruleId === 'cordis-run'))
})
test('subprocess 命中 high', () => {
  const hits = scanText('await ctx.subprocess.spawn({command:"cmd"})', ['x'], rules)
  const hit = hits.find((h) => h.ruleId === 'subprocess-service')
  assert.ok(hit)
  assert.equal(hit.severity, 'high')
})
test('pwsh 工具调用命中', () => {
  const line = '{"type":"tool/call","data":{"name":"pwsh","arguments":"{\\"command\\":\\"whoami\\"}"}}'
  const hits = scanText(line, ['x'], rules)
  assert.ok(hits.find((h) => h.ruleId === 'tool-pwsh'), '应命中 tool-pwsh')
})
test('run_code 工具调用命中', () => {
  const hits = scanText('{"type":"tool/call","data":{"name":"run_code"}}', ['x'], rules)
  assert.ok(hits.find((h) => h.ruleId === 'tool-run-code'))
})
test('child_process 命中 shell-command', () => {
  const hits = scanText('const cp = require("node:child_process")', ['x'], rules)
  assert.ok(hits.find((h) => h.ruleId === 'shell-command'))
})
test('danger-full-access 命中 sandbox-relax', () => {
  const hits = scanText('sandbox_permissions: danger-full-access', ['x'], rules)
  assert.ok(hits.find((h) => h.ruleId === 'sandbox-relax'))
})
test('无关文本不误报', () => {
  const hits = scanText('今天天气不错，我们读了一个普通的 markdown 文件。', ['x'], rules)
  assert.equal(hits.length, 0, `不应命中，实际命中：${hits.map((h) => h.ruleId).join(',')}`)
})
test('每条命中都带非空摘录', () => {
  const hits = scanText('xxx cordis_define yyy', ['x'], rules)
  assert.ok(hits.length > 0)
  for (const hit of hits) assert.ok(hit.snippet.length > 0, `${hit.ruleId} 摘录为空`)
})
test('同一规则在同一文本里只报一次', () => {
  const hits = scanText('cordis_define 和 cordis_define 又一次', ['x'], rules)
  assert.equal(hits.filter((h) => h.ruleId === 'cordis-define').length, 1)
})
test('disabledRules 能关掉规则', () => {
  const r = buildRules({ disabledRules: ['cordis-define'] })
  const hits = scanText('cordis_define', ['x'], r)
  assert.equal(hits.find((h) => h.ruleId === 'cordis-define'), undefined)
})
test('自定义规则支持正则字符串', () => {
  const r = buildRules({ rules: [{ id: 'custom-rm', pattern: 'rm\\s+-rf', severity: 'high', description: '删除' }] })
  const hits = scanText('sudo rm -rf /tmp/x', ['x'], r)
  assert.ok(hits.find((h) => h.ruleId === 'custom-rm'))
})
test('非法自定义规则不会炸', () => {
  const r = buildRules({ rules: [{ id: 'bad', pattern: '([' }, null, 42, { id: '' }] })
  assert.equal(r.filter((x) => x.custom).length, 0)
})

console.log('\n[1b] 回归：只审计"调用"，不审计"结果回显"')
test('tool/result 里出现的 cordis_define 不告警', () => {
  // cordis_inspect_list 之类的返回体会列出 cordis_define 这个工具名。
  const line = JSON.stringify({
    type: 'tool/result',
    data: { content: [{ type: 'text', text: 'available tools: cordis_define, cordis_run' }] },
  })
  const hits = scanText(line, ['x'], rules)
  const bad = hits.find((h) => h.ruleId === 'cordis-define' || h.ruleId === 'cordis-run')
  assert.equal(bad, undefined, `结果回显不应告警，却命中了 ${bad?.ruleId}`)
})
test('request/header 里的工具清单不告警', () => {
  const line = JSON.stringify({
    type: 'request/header',
    data: { tools: [{ name: 'cordis_define' }, { name: 'pwsh' }] },
  })
  const hits = scanText(line, ['x'], rules)
  assert.equal(hits.length, 0, `请求头不应告警，却命中 ${hits.map((h) => h.ruleId).join(',')}`)
})
test('真正的 tool/call 仍然告警', () => {
  const line = JSON.stringify({ type: 'tool/call', data: { name: 'cordis_define', arguments: '{}' } })
  const hits = scanText(line, ['x'], rules)
  assert.ok(hits.find((h) => h.ruleId === 'cordis-define'), '真实调用必须告警')
})
test('工具名规则只吃 tool/call，不匹配裸文本', () => {
  // 普通文本里出现 pwsh 字样（不是调用）不应触发 tool-pwsh
  const hits = scanText('文档里提到 pwsh 这个工具的名字', ['x'], rules)
  assert.equal(hits.find((h) => h.ruleId === 'tool-pwsh'), undefined)
})
test('prepareScanText 能报出被排除的行数', () => {
  const text = [
    JSON.stringify({ type: 'tool/result', data: { content: [] } }),
    JSON.stringify({ type: 'tool/call', data: { name: 'pwsh', arguments: '{}' } }),
  ].join('\n')
  const prepared = prepareScanText(text, ['x'])
  assert.equal(prepared.skipped, 1)
  assert.equal(prepared.calls.length, 1)
  assert.equal(prepared.calls[0].name, 'pwsh')
})
test('真实日志里的工具清单结果不会造成误报风暴', () => {
  // 模拟一段真实会话日志：一次 listTools 的返回体（含全部敏感工具名）
  const listing = JSON.stringify({
    type: 'tool/result',
    data: {
      content: [
        {
          type: 'text',
          text: 'cordis_define cordis_run subprocess spawn child_process danger-full-access plugin_manager',
        },
      ],
    },
  })
  const hits = scanText(listing, ['x'], rules)
  assert.equal(hits.length, 0, `工具清单结果不应告警，却命中：${hits.map((h) => h.ruleId).join(',')}`)
})

console.log('\n[1c] 审计面：只审计工具调用（默认）')
test('对话文本提到敏感词不告警', () => {
  const cases = [
    JSON.stringify({ type: 'user/message', data: { text: '帮我写个 cordis_define 和 subprocess 的插件' } }),
    JSON.stringify({ type: 'assistant/message', data: { content: [{ type: 'text', text: 'cordis_run 会执行动态代码' }] } }),
    JSON.stringify({ type: 'system/message', data: { text: 'sandbox: danger-full-access' } }),
    JSON.stringify({ type: 'request/context', data: { text: 'plugin_manager / deepseekAccount / cordis.yml' } }),
  ]
  for (const line of cases) {
    const hits = scanText(line, ['x'], rules)
    assert.equal(hits.length, 0, `对话/上下文文本不应告警，却命中 ${hits.map((h) => h.ruleId)}`)
  }
})
test('tool/result 里的工具名不告警', () => {
  const line = JSON.stringify({
    type: 'tool/result',
    data: { content: [{ type: 'text', text: 'cordis_define cordis_run subprocess danger-full-access' }] },
  })
  assert.equal(scanText(line, ['x'], rules).length, 0)
})
test('真实工具调用仍然告警（工具名规则）', () => {
  for (const name of ['cordis_define', 'cordis_run', 'run_code', 'pwsh', 'subagent', 'workflow']) {
    const line = JSON.stringify({ type: 'tool/call', data: { name, arguments: '{}' } })
    const hits = scanText(line, ['x'], rules)
    assert.ok(hits.length > 0, `${name} 应触发告警`)
  }
})
test('工具参数里的危险串会命中正则规则', () => {
  const line = JSON.stringify({
    type: 'tool/call',
    data: { name: 'pwsh', arguments: JSON.stringify({ command: 'spawn child_process danger-full-access' }) },
  })
  const ids = scanText(line, ['x'], rules).map((h) => h.ruleId)
  for (const expected of ['tool-pwsh', 'shell-command', 'sandbox-relax']) {
    assert.ok(ids.includes(expected), `应命中 ${expected}，实际 ${ids.join(',')}`)
  }
})
test('兼容 tool-call 这种扁平形态', () => {
  const line = JSON.stringify({ type: 'tool-call', id: 'call_1', name: 'cordis_run', arguments: '{}' })
  const ids = scanText(line, ['x'], rules).map((h) => h.ruleId)
  assert.ok(ids.includes('cordis-run'), `扁平形态应命中，实际 ${ids.join(',')}`)
})
test('同一句话：消息里不报，工具调用里报', () => {
  const text = 'cordis_define'
  const asMessage = JSON.stringify({ type: 'user/message', data: { text } })
  const asCall = JSON.stringify({ type: 'tool/call', data: { name: 'cordis_define', arguments: '{}' } })
  assert.equal(scanText(asMessage, ['x'], rules).length, 0, '出现在消息里不报')
  assert.ok(scanText(asCall, ['x'], rules).length > 0, '出现在调用里要报')
})
test('非 JSON 的纯文本日志始终按文本审计', () => {
  const hits = scanText('2026-01-01 ERROR cordis_define invoked', ['x'], rules)
  assert.ok(hits.some((h) => h.ruleId === 'cordis-define'), '纯文本日志不应被静默跳过')
})
test("audit: 'all-text' 可回退到全文本扫描", () => {
  const line = JSON.stringify({ type: 'user/message', data: { text: '提到 cordis_define' } })
  assert.equal(scanText(line, ['x'], rules, 'tool-calls').length, 0, '默认不应告警')
  const back = scanText(line, ['x'], rules, 'all-text')
  assert.ok(back.some((h) => h.ruleId === 'cordis-define'), 'all-text 模式应恢复告警')
})
test('prepareScanText 报告审计面统计', () => {
  const text = [
    JSON.stringify({ type: 'user/message', data: { text: 'cordis_define' } }),
    JSON.stringify({ type: 'tool/result', data: { content: [] } }),
    JSON.stringify({ type: 'tool/call', data: { name: 'pwsh', arguments: '{}' } }),
  ].join('\n')
  const prepared = prepareScanText(text, ['x'], 'tool-calls')
  assert.equal(prepared.calls.length, 1, '只应识别出 1 个工具调用')
  assert.equal(prepared.skipped, 2, '2 个非工具事件应被排除')
  assert.ok(prepared.text.includes('pwsh'), '待审计文本应含工具调用')
  assert.ok(!prepared.text.includes('cordis_define'), '待审计文本不得含消息内容')
  takeScanCounters()
})
test('已知残留：把对话内容当参数传给工具时仍会告警（这是正确行为，不是缺陷）', () => {
  // 实测本会话的真机日志时发现的：只审计工具调用能滤掉"消息文本"，但滤不掉
  // "消息文本被当参数传进工具"的情形 —— 例如 write(subagent, workflow) 的 arguments
  // 里就带着整段对话摘录。那确实是**一次真实的工具调用**，告警是对的。
  // 结论：audit:'tool-calls' 能滤掉"消息文本"的噪声，但"整轮都在处理敏感词相关
  // 文本"的会话（比如开发这个插件本身）仍会因"工具参数含敏感串"而告警 ——
  // 所以插件**始终忽略自身会话**（不再提供关闭开关）。
  const line = JSON.stringify({
    type: 'tool/call',
    data: { name: 'subagent', arguments: JSON.stringify({ prompt: '请帮我实现 cordis_define 相关功能' }) },
  })
  const ids = scanText(line, ['x'], rules).map((h) => h.ruleId)
  assert.ok(ids.includes('tool-subagent'), `应先命中工具名规则，实际 ${ids.join(',')}`)
  // 该参数里出现了敏感词，正则规则也会命中；这是"工具参数含敏感串"，属预期
  assert.ok(ids.length >= 1, '真实工具调用必须告警')
  assert.ok(ids.includes('cordis-define'), '参数里的敏感串同样应命中正则规则')
})

test('回归：告警摘录必须以命中串为中心（否则看不出报了什么）', () => {
  // 最初从"命中前 80 字符"开始截 240 字。命中串很长时（工具参数就是整行 JSON），
  // 窗口会被前文占满、把命中串挤出可见范围 —— 实测 stderr 行里根本看不到
  // `cordis_define`。这里构造一个"命中串远在 200 字之后"的长文本验证。
  const padding = '前文'.repeat(150) // 300 字
  const line = JSON.stringify({ type: 'tool/call', data: { name: 'cordis_define', arguments: '{}' } })
  const hits = scanText(`${padding}${line}`, ['x'], rules)
  const hit = hits.find((h) => h.ruleId === 'cordis-define')
  assert.ok(hit, '应命中 cordis-define')
  assert.ok(
    hit.snippet.includes('cordis_define'),
    `摘录必须包含命中串本身，实际摘录: ${hit.snippet}`,
  )
  assert.ok(hit.snippet.length <= 260, `摘录应有长度上限，实际 ${hit.snippet.length}`)
})
test('摘录在有前后内容时也能定位命中串', () => {
  // JSONL 是**按行**解析的，所以上下文要用合法的 JSON 行（行首不是 { 的会被当成纯文本）。
  const before = JSON.stringify({ type: 'assistant/message', data: { text: '准备执行命令' } })
  const call = JSON.stringify({
    type: 'tool/call',
    data: { name: 'pwsh', arguments: JSON.stringify({ command: 'whoami', description: '查看当前用户' }) },
  })
  const after = JSON.stringify({ type: 'step/end', data: {} })
  const hits = scanText([before, call, after].join('\n'), ['x'], rules)
  const hit = hits.find((h) => h.ruleId === 'tool-pwsh')
  assert.ok(hit, `应命中 tool-pwsh，实际 ${hits.map((h) => h.ruleId).join(',')}`)
  assert.ok(hit.snippet.includes('whoami'), `摘录应含参数内容，实际: ${hit.snippet}`)
})

test('回归：宿主侧不再 spawn 任何子进程（声音改由页面播放）', () => {
  // 旧实现用 powershell 做 beep + MessageBox：模态弹窗会把界面按住，
  // 且 spawn 的 spec 与契约不符，日志只显示"已启动"却根本没响。
  // 现在声音由 banner.js 用 Web Audio 合成，宿主侧**完全不应该**再碰 subprocess。
  let spawnCalls = 0
  const ctx = {
    effect: () => () => {},
    on: () => () => {},
    get: (name) => (name === 'subprocess' ? { spawn: () => (spawnCalls++, { on() {} }) } : undefined),
  }
  const guard = new LogGuard(ctx, testConfig({ notifySound: true, notifyCooldownMs: 0 }))
  guard.raise([fakeAlert('tool-pwsh', 'fp-sound-1')])
  guard.raise([fakeAlert('cordis-run', 'fp-sound-2')])
  assert.equal(spawnCalls, 0, '宿主侧不得再 spawn 任何子进程')
})
test('声音信号受冷却限制，并落到 notify.log 供排查', () => {
  const notifyLog = join(stateDir, 'sound-signal.log')
  const ctx = { effect: () => () => {}, on: () => () => {}, get: () => undefined }
  const guard = new LogGuard(ctx, testConfig({ notifySound: true, notifyCooldownMs: 60_000, notifyLog }))

  guard.raise([fakeAlert('tool-pwsh', 'fp-c1')])
  guard.raise([fakeAlert('cordis-run', 'fp-c2')])
  let lines = readFileSync(notifyLog, 'utf8').trim().split('\n')
  assert.equal(lines.filter((l) => l.includes('sound-signal')).length, 1, '冷却窗口内只发一次声音信号')

  // 冷却过期后应能再发
  guard.notifyCooldownUntil = Date.now() - 1
  guard.raise([fakeAlert('subprocess', 'fp-c3')])
  lines = readFileSync(notifyLog, 'utf8').trim().split('\n')
  assert.equal(lines.filter((l) => l.includes('sound-signal')).length, 2, '冷却过期后应可再发')
})
test('回归：告警常驻展示直到确认（不再读即消费）', () => {
  const ctx = { effect: () => () => {}, on: () => () => {}, get: () => undefined }
  // 用独立状态文件：共享 stateDir 会被其它测试的告警污染，"初始为空"就不成立。
  const guard = new LogGuard(
    ctx,
    testConfig({ notifySound: false, unackedStateFile: join(stateDir, 'unacked-persist.json') }),
  )

  assert.equal(guard.unackedList().alerts.length, 0, '初始为空')
  const seq0 = guard.unackedList().seq
  guard.raise([fakeAlert('tool-pwsh', 'fp-p1')])
  assert.equal(guard.unackedList().alerts.length, 1, '告警后应有 1 条')
  assert.equal(guard.unackedList().seq, seq0 + 1, 'seq 应递增（页面据此判断"有新一批"）')

  // 反复读取必须仍然在 —— 这正是"常态展示"的核心
  for (let i = 0; i < 5; i++) {
    assert.equal(guard.unackedList().alerts.length, 1, '第 ' + (i + 1) + ' 次读取后仍应保留')
  }

  const removed = guard.acknowledgeAlerts()
  assert.equal(removed, 1, '确认应移除 1 条')
  assert.equal(guard.unackedList().alerts.length, 0, '确认后应为空（横幅收起）')
})
test('回归：未确认告警跨重启保留（刷新/重启不会自己消失）', () => {
  const state = join(stateDir, 'unacked-restart.json')
  const ctx = { effect: () => () => {}, on: () => () => {}, get: () => undefined }
  const first = new LogGuard(ctx, testConfig({ notifySound: false, unackedStateFile: state }))
  first.raise([fakeAlert('cordis-define', 'fp-r1'), fakeAlert('cordis-run', 'fp-r2')])
  assert.equal(first.unackedList().alerts.length, 2)

  const second = new LogGuard(ctx, testConfig({ notifySound: false, unackedStateFile: state }))
  assert.equal(second.unackedList().alerts.length, 2, '重启后未确认告警必须还在')
  assert.equal(second.unackedList().seq, first.unackedList().seq, 'seq 也应恢复')

  // 部分确认：只移除指定指纹
  const removed = second.acknowledgeAlerts(['fp-r1'])
  assert.equal(removed, 1)
  const left = second.unackedList().alerts.map((a) => a.fingerprint)
  assert.deepEqual(left, ['fp-r2'], '部分确认应只移除指定项')
})
test('未确认队列有上限，超出丢最旧', () => {
  const ctx = { effect: () => () => {}, on: () => () => {}, get: () => undefined }
  const guard = new LogGuard(ctx, testConfig({ notifySound: false, maxPendingAlerts: 3 }))
  for (let i = 1; i <= 5; i++) guard.raise([fakeAlert('tool-pwsh', 'fp-cap-' + i)])
  const ids = guard.unackedList().alerts.map((a) => a.fingerprint)
  assert.equal(ids.length, 3, '应被上限截断为 3')
  assert.deepEqual(ids, ['fp-cap-3', 'fp-cap-4', 'fp-cap-5'], '保留最新的 3 条')
})
test('notifyCooldownMs 非法值回落默认', () => {
  assert.equal(normalizeConfig({ notifyCooldownMs: -5 }).notifyCooldownMs, 30_000)
  assert.equal(normalizeConfig({ notifyCooldownMs: 'x' }).notifyCooldownMs, 30_000)
  assert.equal(normalizeConfig({ notifyCooldownMs: 0 }).notifyCooldownMs, 0)
  assert.equal(normalizeConfig({ notifyCooldownMs: 5000 }).notifyCooldownMs, 5000)
})
test('notifyLog 可置 null 关闭', () => {
  assert.equal(normalizeConfig({ notifyLog: null }).notifyLog, null)
  assert.ok(normalizeConfig({}).notifyLog.endsWith('notify.log'))
})
test('unackedStateFile 可置 null 关闭（代价：重启后告警不再保留）', () => {
  assert.equal(normalizeConfig({ unackedStateFile: null }).unackedStateFile, null)
  assert.ok(normalizeConfig({}).unackedStateFile.endsWith('unacked-alerts.json'))
})
test('回归：启动即忽略已知自身会话（消除启动空窗）', () => {
  // 自身识别原本只靠 DSH_SESSION_ID（Host 里通常没有）+ session/event（要等首个事件），
  // 于是插件刚启动、事件还没来之前自身会话仍会被扫描 —— "重启后头几轮自己报自己"。
  const tmpDir = mkdtempSync(join(tmpdir(), 'selfid-'))
  const state = join(tmpDir, 'ignored-sessions.json')
  const cfg = () => testConfig({ ignoredStateFile: state })
  const ctx = { effect: () => () => {}, on: () => () => {}, get: () => undefined }

  const first = new LogGuard(ctx, cfg())
  const before = first.ignoredSessionIds.size
  first.noteActiveSession('session-KNOWN-SELF')
  assert.ok(first.ignoredSessionIds.has('session-KNOWN-SELF'), '应记入忽略名单')
  assert.ok(existsSync(state), '应把自身会话持久化')

  // 模拟重启：新实例在首个事件到来之前就应忽略自身
  const second = new LogGuard(ctx, cfg())
  assert.ok(
    second.ignoredSessionIds.has('session-KNOWN-SELF'),
    `重启后应立即忽略已知自身会话，实际 ${JSON.stringify([...second.ignoredSessionIds])}`,
  )
  assert.ok(second.ignoredSessionIds.size >= before + 1)

  // 状态文件损坏时不得影响构造
  writeFileSync(state, '{ 这不是 JSON', 'utf8')
  assert.doesNotThrow(() => new LogGuard(ctx, cfg()), '状态文件损坏不应影响启动')
  rmSync(tmpDir, { recursive: true, force: true })
})

console.log('\n[2] 单元：告警渲染与配置')
test('unackedList 返回横幅渲染所需字段，且**读取不消费**', () => {
  const fake = makeFakeCtx()
  const guard = new LogGuard(fake.ctx, testConfig())
  guard.raise([fakeAlert('cordis-run', 'fp-fields', 'critical')])
  const list = guard.unackedList()
  assert.equal(list.alerts.length, 1)
  assert.equal(list.alerts[0].ruleId, 'cordis-run')
  assert.equal(list.alerts[0].severity, 'critical')
  assert.equal(list.alerts[0].matched, 'matched-text')
  assert.equal(typeof list.seq, 'number', '应一并给出序号（页面据此判断新批次）')
  // 关键：再读一次仍在（旧 drainAlerts 会取走即清，导致告警一闪而过）
  assert.equal(guard.unackedList().alerts.length, 1, '读取不得清空队列')
})
test('normalizeConfig 回落默认值', () => {
  const c = normalizeConfig(undefined)
  assert.equal(c.scanIntervalMs, 1000)
  assert.equal(c.enabled, true)
  assert.equal(c.uiBanner, true)
  assert.ok(c.sessionDir.endsWith('sessions'))
  assert.deepEqual(c.sessionFileNames, ['session.v4.jsonl.zstd'])
})
test('normalizeConfig 接受用户覆写', () => {
  const c = normalizeConfig({ scanIntervalMs: 250, scanExisting: true, alertFile: null, files: ['a.log'] })
  assert.equal(c.scanIntervalMs, 250)
  assert.equal(c.scanExisting, true)
  assert.equal(c.alertFile, null)
  assert.deepEqual(c.files, ['a.log'])
})
test('normalizeConfig 拒绝非法数值', () => {
  const c = normalizeConfig({ scanIntervalMs: -5, maxPendingAlerts: 'abc' })
  assert.equal(c.scanIntervalMs, 1000)
  assert.equal(c.maxPendingAlerts, 20)
})

console.log('\n[3] 真实日志：多帧 zstd 解码')
const realDir = join(homedir(), '.dsh', 'sessions')
/** 找一个体积最大的真实会话日志。 */
function biggestSessionLog() {
  let best = null
  try {
    for (const dirent of readdirSyncRecursive(realDir)) {
      if (!dirent.endsWith('session.v4.jsonl.zstd')) continue
      const size = readFileSync(dirent).length
      if (!best || size > best.size) best = { path: dirent, size }
    }
  } catch {
    return null
  }
  return best
}
/** 递归列出文件（避免依赖 readdirSync 的 recursive 选项）。 */
function readdirSyncRecursive(root) {
  const out = []
  const stack = [root]
  while (stack.length > 0) {
    const dir = stack.pop()
    let entries
    try {
      entries = readdirSync(dir, { withFileTypes: true })
    } catch {
      continue
    }
    for (const entry of entries) {
      const full = join(dir, entry.name)
      if (entry.isDirectory()) stack.push(full)
      else out.push(full)
    }
  }
  return out
}

const biggest = biggestSessionLog()
if (biggest) {
  console.log(`  （样本：${biggest.path}，${biggest.size} 字节）`)
  test('多帧 zstd 能完整解码（含全部帧）', () => {
    const buf = readFileSync(biggest.path)
    const decoded = decodeZstd(buf)
    assert.equal(decoded.failed, 0, `有 ${decoded.failed} 帧解压失败`)
    assert.ok(decoded.frames > 1, `预期多帧，实际 ${decoded.frames}`)
    assert.ok(decoded.text.length > 1000, `解码文本过短：${decoded.text.length}`)
    const lines = decoded.text.split('\n').filter(Boolean)
    assert.ok(lines.length > 10, `行数过少：${lines.length}`)
    // 每一行都应是合法 JSON（会话日志格式）
    let bad = 0
    for (const line of lines) {
      try {
        JSON.parse(line)
      } catch {
        bad++
      }
    }
    assert.equal(bad, 0, `有 ${bad} 行不是合法 JSON`)
  })
  test('真实日志里能读出工具调用事件', () => {
    const decoded = decodeZstd(readFileSync(biggest.path))
    const names = new Set()
    for (const line of decoded.text.split('\n')) {
      if (!line) continue
      try {
        const event = JSON.parse(line)
        if (event?.type === 'tool/call' && event.data?.name) names.add(event.data.name)
      } catch {
        /* 忽略非 JSON 行 */
      }
    }
    assert.ok(names.size > 0, '没找到任何 tool/call 事件')
    console.log(`       该日志中的工具：${[...names].join(', ')}`)
    // 至少应该能识别出 pwsh（我们在本次会话里大量使用）
    assert.ok(names.has('pwsh'), '预期该日志包含 pwsh 调用')
  })
} else {
  console.log('  （未找到真实会话日志，跳过）')
}

console.log('\n[4] 端到端：tail 文件 → 命中 → 告警')
await testAsync('LogGuard 只对新增内容告警，并写出告警文件 + 供横幅拉取', async () => {
  const logPath = join(tmp, 'sample.log')
  const alertPath = join(tmp, 'alerts.jsonl')
  if (existsSync(alertPath)) rmSync(alertPath)
  writeFileSync(logPath, '历史内容：cordis_define（默认不应告警，因为 scanExisting=false）\n', 'utf8')

  let spawned = 0
  const fake = makeFakeCtx({ onSpawn: () => (spawned++, { on() {} }) })
  const config = normalizeConfig({
    files: [logPath],
    watchSessionLogs: false,
    alertFile: alertPath,
    scanIntervalMs: 50,
    notifySound: false,
    printToHostConsole: false,
  })
  const guard = new LogGuard(fake.ctx, config)

  // 手动驱动一轮，避免依赖真实计时器。
  guard.tick()
  assert.equal(guard.unackedList().alerts.length, 0, '首次 tick 不应告警（scanExisting=false）')

  appendFileSync(logPath, '普通行，没有敏感操作\n', 'utf8')
  guard.tick()
  assert.equal(guard.unackedList().alerts.length, 0, '普通新增行不应告警')

  appendFileSync(
    logPath,
    '{"type":"tool/call","data":{"name":"cordis_run","arguments":"{}"}}\n',
    'utf8',
  )
  guard.tick()
  const pendingAfterCall = guard.unackedList().alerts.length
  assert.ok(pendingAfterCall >= 1, 'cordis_run 应产生告警')
  assert.ok(
    guard.unackedList().alerts.some((alert) => alert.ruleId === 'cordis-run'),
    '应命中 cordis-run 规则',
  )

  // 新语义：告警**常驻**在未确认队列里，供横幅反复拉取；只有用户确认才清空。
  assert.ok(
    guard.unackedList().alerts.some((a) => a.ruleId === 'cordis-run'),
    '未确认队列里应有 cordis-run 告警',
  )
  guard.acknowledgeAlerts()
  assert.equal(guard.unackedList().alerts.length, 0, '确认后队列应清空')

  assert.ok(existsSync(alertPath), '应写出告警文件')
  const alertLines = readFileSync(alertPath, 'utf8').split('\n').filter(Boolean)
  assert.equal(alertLines.length, pendingAfterCall, '告警文件条数应与命中条数一致')
  const records = alertLines.map((line) => JSON.parse(line))
  assert.ok(records.some((r) => r.ruleId === 'cordis-run' && r.severity === 'critical'))

  // 去重：同一内容再次出现不应重复告警
  appendFileSync(logPath, '{"type":"tool/call","data":{"name":"cordis_run","arguments":"{}"}}\n', 'utf8')
  guard.tick()
  assert.equal(guard.unackedList().alerts.length, 0, '去重窗口内不应重复告警')
  void spawned
})

await testAsync('半行 JSON 不会被误判，补全后才告警', async () => {
  const logPath = join(tmp, 'partial.log')
  writeFileSync(logPath, '', 'utf8')
  const fake = makeFakeCtx()
  const guard = new LogGuard(
    fake.ctx,
    normalizeConfig({
      files: [logPath],
      watchSessionLogs: false,
      alertFile: join(tmp, 'partial-alerts.jsonl'),
      printToHostConsole: false,
    }),
  )
  guard.tick()

  // 先写半行（模拟日志刷到一半）
  appendFileSync(logPath, '{"type":"tool/call","data":{"name":"cordis_', 'utf8')
  guard.tick()
  assert.equal(guard.unackedList().alerts.length, 0, `半行不应告警，实际命中 ${guard.unackedList().alerts.map((a) => a.ruleId)}`)

  // 补全整行
  appendFileSync(logPath, 'define","arguments":"{}"}}\n', 'utf8')
  guard.tick()
  assert.ok(
    guard.unackedList().alerts.some((a) => a.ruleId === 'cordis-define'),
    '补全后应告警',
  )
})

await testAsync('多行未刷新的尾部不会漏报', async () => {
  const logPath = join(tmp, 'multiline.log')
  writeFileSync(logPath, '', 'utf8')
  const fake = makeFakeCtx()
  const guard = new LogGuard(
    fake.ctx,
    normalizeConfig({
      files: [logPath],
      watchSessionLogs: false,
      alertFile: join(tmp, 'multiline-alerts.jsonl'),
      printToHostConsole: false,
    }),
  )
  guard.tick()

  // 一次追加三行，但尾部没有换行符
  appendFileSync(
    logPath,
    '{"type":"tool/call","data":{"name":"read","arguments":"{}"}}\n' +
      '{"type":"tool/result","data":{"content":[{"type":"text","text":"cordis_define cordis_run"}]}}\n' +
      '{"type":"tool/call","data":{"name":"cordis_run","arguments":"{}"}}',
    'utf8',
  )
  guard.tick()
  assert.equal(guard.unackedList().alerts.length, 0, '没有换行结尾时不应扫描未完结的行')

  appendFileSync(logPath, '\n', 'utf8')
  guard.tick()
  assert.ok(
    guard.unackedList().alerts.some((a) => a.ruleId === 'cordis-run'),
    '补上换行后应告警',
  )
  assert.ok(
    !guard.unackedList().alerts.some((a) => a.ruleId === 'cordis-define'),
    '结果回显里的 cordis_define 不应告警',
  )
})

await testAsync('LogGuard 能监控真实 zstd 会话日志的新增帧', async () => {
  if (!biggest) {
    console.log('       跳过（无样本）')
    return
  }
  const copyPath = join(tmp, 'session.v4.jsonl.zstd')
  // 把首帧的会话 id 换成中性的，否则这份样本可能正好是"当前会话自己" ——
  // 那会被自身会话忽略逻辑正确跳过，从而让断言失去意义（实测最大的日志就是自己那份）。
  {
    const { zstdDecompressSync, zstdCompressSync } = await import('node:zlib')
    const raw = readFileSync(biggest.path)
    const magic = Buffer.from([0x28, 0xb5, 0x2f, 0xfd])
    const first = raw.indexOf(magic)
    const second = raw.indexOf(magic, first + 4)
    const head = zstdDecompressSync(raw.subarray(first, second === -1 ? raw.length : second)).toString('utf8')
    const neutral = head.replace(/"id":"[^"]*"/, '"id":"session-NEUTRAL-SAMPLE"')
    writeFileSync(copyPath, Buffer.concat([zstdCompressSync(Buffer.from(neutral, 'utf8')), raw.subarray(second)]))
  }
  const alertPath = join(tmp, 'alerts2.jsonl')
  if (existsSync(alertPath)) rmSync(alertPath)

  const fake = makeFakeCtx()
  const config = normalizeConfig({
    files: [copyPath],
    watchSessionLogs: false,
    alertFile: alertPath,
    scanExisting: true,
    scanIntervalMs: 50,
    printToHostConsole: false,
  })
  const guard = new LogGuard(fake.ctx, config)
  guard.tick() // 全量扫描历史
  const total = guard.unackedList().alerts.length
  console.log(
    `       历史全量扫描：审计了 ${guard.auditedCalls} 次工具调用，命中 ${total} 条告警`,
  )
  // 注意：**不能断言"必有命中"**。默认审计面只覆盖工具调用，而这份样本是某个
  // 真实会话，里面有没有敏感调用取决于那次会话干了什么（实测这个样本全是
  // pwsh/glob/read，没有敏感调用）。这里改为断言"确实审计到了工具调用"，
  // 这才是这份大日志能稳定验证的东西：多帧解码 + 游标推进 + 工具调用识别。
  assert.ok(guard.auditedCalls > 0, '真实日志里应审计到工具调用（证明解码与识别都在工作）')
  guard.acknowledgeAlerts()

  // 再 tick 一次：没有新帧就不应重复告警
  guard.tick()
  assert.equal(guard.unackedList().alerts.length, 0, '无新增内容时不应告警')
  if (total > 0) {
    const written = readFileSync(alertPath, 'utf8').split('\n').filter(Boolean)
    assert.equal(written.length, total, '告警文件条数应与命中条数一致')
  } else {
    console.log('       （该样本没有敏感工具调用，跳过告警文件条数校验）')
  }
})

await testAsync('插件 apply() 能装配 UI 横幅并可被卸载', async () => {
  const logPath = join(tmp, 'apply.log')
  writeFileSync(logPath, '', 'utf8')
  const fake = makeFakeCtx()
  const plugin = (await import('../index.mjs')).default
  plugin.apply(fake.ctx, {
    files: [logPath],
    watchSessionLogs: false,
    alertFile: join(tmp, 'apply-alerts.jsonl'),
    printToHostConsole: false,
  })
  assert.equal(fake.intervals.length, 1, '应注册一个轮询定时器')

  // ① webServer 路由：alerts.json + banner.js + history
  const paths = fake.routes.map((r) => r.path).sort()
  assert.deepEqual(
    paths,
    // paths 已 .sort()，这里按字母序给出期望值。
    [
      '/dsh-log-guard/ack',
      '/dsh-log-guard/alerts.json',
      '/dsh-log-guard/banner.js',
      '/dsh-log-guard/history',
    ],
    '应注册四个横幅路由（含用户确认用的 /ack）',
  )
  // ② 注入行：index-inject 订阅存在，触发后 table 里多出指向 banner.js 的 script 行
  const events = fake.subscriptions.map((s) => s.event)
  for (const event of ['app-boot/config-reload', 'agent/created', 'session/created', 'webserver/index-inject']) {
    assert.ok(events.includes(event), `应挂上事件 ${event}`)
  }
  const inject = fake.subscriptions.find((s) => s.event === 'webserver/index-inject')
  const table = []
  inject.listener(table)
  assert.equal(table.length, 1, '触发 index-inject 后应注入一行')
  assert.ok(table[0].text.indexOf('/dsh-log-guard/banner.js') >= 0, '注入行应指向 banner.js')

  // ③ alerts.json 路由消费挂起的告警
  appendFileSync(logPath, 'cordis_define\n', 'utf8')
  fake.intervals[0].fn()
  const alertsRoute = fake.routes.find((r) => r.path === '/dsh-log-guard/alerts.json')
  let body = ''
  const res = { writeHead: () => {}, end: (s) => { body = s } }
  await alertsRoute.handler({}, res)
  const payload = JSON.parse(body)
  assert.equal(payload.ok, true, 'alerts.json 应返回 ok:true')
  assert.ok(payload.alerts.some((a) => a.ruleId === 'cordis-define'), 'alerts.json 应返回命中的告警')

  // 卸载：跑一遍所有 effect 的 disposer，定时器应被清除。
  // 注意：必须在还原全局定时器之前跑 —— stop() 用的是此刻的全局 clearInterval。
  for (const entry of fake.disposers) {
    if (typeof entry.disposer === 'function') entry.disposer()
  }
  assert.equal(fake.intervals[0].cleared, true, '卸载时应清除定时器')
})

await testAsync('banner.js 路由返回的脚本引用 alerts.json 且含 banner 挂载点', async () => {
  const logPath = join(tmp, 'banner-js.log')
  writeFileSync(logPath, '', 'utf8')
  const fake = makeFakeCtx()
  const plugin = (await import('../index.mjs')).default
  plugin.apply(fake.ctx, {
    files: [logPath],
    watchSessionLogs: false,
    alertFile: join(tmp, 'banner-js-alerts.jsonl'),
    printToHostConsole: false,
  })
  const scriptRoute = fake.routes.find((r) => r.path === '/dsh-log-guard/banner.js')
  assert.ok(scriptRoute, '应有 banner.js 路由')
  let body = ''
  const res = { writeHead: () => {}, end: (s) => { body = s } }
  await scriptRoute.handler({}, res)
  for (const marker of ['/dsh-log-guard/alerts.json', 'dsh-log-guard-banner', '安全告警', '在线', 'pointerdown']) {
    assert.ok(body.indexOf(marker) >= 0, `banner.js 应包含 ${marker}`)
  }
})

await testAsync('history 路由把 alerts.jsonl 渲染成 HTML 页', async () => {
  const logPath = join(tmp, 'history.log')
  writeFileSync(logPath, '', 'utf8')
  const alertPath = join(tmp, 'history-alerts.jsonl')
  writeFileSync(
    alertPath,
    JSON.stringify({
      time: '2026-01-01T00:00:00.000Z',
      severity: 'critical',
      ruleId: 'cordis-run',
      description: '动态 Cordis 包运行',
      sources: ['x/session.v4.jsonl.zstd'],
      matched: 'cordis_run',
      snippet: '...',
      fingerprint: 'abc',
    }) + '\n',
    'utf8',
  )
  const fake = makeFakeCtx()
  const plugin = (await import('../index.mjs')).default
  plugin.apply(fake.ctx, {
    files: [logPath],
    watchSessionLogs: false,
    alertFile: alertPath,
    printToHostConsole: false,
  })
  const historyRoute = fake.routes.find((r) => r.path === '/dsh-log-guard/history')
  assert.ok(historyRoute, '应有 history 路由')
  let body = ''
  const res = { writeHead: () => {}, end: (s) => { body = s } }
  await historyRoute.handler({}, res)
  for (const marker of ['告警历史', 'cordis-run', '动态 Cordis 包运行', 'cordis_run']) {
    assert.ok(body.indexOf(marker) >= 0, `history 页应包含 ${marker}`)
  }
})

await testAsync('回归：会话日志发现必须支持三层嵌套（真实布局）', async () => {
  // 真实布局： <sessionDir>/<workspace-slug>/<session-id>/session.v4.jsonl.zstd
  // 早期实现按 <sessionDir>/<dir>/<file> 拼路径，拼出来的全是不存在的路径，
  // 于是插件"在运行"却一个文件都没监控。这个测试盯死这个回归。
  const sessionsRoot = join(tmp, 'sessions-nested')
  const slugA = join(sessionsRoot, '--C-Users-x-proj--')
  const slugB = join(sessionsRoot, '--D-other--')
  const sessA1 = join(slugA, 'session-aaaa')
  const sessA2 = join(slugA, 'session-bbbb')
  const sessB1 = join(slugB, 'session-cccc')
  for (const d of [sessA1, sessA2, sessB1]) mkdirSync(d, { recursive: true })

  writeFileSync(join(sessA1, 'session.v4.jsonl.zstd'), '')
  writeFileSync(join(sessA2, 'session.v4.jsonl.zstd'), '')
  writeFileSync(join(sessB1, 'session.v4.jsonl.zstd'), '')
  // 干扰项：文件名不匹配；以及一份刻意埋深的（需要 root→slug→session→l1→l2→l3 共 4 层）
  writeFileSync(join(sessA1, 'other.log'), 'cordis_define')
  mkdirSync(join(sessA1, 'l1', 'l2', 'l3'), { recursive: true })
  writeFileSync(join(sessA1, 'l1', 'l2', 'l3', 'session.v4.jsonl.zstd'), '')

  const fake = makeFakeCtx()
  const guard = new LogGuard(
    fake.ctx,
    normalizeConfig({
      alertFile: null,
      printToHostConsole: false,
      watchSessionLogs: true,
      sessionDir: sessionsRoot,
    }),
  )
  const files = guard.resolveFiles()
  // 默认深度 3：够到真实布局（slug/session/file），够不到埋到 l3 的那份
  assert.equal(files.length, 3, `默认深度 3 应发现 3 个日志文件，实际 ${files.length}`)
  assert.equal(guard.sessionFilesFound, 3)
  for (const f of files) {
    assert.ok(f.endsWith('session.v4.jsonl.zstd'), `不应收录其它文件名：${f}`)
    assert.ok(!f.includes('l3'), '不应越过默认深度上限')
  }

  // 深度上限必须真的生效、且可调：depth D 能到达嵌套 D-1 层的文件。
  // 埋深的那份在 root/slugA/sessA/l1/l2/l3/ 下（5 层），所以需要 depth 5。
  const deeper = new LogGuard(
    fake.ctx,
    normalizeConfig({
      alertFile: null,
      printToHostConsole: false,
      watchSessionLogs: true,
      sessionDir: sessionsRoot,
      maxSessionScanDepth: 5,
    }),
  )
  assert.equal(deeper.resolveFiles().length, 4, '深度 5 时应够到埋得更深的那份')

  // 真实布局至少需要 2 层，深度 1 什么都找不到
  const tooShallow = new LogGuard(
    fake.ctx,
    normalizeConfig({
      alertFile: null,
      printToHostConsole: false,
      watchSessionLogs: true,
      sessionDir: sessionsRoot,
      maxSessionScanDepth: 1,
    }),
  )
  assert.equal(tooShallow.resolveFiles().length, 0, '深度不足时应如实返回 0（供启动自检告警）')
})

await testAsync('回归：会话目录里一个日志都没有时必须能报出 0（不能静默）', async () => {
  const emptyRoot = join(tmp, 'sessions-empty')
  mkdirSync(emptyRoot, { recursive: true })
  const fake = makeFakeCtx()
  const guard = new LogGuard(
    fake.ctx,
    normalizeConfig({
      alertFile: null,
      printToHostConsole: false,
      watchSessionLogs: true,
      sessionDir: emptyRoot,
    }),
  )
  const files = guard.resolveFiles()
  assert.equal(files.length, 0)
  assert.equal(guard.sessionFilesFound, 0, '必须如实报告 0，供启动自检告警')
})

await testAsync('端到端：三层嵌套的真实布局能被监控到并产生告警', async () => {
  const sessionsRoot = join(tmp, 'sessions-e2e')
  const sessDir = join(sessionsRoot, '--C-slug--', 'session-live')
  mkdirSync(sessDir, { recursive: true })
  const logPath = join(sessDir, 'session.v4.jsonl.zstd')
  writeFileSync(logPath, '', 'utf8')

  const fake = makeFakeCtx()
  const guard = new LogGuard(
    fake.ctx,
    normalizeConfig({
      alertFile: join(tmp, 'nested-alerts.jsonl'),
      printToHostConsole: false,
      watchSessionLogs: true,
      sessionDir: sessionsRoot,
      scanIntervalMs: 50,
    }),
  )
  guard.tick() // 首次建立游标（scanExisting=false → 从末尾开始）
  assert.equal(guard.sessionFilesFound, 1, '应发现嵌套里的那一个日志')

  // 模拟真实会话日志追加一条工具调用
  appendFileSync(
    logPath,
    '{"type":"tool/call","data":{"name":"cordis_define","arguments":"{}"}}\n',
    'utf8',
  )
  guard.tick()
  assert.ok(
    guard.unackedList().alerts.some((a) => a.ruleId === 'cordis-define'),
    '三层嵌套目录下的日志新增必须被检测到',
  )
})

await testAsync('回归：zstd 半截帧导致解码变短时，不得重扫历史（本轮误报的根因）', async () => {
  // 实测机制（不是猜的）：把一帧截断后 Node 的 zstdDecompressSync **不抛错**，
  // 而是"这一帧贡献 0 个字符" —— 整份解码文本因此比上一轮**变短**。
  // 旧实现在这里把游标重置为 0，等帧补全后就把**整份历史**重扫一遍，
  // 把一小时前的会话内容再告警一次。这就是那几批一模一样的 11 条误报的来源。
  const { zstdCompressSync } = await import('node:zlib')
  const logPath = join(tmp, 'shrink.v4.jsonl.zstd')
  const frame = (obj) => zstdCompressSync(Buffer.from(`${JSON.stringify(obj)}\n`, 'utf8'))

  const historic = Buffer.concat([
    frame({ type: 'user/message', data: { text: '历史内容，只提到 cordis_define' } }),
    frame({ type: 'tool/call', data: { name: 'cordis_define', arguments: '{}' } }),
    frame({ type: 'step/end', data: {} }),
  ])
  const fSubprocess = frame({ type: 'tool/call', data: { name: 'subprocess', arguments: '{}' } })
  const halfSubprocess = fSubprocess.subarray(0, Math.floor(fSubprocess.length / 2))

  const fake = makeFakeCtx()
  const guard = new LogGuard(
    fake.ctx,
    normalizeConfig({
      files: [logPath],
      watchSessionLogs: false,
      alertFile: null,
      printToHostConsole: false,
      scanExisting: true, // 先把历史扫掉，游标推到末尾
    }),
  )

  // ① 全量扫描历史，应命中 cordis_define
  writeFileSync(logPath, historic)
  guard.tick()
  assert.ok(
    guard.unackedList().alerts.some((a) => a.ruleId === 'cordis-define'),
    '首次全量扫描应命中历史里的 cordis_define',
  )
  assert.ok(
    !guard.unackedList().alerts.some((a) => a.ruleId === 'subprocess-service'),
    '历史里没有 subprocess，不应命中（否则后面的断言无法区分新旧内容）',
  )
  const cursorAfterFull = guard.sources.get(logPath).lineStart
  guard.acknowledgeAlerts()

  // ② 写入"半截的 subprocess 帧"：这一帧贡献 0 字符，解码文本 == 上一轮（不变短也不变长）
  writeFileSync(logPath, Buffer.concat([historic, halfSubprocess]))
  guard.tick()
  assert.equal(guard.unackedList().alerts.length, 0, '半截帧那一轮不得产生告警')
  guard.acknowledgeAlerts()

  // ③ 补全这**同一帧**：解码文本从上一轮变长，新增内容就是 subprocess 那一帧
  writeFileSync(logPath, Buffer.concat([historic, fSubprocess]))
  guard.tick()

  const after = guard.unackedList().alerts.map((a) => a.ruleId)
  assert.ok(
    after.includes('subprocess-service'),
    `帧补全后应命中新的 subprocess，实际 ${after.join(',') || '(无)'}`,
  )
  assert.ok(
    !after.includes('cordis-define'),
    '帧补全后不得重扫历史：旧缺陷正是在这里把历史 cordis_define 又报一遍（那几批 11 条误报）',
  )
  assert.ok(
    after.length <= 2,
    `补全后命中应只有新帧那一条，实际 ${after.length} 条：${after.join(',')}`,
  )
  // 游标必须单调前进，绝不回退到 0
  assert.ok(
    guard.sources.get(logPath).lineStart > cursorAfterFull,
    '游标必须只进不退（回退即意味着重扫历史）',
  )
})

await testAsync('纯文本：文件被截断后不得重扫已扫描过的内容', async () => {
  const logPath = join(tmp, 'shrink.log')
  writeFileSync(logPath, '第一行含 cordis_define\n', 'utf8')

  const fake = makeFakeCtx()
  const guard = new LogGuard(
    fake.ctx,
    normalizeConfig({
      files: [logPath],
      watchSessionLogs: false,
      alertFile: null,
      printToHostConsole: false,
      scanExisting: true,
    }),
  )
  guard.tick()
  assert.ok(guard.unackedList().alerts.some((a) => a.ruleId === 'cordis-define'), '首次应命中')
  guard.acknowledgeAlerts()

  // 截断到更短（模拟轮转/半行写入回退）：游标必须被夹住，不得回退重扫
  writeFileSync(logPath, '第一行含 cordis_\n', 'utf8')
  guard.tick()
  assert.ok(
    !guard.unackedList().alerts.some((a) => a.ruleId === 'cordis-define'),
    '截断后不得把已扫描过的内容再报一遍',
  )
})

await testAsync('默认忽略"自己"的会话日志（避免自我触发）', async () => {
  const sessionsRoot = join(tmp, 'sessions-self')
  const ownDir = join(sessionsRoot, '--C-slug--', 'session-OWNSELF')
  const otherDir = join(sessionsRoot, '--C-slug--', 'session-OTHER')
  mkdirSync(ownDir, { recursive: true })
  mkdirSync(otherDir, { recursive: true })
  const own = join(ownDir, 'session.v4.jsonl.zstd')
  const other = join(otherDir, 'session.v4.jsonl.zstd')
  // 夹具必须是**真实工具调用**：默认审计面只覆盖 tool/call，
  // 纯文本里的敏感词按设计不再告警（见「只审计工具调用」）。
  const { zstdCompressSync } = await import('node:zlib')
  const callFrame = (name) =>
    zstdCompressSync(
      Buffer.from(`${JSON.stringify({ type: 'tool/call', data: { name, arguments: '{}' } })}\n`, 'utf8'),
    )
  const mkLog = (sessionId) =>
    Buffer.concat([
      zstdCompressSync(Buffer.from(`${JSON.stringify({ type: 'session', version: 4, id: sessionId })}\n`, 'utf8')),
      callFrame('cordis_define'),
    ])
  writeFileSync(own, mkLog('session-OWNSELF'))
  writeFileSync(other, mkLog('session-OTHER'))

  const fake = makeFakeCtx()
  const guard = new LogGuard(
    fake.ctx,
    normalizeConfig({
      watchSessionLogs: true,
      sessionDir: sessionsRoot,
      alertFile: null,
      printToHostConsole: false,
      scanExisting: true,
      ignoreSessionIds: ['session-OWNSELF'],
    }),
  )
  assert.equal(guard.isIgnoredSession(own), true, '自身/名单内会话必须被识别为忽略')
  assert.equal(guard.isIgnoredSession(other), false, '其它会话不应被忽略')

  guard.tick()
  const labels = guard.unackedList().alerts.map((a) => a.sources.join(','))
  assert.ok(
    !labels.some((l) => l.includes('OWNSELF')),
    `不得扫描自身会话，实际来源：${labels.join(' | ')}`,
  )
  assert.ok(
    labels.some((l) => l.includes('OTHER')),
    '其它会话仍应被正常扫描（不能因为忽略自身就整体失效）',
  )
  assert.ok((guard.stats.ignored ?? 0) >= 1, '应统计到被忽略的文件数')
})

await testAsync('回归：靠日志文件头识别自身会话（不能依赖 DSH_SESSION_ID）', async () => {
  // 起初自身识别读 process.env.DSH_SESSION_ID —— 但那是 harness 注入给 bash/pwsh
  // **子进程**的变量，Host（Electron 主进程）里根本没有。结果识别静默失效，
  // 自身会话照旧被扫描，同一批历史告警每隔一分钟重复注入。正确通道是日志第一帧的会话头。
  const { zstdCompressSync } = await import('node:zlib')
  const sessionsRoot = join(tmp, 'sessions-header')
  const ownId = 'session-HEADER-OWN'
  const otherId = 'session-HEADER-OTHER'
  const mk = (slug, id, toolName) => {
    const dir = join(sessionsRoot, slug, id)
    mkdirSync(dir, { recursive: true })
    const p = join(dir, 'session.v4.jsonl.zstd')
    writeFileSync(
      p,
      Buffer.concat([
        zstdCompressSync(Buffer.from(`${JSON.stringify({ type: 'session', version: 4, id })}\n`, 'utf8')),
        // 用真实工具调用作为"敏感操作"，而不是消息文本
        zstdCompressSync(
          Buffer.from(`${JSON.stringify({ type: 'tool/call', data: { name: toolName, arguments: '{}' } })}\n`, 'utf8'),
        ),
      ]),
    )
    return p
  }
  const own = mk('--C-slug--', ownId, 'cordis_define')
  const other = mk('--C-slug--', otherId, 'cordis_define')

  const fake = makeFakeCtx()
  // 关键：不设置 DSH_SESSION_ID，完全依赖文件头识别
  const guard = new LogGuard(
    fake.ctx,
    normalizeConfig({
      watchSessionLogs: true,
      sessionDir: sessionsRoot,
      alertFile: null,
      printToHostConsole: false,
      scanExisting: true,
      ignoreSessionIds: [ownId],
    }),
  )

  assert.equal(guard.sessionIdOfFile(own), ownId, '必须能从文件头读出会话 id')
  assert.equal(guard.sessionIdOfFile(other), otherId, '另一个文件也要能读出')
  assert.equal(guard.isIgnoredSession(own), true, '自身会话（按文件头识别）必须被忽略')
  assert.equal(guard.isIgnoredSession(other), false, '其它会话不得被忽略')

  // 事件通道：拿到活动会话 id 后自动加入忽略名单，且幂等
  const before = guard.ignoredSessionIds.size
  assert.equal(guard.noteActiveSession('session-FROM-EVENT'), true, '首次应新增')
  assert.equal(guard.noteActiveSession('session-FROM-EVENT'), false, '重复应幂等')
  assert.equal(guard.ignoredSessionIds.size, before + 1)

  guard.tick()
  const labels = guard.unackedList().alerts.map((a) => a.sources.join(','))
  assert.ok(
    !labels.some((l) => l.includes(ownId)),
    `不得扫描自身会话，实际来源：${labels.join(' | ')}`,
  )
  assert.ok(
    labels.some((l) => l.includes(otherId)),
    '其它会话仍应被扫描（修误报不能把真检测也修没）',
  )
})

await testAsync('回归：审计计数不得滞后一轮（必须在扫描之后取）', async () => {
  // 计数是 scanText → prepareScanText 递增的。最初我把 takeScanCounters() 放在
  // 扫描**之前**，于是统计永远滞后一轮：tick#1 报 0、tick#2 才报 2。
  // 这是写示例脚本时靠"审计 0 次工具调用、却报了 4 条告警"这个自相矛盾发现的。
  const logPath = join(tmp, 'counters.log')
  writeFileSync(
    logPath,
    [
      JSON.stringify({ type: 'user/message', data: { text: 'cordis_define' } }),
      JSON.stringify({ type: 'tool/call', data: { name: 'pwsh', arguments: '{}' } }),
      JSON.stringify({ type: 'tool/call', data: { name: 'cordis_define', arguments: '{}' } }),
      '',
    ].join('\n'),
    'utf8',
  )

  const fake = makeFakeCtx()
  const guard = new LogGuard(
    fake.ctx,
    normalizeConfig({
      files: [logPath],
      watchSessionLogs: false,
      alertFile: null,
      printToHostConsole: false,
      scanExisting: true,
    }),
  )

  // 第一次 tick 之后就必须有正确计数（滞后的话这里是 0）
  guard.tick()
  assert.equal(guard.auditedCalls, 2, `首轮就应报告 2 次工具调用，实际 ${guard.auditedCalls}`)
  assert.equal(guard.skippedEvents, 1, `首轮就应报告 1 个非工具事件，实际 ${guard.skippedEvents}`)
  assert.ok(guard.unackedList().alerts.length > 0, '同时应有告警（计数与实际命中不能自相矛盾）')

  // 再追加一条：计数应继续累加，而不是停在上一轮
  appendFileSync(logPath, `${JSON.stringify({ type: 'tool/call', data: { name: 'cordis_run', arguments: '{}' } })}\n`, 'utf8')
  guard.acknowledgeAlerts()
  guard.tick()
  assert.equal(guard.auditedCalls, 3, `应累加到 3，实际 ${guard.auditedCalls}`)
})

await testAsync('stop() 对"返回句柄"的定时器实现也安全', async () => {
  const logPath = join(tmp, 'handle.log')
  writeFileSync(logPath, '', 'utf8')
  // 有些实现（含测试替身）的 setInterval 返回句柄而不是 disposer。
  const handle = { id: 1, cleared: false }
  const ctx = {
    setInterval: () => handle,
    effect: (f) => {
      f()
      return () => {}
    },
    on: () => () => {},
    get: () => undefined,
  }
  const guard = new LogGuard(
    ctx,
    normalizeConfig({
      files: [logPath],
      watchSessionLogs: false,
      alertFile: null,
      printToHostConsole: false,
    }),
  )
  guard.start()
  assert.doesNotThrow(() => guard.stop(), 'stop() 不应抛异常')
  // 二次调用也应安全
  assert.doesNotThrow(() => guard.stop(), 'stop() 应可重复调用')
})

await testAsync('enabled:false 时完全不接管', async () => {
  const fake = makeFakeCtx()
  const plugin = (await import('../index.mjs')).default
  plugin.apply(fake.ctx, { enabled: false })
  assert.equal(fake.intervals.length, 0, '不应注册定时器')
  assert.equal(fake.routes.length, 0, '不应注册横幅路由')
  assert.equal(fake.subscriptions.length, 0, '不应挂生命周期钩子')
})

await testAsync('apply() 不触碰任何需要 inject 的 ctx 属性（回归：timer 服务）', async () => {
  const logPath = join(tmp, 'no-context-props.log')
  writeFileSync(logPath, '', 'utf8')

  // 真实宿主里 `ctx.setInterval` 是 timer 服务上的属性访问，Cordis 会抛
  //   cannot get property "timer" without inject
  // 导致插件 activate 直接失败。这里用 Proxy 把任何未声明服务的属性访问都变成同样的错误，
  // 只要插件碰了它，这个测试就会失败。
  const intervalHandles = []
  const realSetInterval = globalThis.setInterval
  const realClearInterval = globalThis.clearInterval
  globalThis.setInterval = (fn, ms) => {
    const handle = { fn, ms, cleared: false }
    intervalHandles.push(handle)
    return handle
  }
  globalThis.clearInterval = () => {}

  const ctx = new Proxy(
    {
      effect: (factory) => {
        factory()
        return () => {}
      },
      on: () => () => {},
      get: () => undefined,
    },
    {
      get(target, prop) {
        if (prop in target) return target[prop]
        throw new TypeError(`cannot get property "${String(prop)}" without inject`)
      },
    },
  )

  try {
    const plugin = (await import('../index.mjs')).default
    assert.doesNotThrow(() => {
      plugin.apply(ctx, {
        files: [logPath],
        watchSessionLogs: false,
        alertFile: null,
        printToHostConsole: false,
      })
    }, 'apply() 不应访问需要 inject 的 ctx 属性')
    assert.equal(intervalHandles.length, 1, '应通过全局 setInterval 启动轮询')
  } finally {
    globalThis.setInterval = realSetInterval
    globalThis.clearInterval = realClearInterval
  }
})

await testAsync('webServer 晚就绪时也能补装上横幅路由', async () => {
  const logPath = join(tmp, 'late.log')
  writeFileSync(logPath, '', 'utf8')

  // 先造一个还没有 webServer 的上下文
  const intervals = []
  const routes = []
  const listeners = []
  let hasWebServer = false
  const realSetInterval = globalThis.setInterval
  const realClearInterval = globalThis.clearInterval
  globalThis.setInterval = (fn, ms) => {
    const handle = { fn, ms }
    intervals.push(handle)
    return handle
  }
  globalThis.clearInterval = () => {}
  const ctx = {
    effect(factory) {
      factory()
      return () => {}
    },
    on(event, listener) {
      listeners.push({ event, listener })
      return () => {}
    },
    get(name) {
      if (name === 'webServer' && hasWebServer) {
        return {
          register(route) {
            routes.push(route)
            return () => {}
          },
        }
      }
      return undefined
    },
  }

  const plugin = (await import('../index.mjs')).default
  try {
    plugin.apply(ctx, {
      files: [logPath],
      watchSessionLogs: false,
      alertFile: join(tmp, 'late-alerts.jsonl'),
      printToHostConsole: false,
    })
    assert.equal(routes.length, 0, '服务未就绪时不应注册成功')

    // 服务就绪，触发配置重载事件
    hasWebServer = true
    const reload = listeners.find((l) => l.event === 'app-boot/config-reload')
    assert.ok(reload, '应挂上 app-boot/config-reload 钩子')
    reload.listener()
    assert.equal(routes.length, 4, '服务就绪后补装四个横幅路由')

    // 幂等：再触发一次不应重复注册
    reload.listener()
    assert.equal(routes.length, 4, '重复触发不应重复注册')
  } finally {
    globalThis.setInterval = realSetInterval
    globalThis.clearInterval = realClearInterval
  }
})

console.log('\n[6] blocker / jammer（执行策略）')

/** 造一个"待执行调用"。 */
function fakeCall(name, args = {}, callId = 'call-x') {
  return { name, arguments: args, callId }
}
/** 从 fake ctx 里取出注册的 waterfall 监听器。 */
function listenerFor(fake, event) {
  const s = fake.subscriptions.find((x) => x.event === event)
  return s ? s.listener : null
}

test('回归：执行策略默认关闭（不擅自改变宿主行为）', () => {
  const fake = makeFakeCtx()
  const guard = new LogGuard(fake.ctx, testConfig())
  assert.equal(guard.config.enforce.enabled, false, 'enforce.enabled 默认 false')
  assert.equal(installEnforcement(fake.ctx, guard, guard.config), 0, '未启用时应挂 0 个监听器')
  assert.equal(listenerFor(fake, 'tools/pre-execute'), null, '不应注册 pre-execute')
  assert.equal(listenerFor(fake, 'tools/post-execute'), null, '不应注册 post-execute')
  assert.deepEqual(guard.enforcementMatches(fakeCall('cordis_define')), [], '未启用时匹配恒为空')
})

test('只按工具名匹配 critical（不扫参数）', () => {
  const fake = makeFakeCtx()
  const guard = new LogGuard(fake.ctx, testConfig({ enforce: { enabled: true } }))
  assert.deepEqual(
    guard.enforcementMatches(fakeCall('cordis_define')).map((r) => r.id),
    ['cordis-define'],
  )
  assert.deepEqual(
    guard.enforcementMatches(fakeCall('cordis_run')).map((r) => r.id),
    ['cordis-run'],
  )
  // pwsh 是 high，不在默认 severities=['critical'] 内
  assert.deepEqual(guard.enforcementMatches(fakeCall('pwsh')), [], '非 critical 不拦')
  // 默认不扫参数：write 内容含 cordis_define 不应命中（否则编辑本插件会被自己拦住）
  assert.deepEqual(
    guard.enforcementMatches(fakeCall('write', { content: 'cordis_define 与 cordis_run' })),
    [],
    '默认不扫参数，避免误拦写文件',
  )
})

test('enforceArguments 打开后才按参数匹配', () => {
  const fake = makeFakeCtx()
  const guard = new LogGuard(
    fake.ctx,
    testConfig({ enforce: { enabled: true, enforceArguments: true } }),
  )
  const hit = guard.enforcementMatches(fakeCall('write', { content: '调用 cordis_define' }))
  assert.ok(hit.some((r) => r.id === 'cordis-define'), '打开后参数命中应生效')
})

test('severities / rules 过滤生效', () => {
  const fake = makeFakeCtx()
  const highGuard = new LogGuard(fake.ctx, testConfig({ enforce: { enabled: true, severities: ['high'] } }))
  assert.deepEqual(
    highGuard.enforcementMatches(fakeCall('pwsh')).map((r) => r.id),
    ['tool-pwsh'],
    'severities=high 时应命中 pwsh',
  )
  assert.deepEqual(highGuard.enforcementMatches(fakeCall('cordis_define')), [], 'critical 此时不在范围内')

  const onlyOne = new LogGuard(fake.ctx, testConfig({ enforce: { enabled: true, rules: ['cordis-run'] } }))
  assert.deepEqual(onlyOne.enforcementMatches(fakeCall('cordis_define')), [], 'rules 白名单外不匹配')
  assert.deepEqual(
    onlyOne.enforcementMatches(fakeCall('cordis_run')).map((r) => r.id),
    ['cordis-run'],
  )
})

await testAsync('blocker=ask：命中返回 ask 且带中英 displayReason', async () => {
  const fake = makeFakeCtx()
  const guard = new LogGuard(fake.ctx, testConfig({ enforce: { enabled: true, blocker: 'ask' } }))
  const installed = installEnforcement(fake.ctx, guard, guard.config)
  assert.equal(installed, 2, 'blocker + jammer 各挂一个')

  const listener = listenerFor(fake, 'tools/pre-execute')
  assert.ok(listener, '应注册 tools/pre-execute')

  let nextCalls = 0
  const decision = await listener(fakeCall('cordis_define', {}, 'call-ask'), async () => {
    nextCalls++
    return { kind: 'allow' }
  })
  assert.equal(decision.kind, 'ask', '应返回 ask')
  assert.ok(decision.reason.includes('cordis-define'), 'reason 应点名规则')
  assert.equal(typeof decision.displayReason.en, 'string')
  assert.equal(typeof decision.displayReason.zh, 'string')
  assert.equal(nextCalls, 0, '命中时不应再委托 next()')

  // 未命中必须委托，否则会吞掉所有其它工具调用
  const allow = await listener(fakeCall('read', {}, 'call-ok'), async () => {
    nextCalls++
    return { kind: 'allow' }
  })
  assert.equal(allow.kind, 'allow')
  assert.equal(nextCalls, 1, '未命中必须调用 next()')
})

await testAsync('blocker=deny / cancel / off 的行为', async () => {
  for (const [action, expected] of [
    ['deny', 'deny'],
    ['cancel', 'cancel'],
  ]) {
    const fake = makeFakeCtx()
    const guard = new LogGuard(fake.ctx, testConfig({ enforce: { enabled: true, blocker: action } }))
    installEnforcement(fake.ctx, guard, guard.config)
    const decision = await listenerFor(fake, 'tools/pre-execute')(
      fakeCall('cordis_run', {}, 'call-' + action),
      async () => ({ kind: 'allow' }),
    )
    assert.equal(decision.kind, expected, `blocker=${action} 应返回 ${expected}`)
  }

  // blocker=off：不应注册 pre-execute，但仍应注册 jammer
  const fake = makeFakeCtx()
  const guard = new LogGuard(fake.ctx, testConfig({ enforce: { enabled: true, blocker: 'off' } }))
  const installed = installEnforcement(fake.ctx, guard, guard.config)
  assert.equal(installed, 1, '只挂 jammer')
  assert.equal(listenerFor(fake, 'tools/pre-execute'), null, 'blocker=off 不注册 pre-execute')
  assert.ok(listenerFor(fake, 'tools/post-execute'), 'jammer 仍应注册')
})

await testAsync('jammer=block：命中返回 block + feedback，未命中委托', async () => {
  const fake = makeFakeCtx()
  const guard = new LogGuard(fake.ctx, testConfig({ enforce: { enabled: true, jammer: 'block' } }))
  installEnforcement(fake.ctx, guard, guard.config)
  const listener = listenerFor(fake, 'tools/post-execute')
  assert.ok(listener, '应注册 tools/post-execute')

  const decision = await listener(
    fakeCall('cordis_define', {}, 'call-jam'),
    { isError: false, value: { leaked: 'real-output' }, content: [{ type: 'text', text: '真实输出' }] },
    async () => ({ kind: 'accept' }),
  )
  assert.equal(decision.kind, 'block', '应返回 block')
  assert.ok(Array.isArray(decision.feedback) && decision.feedback.length > 0, 'feedback 不能为空')
  assert.equal(decision.feedback[0].type, 'text')
  assert.ok(decision.feedback[0].text.includes('已阻断'), '反馈应说明已阻断')
  assert.ok(!decision.feedback[0].text.includes('real-output'), '反馈不得泄漏真实结果')

  // 未命中必须委托
  let delegated = 0
  const accept = await listener(fakeCall('read'), { isError: false, value: 1, content: [] }, async () => {
    delegated++
    return { kind: 'accept' }
  })
  assert.equal(accept.kind, 'accept')
  assert.equal(delegated, 1, '未命中必须调用 next()')
})

await testAsync('拦截/阻断会进入告警队列（用户看得见）', async () => {
  const fake = makeFakeCtx()
  const guard = new LogGuard(
    fake.ctx,
    testConfig({ enforce: { enabled: true, blocker: 'deny', jammer: 'off' }, notifySound: false }),
  )
  installEnforcement(fake.ctx, guard, guard.config)
  const before = guard.unackedList().alerts.length
  await listenerFor(fake, 'tools/pre-execute')(fakeCall('cordis_define', {}, 'call-alert'), async () => ({
    kind: 'allow',
  }))
  const after = guard.unackedList().alerts
  assert.ok(after.length > before, '拦截应产生告警')
  const hit = after.find((a) => a.ruleId === 'cordis-define')
  assert.ok(hit, '告警里应有 cordis-define')
  assert.ok(hit.description.includes('拦截'), `描述应标明拦截，实际: ${hit.description}`)
  assert.deepEqual(hit.sources, ['tool:cordis_define'], '来源应标出是哪个工具')
})

console.log('\n[5] 规则集概览')
console.log(
  `  默认规则 ${DEFAULT_RULES.length} 条：` +
    DEFAULT_RULES.map((r) => `${r.id}(${r.severity})`).join(', '),
)

rmSync(tmp, { recursive: true, force: true })

console.log(`\n结果：${passed} 通过，${failed} 失败\n`)
if (failed > 0) {
  for (const failure of failures) console.error(`- ${failure.name}: ${failure.error?.stack ?? failure.error}`)
  process.exitCode = 1
}
