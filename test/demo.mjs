/**
 * 示例验证：构造一份样本日志，跑**插件自己的代码**，把四条告警通道的实际输出打出来。
 *
 * 运行： node test/demo.mjs
 *
 * 它证明的不是"我以为会这样"，而是"插件真的会这样输出"。样本用真实的 DSH 事件形态：
 *   - user/message    对话里提到敏感词          → 期望：静默
 *   - tool/result     工具返回体列出工具名      → 期望：静默
 *   - system/message  系统提示里的敏感字样      → 期望：静默
 *   - tool/call       真实调用 pwsh            → 期望：告警
 *   - tool/call       真实调用 cordis_define   → 期望：告警（critical）
 *   - tool/call       真实调用 subprocess      → 期望：告警
 *   - 纯文本行        非 JSONL 日志            → 期望：按文本审计
 */
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { isolate } from './_isolation.mjs'

const m = await import(pathToFileURL(join(import.meta.dirname, '..', 'index.mjs')).href)
const { LogGuard, normalizeConfig } = m

// 用来捕获插件往宿主 stderr 打的告警行（这正是你在宿主日志里会看到的东西）
const captured = []
const realWrite = process.stderr.write.bind(process.stderr)
process.stderr.write = (chunk, ...rest) => {
  const text = String(chunk)
  if (text.includes('[DSH-LOG-GUARD]')) {
    captured.push(text.replace(/\u001b\[[0-9;]*m/g, '').trimEnd())
    return true
  }
  return realWrite(chunk, ...rest)
}

const tmp = mkdtempSync(join(tmpdir(), 'log-guard-demo-'))
const logPath = join(tmp, 'session.v4.jsonl.zstd')
const alertPath = join(tmp, 'alerts.jsonl')

const L = (obj) => JSON.stringify(obj)
/** 样本：一半是"不该报的"，一半是"该报的" */
const SAMPLE = [
  // ---- 应当静默 ----
  L({ type: 'user/message', data: { text: '帮我写个监听 cordis_define 和 subprocess 的插件' } }),
  L({ type: 'assistant/message', data: { content: [{ type: 'text', text: 'cordis_run 会执行动态代码' }] } }),
  L({
    type: 'tool/result',
    data: { content: [{ type: 'text', text: 'cordis_define cordis_run subprocess danger-full-access' }] },
  }),
  L({ type: 'system/message', data: { text: 'file policy: workspace-write; sandbox 可放宽到 danger-full-access' } }),
  L({ type: 'request/context', data: { text: 'plugin_manager / deepseekAccount / cordis.yml' } }),
  // ---- 应当告警 ----
  L({
    type: 'tool/call',
    data: {
      name: 'pwsh',
      callId: 'call_demo_1',
      arguments: L({ command: 'Get-ChildItem -Recurse', description: '列出文件' }),
    },
  }),
  L({ type: 'tool/call', data: { name: 'cordis_define', callId: 'call_demo_2', arguments: '{"code":"ctx.log(...)"}' } }),
  L({ type: 'tool/call', data: { name: 'subprocess', callId: 'call_demo_3', arguments: '{"command":"whoami"}' } }),
  L({ type: 'tool/call', data: { name: 'cordis_run', callId: 'call_demo_4', arguments: '{}' } }),
  // ---- 纯文本日志（非 JSONL）----
  '2026-01-01 12:00:00 WARN 外部脚本调用了 rm -rf 与 spawn',
]

writeFileSync(logPath, `${SAMPLE.join('\n')}\n`, 'utf8')

const ctx = { effect: (f) => { f(); return () => {} }, on: () => () => {}, get: () => undefined }
const guard = new LogGuard(
  ctx,
  normalizeConfig({
      ...isolate(),
    files: [logPath],
    watchSessionLogs: false,
    alertFile: alertPath,
    printToHostConsole: true, // 打开，才能看到 stderr 通道
    scanExisting: true, // 扫描样本内容（演示用；线上默认 false 只看新增）
    notifySound: false,
  }),
)

console.log('='.repeat(72))
console.log('样本日志（' + SAMPLE.length + ' 行）')
console.log('='.repeat(72))
for (const [i, line] of SAMPLE.entries()) {
  const short = line.length > 88 ? `${line.slice(0, 85)}…` : line
  console.log(`  ${String(i + 1).padStart(2)}. ${short}`)
}

console.log('\n开始扫描…\n')
guard.tick()

const alerts = guard.unackedList().alerts
// 新语义：告警常驻未确认队列，反复读取不消费
const block = guard.unackedList().alerts

console.log('='.repeat(72))
console.log(`结果：审计 ${guard.auditedCalls} 次工具调用，排除 ${guard.skippedEvents} 个非工具事件`);
console.log(`      命中 ${alerts.length} 条告警\n`)

console.log(`【通道 1】宿主 stderr（${captured.length} 行）——你在宿主日志里会看到的`);
console.log('-'.repeat(72))
for (const line of captured) console.log('  ' + line)

console.log(`\n【通道 2】告警文件 alerts.jsonl（${existsSync(alertPath) ? readFileSync(alertPath, 'utf8').trim().split('\n').length : 0} 行）`)
console.log('-'.repeat(72))
if (existsSync(alertPath)) {
  for (const line of readFileSync(alertPath, 'utf8').trim().split('\n')) {
    const o = JSON.parse(line)
    console.log(`  ${o.time}  [${o.severity}]  ${o.ruleId}`)
    console.log(`      来源: ${o.sources.join(',')}`)
    console.log(`      命中: ${String(o.matched).slice(0, 90)}`)
  }
} else {
  console.log('  (未生成)')
}

console.log('\n【通道 3】UI 告警横幅（alerts.json 返回给页面 banner 的内容）')
console.log('-'.repeat(72))
if (block.length === 0) console.log('  (无)')
else for (const a of block) console.log(`  [${a.severity}] ${a.ruleId} :: 命中「${a.matched}」`)

console.log('\n【通道 4】蜂鸣/弹窗：本次 notifySound=false，未触发')
console.log('           置 notifySound: true 时会响三声并弹一个系统提示框。')

console.log('\n' + '='.repeat(72))
console.log('命中明细（逐条核对"该报的报了、不该报的没报"）')
console.log('='.repeat(72))
for (const a of alerts) {
  console.log(`  [${a.severity}] ${a.ruleId.padEnd(20)} ${a.snippet.slice(0, 70)}`)
}

// 断言：该报的都在、不该报的都不在
// 注意 shell-command 来自**最后那行纯文本日志**（含 `spawn`）——纯文本日志按设计
// 始终按文本审计，不受"只审计工具调用"限制。它不是误报，是另一条预期路径。
const EXPECTED = ['tool-pwsh', 'cordis-define', 'subprocess-service', 'cordis-run', 'shell-command']
const got = new Set(alerts.map((a) => a.ruleId))
console.log('\n该报的规则是否都命中：')
let ok = true
for (const rule of EXPECTED) {
  const hit = got.has(rule)
  if (!hit) ok = false
  console.log(`  ${hit ? '✓' : '✗'} ${rule}`)
}
const unexpected = [...got].filter((r) => !EXPECTED.includes(r))
console.log('是否有预期外的命中：')
if (unexpected.length === 0) console.log('  ✓ 无')
else {
  ok = false
  console.log(`  ✗ ${unexpected.join(', ')}`)
}
console.log('对话/结果/系统提示里的敏感词是否静默：')
console.log(`  ${got.has('cordis-define') ? '(见上方 cordis-define，它来自真实调用)' : ''}`)
console.log(`  审计了 ${guard.auditedCalls} 次工具调用，排除 ${guard.skippedEvents} 个非工具事件`)
// 样本里 5 个非工具事件应被排除
if (guard.skippedEvents === 5) console.log('  ✓ 5 个非工具事件（3 类消息 + 结果 + 上下文）已排除')
else {
  ok = false
  console.log(`  ✗ 期望排除 5 个非工具事件，实际 ${guard.skippedEvents}`)
}

process.stderr.write = realWrite
rmSync(tmp, { recursive: true, force: true })

const pass = ok && alerts.length === EXPECTED.length
console.log(`\n结论：${pass ? '通过' : '见上方标记'}`)
if (!pass) process.exitCode = 1
