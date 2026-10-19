/**
 * 对**真实会话日志**对比两种审计面，验证"只审计工具调用"的效果。
 * 重点看：同一份日志、同一个会话（含本次对话），噪声掉了多少、真调用还在不在。
 *
 * 运行： node test/real-log-compare.mjs
 */
import { join } from 'node:path'
import { homedir } from 'node:os'
import { readdirSync, statSync, readFileSync as fsReadFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
import { isolate } from './_isolation.mjs'

const m = await import(pathToFileURL(join(import.meta.dirname, '..', 'index.mjs')).href)
const { LogGuard, normalizeConfig } = m

const ctx = { effect: (f) => { f(); return () => {} }, on: () => () => {}, get: () => undefined }

/**
 * 自身识别有三条通道，其中 `process.env.DSH_SESSION_ID` **没有配置开关**：
 * harness 会把它注入给工具子进程，所以从这里跑脚本时它是**存在的**。
 * 本脚本要"故意连自身会话一起审计"，因此必须临时摘掉它，否则被静默跳过、对比失真。
 */
const savedSessionEnv = process.env.DSH_SESSION_ID
delete process.env.DSH_SESSION_ID

/** 用指定审计面全量扫一遍真实会话日志，返回命中分布。 */
function scanAll(audit) {
  const guard = new LogGuard(
    ctx,
    normalizeConfig({
      ...isolate(),
      alertFile: null,
      printToHostConsole: false,
      scanExisting: true,
      audit,
      // 本脚本要"故意连自身会话一起审计"来对比噪声，所以必须隔离掉持久化的自身忽略状态
      //（否则会继承 <DSH_HOME>/log-guard/ignored-sessions.json，把自身会话跳过，对比就失真）。
      ignoredStateFile: null,
      ignoreSessionIds: [],
    }),
  )
  guard.tick()
  const byRule = {}
  for (const a of guard.unackedList().alerts) byRule[a.ruleId] = (byRule[a.ruleId] ?? 0) + 1
  return { total: guard.unackedList().alerts.length, byRule, files: guard.sessionFilesFound, audited: guard.auditedCalls, skipped: guard.skippedEvents }
}

console.log('会话目录:', join(homedir(), '.dsh', 'sessions'))
console.log('（离线诊断：忽略名单为空，全部会话日志都会扫）\n')

const all = scanAll('all-text')
const tools = scanAll('tool-calls')

console.log('审计面           命中总数   已审计调用   跳过事件')
console.log(`all-text        ${String(all.total).padStart(8)}   ${String(all.audited).padStart(10)}   ${String(all.skipped).padStart(8)}`)
console.log(`tool-calls      ${String(tools.total).padStart(8)}   ${String(tools.audited).padStart(10)}   ${String(tools.skipped).padStart(8)}`)

console.log('\nall-text 的命中分布（旧行为，噪声大）：')
for (const [k, v] of Object.entries(all.byRule).sort((a, b) => b[1] - a[1])) console.log(`   ${k.padEnd(22)} ${v}`)

console.log('\ntool-calls 的命中分布（新默认）：')
for (const [k, v] of Object.entries(tools.byRule).sort((a, b) => b[1] - a[1])) console.log(`   ${k.padEnd(22)} ${v}`)

console.log(`\n噪声下降: ${all.total} → ${tools.total} 条（减少 ${all.total - tools.total} 条，` +
  `${all.total > 0 ? Math.round((1 - tools.total / all.total) * 100) : 0}%）`)
console.log(tools.audited > 0
  ? `真调用仍被审计: ${tools.audited} 条工具调用进入审计面 —— 检测能力没有丢`
  : '警告: 没有任何工具调用被审计，检测面可能被砍空了')

// ---------------------------------------------------------------------------
// 决定性对比：**本次对话所在的日志**（就是当初引发 11 条误报循环的那一个）
// ---------------------------------------------------------------------------
console.log('\n' + '='.repeat(64))
console.log('决定性对比：一份真实会话日志（当初引发 11 条误报循环的那类文件）')
console.log('='.repeat(64))

const root = join(homedir(), '.dsh', 'sessions')
// 刻意**不写死任何会话 id**：按体积取最大的那份会话日志作为真实样本；
// 也可以显式指定任意一份：
//   node test/real-log-compare.mjs <日志绝对路径>
const forced = process.argv[2]
let ownPath = forced ?? null
let bestSize = -1
;(function walk(dir, depth) {
  if (depth < 0) return
  let entries
  try {
    entries = readdirSync(dir, { withFileTypes: true })
  } catch {
    return
  }
  for (const e of entries) {
    const full = join(dir, e.name)
    if (e.isDirectory()) {
      walk(full, depth - 1)
    } else if (full.endsWith('.zstd')) {
      let size = 0
      try {
        size = statSync(full).size
      } catch {
        continue
      }
      if (forced === undefined && size > bestSize) {
        bestSize = size
        ownPath = full
      }
    }
  }
})(root, 3)

if (ownPath === null) {
  console.log('（未找到本次对话的日志，跳过）')
} else {
  console.log('日志:', ownPath.replace(homedir(), '~'))
  console.log('大小:', (statSync(ownPath).size / 1048576).toFixed(2), 'MB\n')
  for (const audit of ['all-text', 'tool-calls']) {
    const g = new LogGuard(
      ctx,
      normalizeConfig({
      ...isolate(),
        alertFile: null,
        printToHostConsole: false,
        scanExisting: true,
        audit,
        files: [ownPath],
        watchSessionLogs: false,
        // 这里就是专门要审计"自身会话"，不能被持久化忽略状态挡掉。
        ignoredStateFile: null,
        ignoreSessionIds: [],
      }),
    )
    g.tick()
    const byRule = {}
    for (const a of g.unackedList().alerts) byRule[a.ruleId] = (byRule[a.ruleId] ?? 0) + 1
    console.log(
      `  audit=${audit.padEnd(11)} 命中 ${String(g.unackedList().alerts.length).padStart(3)} 条  ` +
        `已审计调用 ${String(g.auditedCalls).padStart(4)}  ${JSON.stringify(byRule)}`,
    )
  }

  // 追根：这 11 条到底是"消息文本"造成的，还是"工具调用参数"造成的？
  console.log('\n逐条看命中来源（判断只审计工具调用到底省掉了什么）：')
  const g = new LogGuard(
    ctx,
    normalizeConfig({
      ...isolate(),
      alertFile: null,
      printToHostConsole: false,
      scanExisting: true,
      audit: 'all-text',
      files: [ownPath],
      watchSessionLogs: false,
      ignoredStateFile: null,
      ignoreSessionIds: [],
    }),
  )
  const source = fsReadFileSync(ownPath)
  g.tick()
  const hits = g.unackedList().alerts
  for (const h of hits) {
    const snippet = h.snippet.slice(0, 100).replace(/\s+/g, ' ')
    // 判断这条命中所在的上下文是不是 tool/call
    const fromToolCall = /"type":"tool\/call"|"type":"tool-call"/.test(h.snippet)
    console.log(`   ${h.ruleId.padEnd(20)} 来自工具调用=${fromToolCall ? '是' : '否 '}  ${snippet}`)
  }
  const toolOrigin = hits.filter((h) => /"type":"tool\/call"|"type":"tool-call"/.test(h.snippet)).length
  console.log(`\n   其中来自工具调用: ${toolOrigin} 条；来自消息/其它文本: ${hits.length - toolOrigin} 条`)
  void source
}

// 恢复环境变量（本进程内的还原；脚本即将退出，属良好习惯）
if (savedSessionEnv !== undefined) process.env.DSH_SESSION_ID = savedSessionEnv
