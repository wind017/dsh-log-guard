/**
 * 真告警验证（离线，不写进任何真实会话日志，因此不会污染对话）。
 *
 * 验证三件事：
 *   A. 自身会话（按文件头识别）被忽略 —— 不再自我触发
 *   B. 其它会话里的**真实工具调用**照样被检测到 —— 没把真检测修没
 *   C. 只扫描新增内容，历史不重扫
 */
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs'
import { zstdCompressSync } from 'node:zlib'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { isolate } from './_isolation.mjs'

const m = await import(pathToFileURL(join(import.meta.dirname, '..', 'index.mjs')).href)
const { LogGuard, normalizeConfig } = m

const frame = (obj) => zstdCompressSync(Buffer.from(`${JSON.stringify(obj)}\n`, 'utf8'))
const ctx = { effect: (f) => { f(); return () => {} }, on: () => () => {}, get: () => undefined }

const ownId = 'session-OWN'
const otherId = 'session-OTHER'

// 造一个会话目录：一个"自己"、一个"别人"，两者都含有敏感词
const root = mkdtempSync(join(tmpdir(), 'log-guard-live-'))
const mkSession = (id) => {
  const dir = join(root, '--C-slug--', id)
  const p = join(dir, 'session.v4.jsonl.zstd')
  return { dir, p }
}
const own = mkSession(ownId)
const other = mkSession(otherId)
for (const s of [own, other]) {
  const { mkdirSync } = await import('node:fs')
  mkdirSync(s.dir, { recursive: true })
  writeFileSync(
    s.p,
    Buffer.concat([
      frame({ type: 'session', version: 4, id: s === own ? ownId : otherId }),
    ]),
  )
}

const guard = new LogGuard(
  ctx,
  normalizeConfig({
      ...isolate(),
    watchSessionLogs: true,
    sessionDir: root,
    alertFile: join(root, 'alerts.jsonl'),
    printToHostConsole: false,
    scanExisting: false,
    ignoreSessionIds: [ownId],
  }),
)
guard.tick()

console.log('A. 自身会话是否被忽略')
console.log(`   文件头识别自身 = ${guard.sessionIdOfFile(own.p)}`)
console.log(`   isIgnoredSession(自己) = ${guard.isIgnoredSession(own.p)}`)
console.log(`   isIgnoredSession(别人) = ${guard.isIgnoredSession(other.p)}`)

console.log('\nB. 往两边各追加一条**真实工具调用**，看谁会被报')
// 自己：模拟本次对话里提到 cordis_define（应当被忽略）
writeFileSync(
  own.p,
  Buffer.concat([
    readFileSync(own.p),
    frame({ type: 'user/message', data: { text: '我们来讨论 cordis_define 和 subprocess' } }),
    frame({ type: 'tool/call', data: { name: 'cordis_define', arguments: '{}' } }),
  ]),
)
// 别人：一条真实的敏感操作（应当被报）
writeFileSync(
  other.p,
  Buffer.concat([
    readFileSync(other.p),
    frame({ type: 'tool/call', data: { name: 'cordis_define', arguments: '{"code":"..."}' } }),
    frame({ type: 'tool/call', data: { name: 'subprocess', arguments: '{"command":"whoami"}' } }),
  ]),
)

guard.tick()
const hits = guard.unackedList().alerts.map((a) => ({ rule: a.ruleId, src: a.sources.join(',') }))
console.log('   命中:')
for (const h of hits) console.log(`     - ${h.rule}  ← ${h.src}`)

const fromOwn = hits.filter((h) => h.src.includes(ownId))
const fromOther = hits.filter((h) => h.src.includes(otherId))
console.log(`\n   来自自身的告警: ${fromOwn.length} 条（必须为 0）`)
console.log(`   来自别人的告警: ${fromOther.length} 条（必须 >0）`)

console.log('\nC. 再 tick 一次（无新增），不应重复告警')
const before = guard.unackedList().alerts.length
guard.acknowledgeAlerts()
guard.tick()
console.log(`   重复告警: ${guard.unackedList().alerts.length} 条（必须为 0）`)

console.log('\n--- 横幅将收到的告警预览 ---')
writeFileSync(
  other.p,
  Buffer.concat([
    readFileSync(other.p),
    frame({ type: 'tool/call', data: { name: 'cordis_run', arguments: '{}' } }),
  ]),
)
guard.tick()
for (const a of guard.unackedList().alerts) console.log(`     [${a.severity}] ${a.ruleId} :: 命中「${a.matched}」`)

rmSync(root, { recursive: true, force: true })

const ok = fromOwn.length === 0 && fromOther.length > 0 && before > 0
console.log(`\n结论: ${ok ? '通过 —— 自身被忽略，他人的真实敏感操作仍会被显性告警' : '失败'}`)
if (!ok) process.exitCode = 1
