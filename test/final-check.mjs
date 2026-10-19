/**
 * 最终端到端核验：用**完全默认**配置（与线上将跑的配置一致）驱动。
 * 离线运行，不连接宿主。
 * 运行： node test/final-check.mjs
 */
import { mkdtempSync, writeFileSync, appendFileSync, existsSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir, homedir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { isolate } from './_isolation.mjs'

const mod = await import(pathToFileURL(join(import.meta.dirname, '..', 'index.mjs')).href)
const { LogGuard, normalizeConfig } = mod

const ctx = { effect: (f) => { f(); return () => {} }, on: () => () => {}, get: () => undefined }

console.log('=== A. 真实默认配置下的会话日志发现 ===')
const realCfg = normalizeConfig({
      ...isolate(), printToHostConsole: false, alertFile: null })
console.log('  sessionDir        :', realCfg.sessionDir)
console.log('  watchSessionLogs  :', realCfg.watchSessionLogs)
console.log('  sessionFileNames  :', JSON.stringify(realCfg.sessionFileNames))
console.log('  最大深度          :', realCfg.maxSessionScanDepth)
const realGuard = new LogGuard(ctx, realCfg)
realGuard.tick()
console.log('  发现会话日志      :', realGuard.sessionFilesFound, '个（修复前是 0，因为路径拼错）')
console.log('  实际监控文件数    :', realGuard.stats.files)
if (realGuard.sessionFilesFound === 0) {
  console.log('  ✗ 没发现任何日志 —— 插件等于没在工作')
  process.exitCode = 1
}

console.log('\n=== B. 默认配置下的告警流转（drainAlerts 供 UI 横幅拉取）===')
// 默认 scanExisting=false，所以先建立游标再模拟增量
const tmp = mkdtempSync(join(tmpdir(), 'log-guard-final-'))
const logPath = join(tmp, 'session.v4.jsonl.zstd')
writeFileSync(logPath, '', 'utf8')
const alertFile = join(tmp, 'alerts.jsonl')

const cfg = normalizeConfig({
      ...isolate(),
  printToHostConsole: false,
  watchSessionLogs: false,
  files: [logPath],
  alertFile,
})
const guard = new LogGuard(ctx, cfg)

guard.tick()
console.log('  启动时 pending    :', guard.unackedList().alerts.length, '（scanExisting=false 应为 0）')

appendFileSync(logPath, '{"type":"tool/call","data":{"name":"cordis_run","arguments":"{}"}}\n', 'utf8')
guard.tick()
const drained = guard.unackedList().alerts
console.log('  命中规则          :', drained.map((a) => a.ruleId).join(', ') || '(无)')
console.log('  告警文件已写入    :', existsSync(alertFile))
console.log('  未确认队列（读取不消费）:', guard.unackedList().alerts.length, '（应仍为 1）')
if (drained.length === 0) {
  console.log('  ✗ 告警没有产生')
  process.exitCode = 1
}
console.log('\n--- 横幅将收到的告警（第 1 条）---')
console.log(JSON.stringify(drained[0] ?? null).slice(0, 200))

console.log('\n--- 告警文件内容 ---')
console.log(readFileSync(alertFile, 'utf8').trim().slice(0, 300))

rmSync(tmp, { recursive: true, force: true })
console.log('\n核验结束。')
