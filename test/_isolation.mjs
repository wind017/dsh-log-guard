/**
 * 测试脚本共用的状态隔离。
 *
 * 为什么需要：插件的状态文件（`alertFile` / `notifyLog` / `ignoredStateFile` /
 * `unackedStateFile`）默认落在用户的 `$DSH_HOME/log-guard/` 下。验收脚本若用默认值，
 * 就会**往用户真实目录里写文件**（实测报 `EPERM … unacked-alerts.json`）。
 * 这里把三项可变状态重定向到一次性临时目录；进程退出时自动清理。
 */
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const root = mkdtempSync(join(tmpdir(), 'log-guard-iso-'))
let seq = 0

/** 分配一个独立的状态目录（每次调用一个，避免脚本内互相污染）。 */
export function stateDir() {
  const dir = join(root, `s${++seq}`)
  mkdirSync(dir, { recursive: true })
  return dir
}

/** 返回可展开进 `normalizeConfig({...})` 的隔离字段。 */
export function isolate() {
  const dir = stateDir()
  return {
    // alertFile 也必须隔离：它默认落在用户的 $DSH_HOME/log-guard/ 下。
    // 曾经漏掉它 —— 实测 stderr 显示脚本把告警写进了真实目录。
    alertFile: join(dir, 'alerts.jsonl'),
    notifyLog: join(dir, 'notify.log'),
    ignoredStateFile: join(dir, 'ignored-sessions.json'),
    unackedStateFile: join(dir, 'unacked-alerts.json'),
  }
}

process.on('exit', () => {
  try {
    rmSync(root, { recursive: true, force: true })
  } catch {
    /* 清理失败不影响验收结论 */
  }
})
