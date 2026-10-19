/**
 * @file dsh-log-guard — DSH Host 插件
 *
 * 职责：定时监听（tail）日志文件，每次检测到新追加的内容时，用规则集扫描
 * `cordis_define` / `cordis_run` / `subprocess` / `pwsh` 等敏感操作，命中后发出
 * **显性告警**：
 *
 *   1. UI 告警横幅 —— 通过 `webserver/index-inject` 往界面注入脚本，命中后在页面
 *      右上角弹出 banner。这是用户真正"看得见"的通道。
 *   2. 告警文件 —— 追加写入 JSONL（默认 `<DSH_HOME>/log-guard/alerts.jsonl`）。
 *   3. 宿主 stderr —— 打一条带醒目前缀的行，宿主/终端侧可见。
 *   4. 可选蜂鸣 —— `notifySound: true` 时播放告警音。
 *
 * 解码支持两类日志：
 *   - 纯文本（一行一条 JSON / 普通文本）
 *   - DSH 会话日志 `session.v4.jsonl.zstd`：**多帧拼接**的 zstd，必须逐帧解压
 *     （Node 内置 `zstdDecompressSync` 只解第一帧，所以这里自行切帧）。
 *
 * @module dsh-log-guard
 */
import { readFileSync, writeFileSync, statSync, appendFileSync, mkdirSync, readdirSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join, resolve, basename } from 'node:path'
import { homedir } from 'node:os'

const require = createRequire(import.meta.url)
const zlib = require('node:zlib')

/** zstd 帧魔数：28 B5 2F FD。 */
const ZSTD_MAGIC = Buffer.from([0x28, 0xb5, 0x2f, 0xfd])

/**
 * 会话目录默认递归深度。
 * 真实布局 `<root>/<workspace-slug>/<session-id>/<file>` 需要 2 层；
 * 取 3 是留一层余量（例如中间多一层项目分组目录），同时避免无节制递归。
 */
const DEFAULT_SESSION_SCAN_DEPTH = 3

/** 单次扫描最多解压/读取的字节数，避免超大日志把宿主拖死。 */
const MAX_READ_BYTES = 64 * 1024 * 1024

/** 解码后保留在内存中的文本上限；超出后从最旧处裁剪（游标随之前移）。 */
const MAX_TEXT_BYTES = 1 * 1024 * 1024

/** 裁剪步长。 */
const TRIM_STEP = 256 * 1024

/** 连续多少字节仍没有换行时，也强行扫描一次（防御非 JSONL 的长行日志）。 */
const MAX_HOLD_BYTES = 256 * 1024

/** 单条告警里摘录片段的最大长度。 */
const SNIPPET_MAX = 240

/** stderr 告警前缀（醒目，便于 grep）。 */
const STDERR_PREFIX = '\u001b[41;97m[DSH-LOG-GUARD]\u001b[0m'

// ---------------------------------------------------------------------------
// 规则集：什么算"敏感操作"
// ---------------------------------------------------------------------------

/**
 * 默认规则集。每条规则要么是 `pattern`（正则），要么是 `tool`（精确匹配日志里
 * `tool/call` 事件的工具名）。宁可多报，不可漏报 —— 这是安全工具。
 */
const DEFAULT_RULES = Object.freeze([
  {
    id: 'cordis-define',
    severity: 'critical',
    pattern: /cordis_define/,
    description: '动态 Cordis 包定义：把一段新代码注入运行中的插件注册表（沙箱非安全边界）。',
  },
  {
    id: 'cordis-run',
    severity: 'critical',
    pattern: /cordis_run/,
    description: '动态 Cordis 包运行：在宿主 node:vm 中执行动态插件代码，其声明的服务会触达真实运行时。',
  },
  {
    id: 'cordis-toolset',
    severity: 'high',
    pattern: /cordis_(inspect|stop|undefine|list|panel)/,
    description: '动态 Cordis 工具集调用：在检查/停止/移除动态插件定义。',
  },
  {
    id: 'subprocess-service',
    severity: 'high',
    pattern: /subprocess/,
    description: '子进程服务相关操作：在宿主上派生外部进程。',
  },
  {
    id: 'tool-pwsh',
    severity: 'high',
    tool: 'pwsh',
    description: 'PowerShell 命令执行：可读写文件、发起网络请求、启动任意程序。',
  },
  {
    id: 'shell-command',
    severity: 'high',
    pattern: /(spawn|execFile|execSync|spawnSync|child_process|CreateProcess|fork\()/,
    description: '进程创建原语：出现启动子进程的调用。',
  },
  {
    id: 'tool-run-code',
    severity: 'high',
    tool: 'run_code',
    description: '代码执行工具：在宿主进程中运行代码。',
  },
  {
    id: 'tool-workflow',
    severity: 'medium',
    tool: 'workflow',
    description: '工作流编排：批量派发子智能体。',
  },
  {
    id: 'tool-subagent',
    severity: 'medium',
    tool: 'subagent',
    description: '子智能体派生：扩大执行面。',
  },
  {
    id: 'sandbox-relax',
    severity: 'high',
    pattern: /danger-full-access/,
    description: '沙箱权限放宽到 danger-full-access：文件沙箱等于关闭。',
  },
  {
    id: 'plugin-mutation',
    severity: 'medium',
    pattern: /(plugin_manager|install_bundle|remove_bundle|set_plugin|set_bundle)/,
    description: '插件/包管理操作：会改变当前 profile 的插件拓扑。',
  },
  {
    id: 'credential-access',
    severity: 'high',
    pattern: /(\.credentials\.yaml|credentials\/record-updated|authorization\/settled|deepseekAccount)/,
    description: '凭据访问迹象：触碰账号凭据或授权流程。',
  },
  {
    id: 'network-egress',
    severity: 'low',
    pattern: /(curl\s|wget\s|Invoke-WebRequest|Invoke-RestMethod|https?:\/\/[^\s"']*)/,
    description: '网络出口：日志中出现外部 URL 或下载命令。',
  },
  {
    id: 'self-modify',
    severity: 'medium',
    pattern: /(cordis\.patch\.yml|cordis\.yml|profiles[\\/][^"'\\/]*[\\/]package\.json)/,
    description: '修改 DSH 自身的组合配置/插件清单。',
  },
])

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v)

/** 取第一个已定义的值。 */
const pick = (...values) => values.find((v) => v !== undefined && v !== null)

/** 把可能是字符串/对象的值安全转成紧凑 JSON 文本。 */
function toText(value) {
  if (typeof value === 'string') return value
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

/** 把日志里的一段原文压成单行、限长的摘录。 */
function snippetOf(text) {
  const oneLine = text.replace(/\s+/g, ' ').trim()
  return oneLine.length <= SNIPPET_MAX ? oneLine : `${oneLine.slice(0, SNIPPET_MAX - 3)}...`
}

/**
 * 以命中串为**中心**生成摘录。
 *
 * 不能简单地从"命中前 80 字符"开始截：命中串本身可能很长（工具参数就是整行 JSON），
 * 那样窗口会被前文占满、把命中串挤出可见范围 —— 实测 stderr 行里就看不到
 * `cordis_define` 到底命中在哪。这里保证命中串完整可见，前后各留一点上下文。
 *
 * @param text 被扫描的完整文本。
 * @param index 命中下标。
 * @param matched 命中串。
 * @returns 单行摘录。
 */
function snippetAround(text, index, matched) {
  const flat = text.replace(/\s+/g, ' ')
  const needle = String(matched).replace(/\s+/g, ' ')
  // 在压平后的文本里重新定位：压缩空白会改变下标，所以直接找 needle。
  const at = needle === '' ? -1 : flat.indexOf(needle)
  if (at < 0) return snippetOf(text)

  const budget = SNIPPET_MAX - 8
  const context = Math.max(20, Math.floor((budget - Math.min(needle.length, budget - 40)) / 2))
  const from = Math.max(0, at - context)
  const maxMatched = Math.max(24, budget - context * 2)
  const shownMatched = needle.length <= maxMatched ? needle : `${needle.slice(0, maxMatched - 3)}...`
  const head = from > 0 ? '...' : ''
  const body = `${head}${flat.slice(from, at)}${shownMatched}`
  const end = at + needle.length
  const tail = end < flat.length ? `${flat.slice(end, end + context)}...` : flat.slice(end, end + context)
  return snippetOf(`${body}${tail}`)
}

/** 规整化的告警指纹/键。 */
const normKey = (s) => s.replace(/\s+/g, ' ').trim().slice(0, 400).toLowerCase()

/** 简单稳定的字符串哈希。 */
function hash(text) {
  let h = 0x811c9dc5
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  return (h >>> 0).toString(16)
}

/** 把毫秒时间戳格式化为本地可读时间。 */
const stamp = (ms = Date.now()) => new Date(ms).toISOString()

// ---------------------------------------------------------------------------
// 解码：纯文本 + 多帧 zstd
// ---------------------------------------------------------------------------

/**
 * 找出缓冲区里所有 zstd 帧的起始偏移。
 * @param buf 压缩数据。
 * @returns 帧起始偏移数组（升序）。
 */
function frameStarts(buf) {
  const starts = []
  let from = 0
  for (;;) {
    const at = buf.indexOf(ZSTD_MAGIC, from)
    if (at < 0) break
    starts.push(at)
    from = at + ZSTD_MAGIC.length
  }
  return starts
}

/**
 * 逐帧解压一份多帧 zstd 日志。
 * 单帧损坏不影响其它帧：坏帧被跳过并计数。
 * @param buf 压缩数据。
 * @returns 解码文本与统计信息。
 */
function decodeZstd(buf) {
  if (typeof zlib.zstdDecompressSync !== 'function') {
    return { text: '', frames: 0, failed: 0, unsupported: true }
  }
  const starts = frameStarts(buf)
  if (starts.length === 0) return { text: '', frames: 0, failed: 0, unsupported: false }

  const parts = []
  let failed = 0
  for (let i = 0; i < starts.length; i++) {
    const end = i + 1 < starts.length ? starts[i + 1] : buf.length
    try {
      parts.push(zlib.zstdDecompressSync(buf.subarray(starts[i], end)).toString('utf8'))
    } catch {
      // 末尾可能是写到一半的帧，等下一次轮询再解。
      failed++
    }
  }
  return { text: parts.join(''), frames: starts.length - failed, failed, unsupported: false }
}

/**
 * 读取一个日志文件并解码成文本。
 *
 * zstd 文件总是整文件解码（帧边界无法从任意字节偏移切入），再靠调用方的游标
 * 只扫描新增部分；解码失败时退化为对原始字节做关键字扫描，保证"能报总比不报好"。
 *
 * @param path 绝对路径。
 * @returns 解码结果。
 */
function readSourceText(path) {
  let buf
  try {
    buf = readFileSync(path)
  } catch (error) {
    return { text: '', bytes: 0, error }
  }
  if (buf.length > MAX_READ_BYTES) {
    return { text: '', bytes: buf.length, error: new Error(`日志超过 ${MAX_READ_BYTES} 字节上限，已跳过`) }
  }

  const head = buf.subarray(0, 4)
  const looksZstd = head.length === 4 && head.equals(ZSTD_MAGIC)
  if (!looksZstd) {
    // 纯文本（或未知格式）：按 UTF-8 尽力解码，非法字节用替换字符占位。
    return { text: buf.toString('utf8'), bytes: buf.length, zstd: false, error: undefined }
  }

  const decoded = decodeZstd(buf)
  if (decoded.unsupported) {
    return {
      text: buf.toString('utf8'),
      bytes: buf.length,
      zstd: true,
      degraded: true,
      error: undefined,
    }
  }
  return {
    text: decoded.text,
    bytes: buf.length,
    zstd: true,
    frames: decoded.frames,
    failedFrames: decoded.failed,
    error: undefined,
  }
}

// ---------------------------------------------------------------------------
// 行解析：区分"调用"与"结果"
// ---------------------------------------------------------------------------

/**
 * 解析一行日志。JSON 行返回对象，非 JSON 行返回 null。
 * @param line 单行文本。
 * @returns 解析出的事件对象或 null。
 */
function parseJsonLine(line) {
  const trimmed = line.trim()
  if (trimmed.length < 8 || trimmed.charCodeAt(0) !== 0x7b /* { */) return null
  try {
    const value = JSON.parse(trimmed)
    return isObject(value) ? value : null
  } catch {
    return null
  }
}

/**
 * 该行是否是会话日志的"工具调用"事件。
 *
 * 兼容两种实测见过的形态：
 *   - `{"type":"tool/call","data":{"name":"pwsh","arguments":"…","callId":"…"}}`
 *   - `{"type":"tool-call","name":"pwsh","arguments":"…","id":"…"}`（部分分支/老版本）
 *
 * @param event 解析后的事件。
 * @returns 是则返回 `{name, arguments, callId}`，否则 null。
 */
function toolCallOf(event) {
  if (!isObject(event)) return null
  const type = event.type
  if (type !== 'tool/call' && type !== 'tool-call') return null
  const payload = isObject(event.data) ? event.data : event
  const name = typeof payload.name === 'string' && payload.name !== '' ? payload.name : undefined
  if (name === undefined) return null
  const raw = payload.arguments
  return {
    name,
    // 保留原文（用于摘录）与可读串（用于匹配）两份。
    argumentsRaw: typeof raw === 'string' ? raw : '',
    arguments: typeof raw === 'string' ? raw : toText(raw ?? ''),
    callId: typeof payload.callId === 'string' ? payload.callId : typeof payload.id === 'string' ? payload.id : undefined,
  }
}

/**
 * 扫描计数器：记录被排除的事件行数，用于自检与统计。
 * 放在模块作用域是为了让 `scanText` 保持纯函数式的返回类型（只返回命中）。
 */
const scanCounters = { skippedEvents: 0, auditedCalls: 0 }

/** 读取并清零扫描计数器。 */
function takeScanCounters() {
  const snapshot = { ...scanCounters }
  scanCounters.skippedEvents = 0
  scanCounters.auditedCalls = 0
  return snapshot
}

/**
 * 算出这次要真正扫描的文本。
 *
 * **审计面 = 工具调用的名字 + 参数**，不看对话内容。这是本插件的核心判断：
 *
 *   1. 危险操作**只能**通过工具真正执行 —— 对话里说一万遍 `cordis_define` 也不会
 *      有任何代码被注入，真正注入必须调用 `cordis_define` 工具。
 *   2. 所以"只审计工具调用"既覆盖了全部**真实的**执行面，又天然免疫两种噪声：
 *      - 自我触发：插件不能把自己/用户**讨论**敏感词当成敏感操作；
 *      - 结果回显：`tool/result` 里会列出 `cordis_define` 之类的工具名。
 *
 * 代价（见 README「只审计工具调用」一节）：以文本形态出现在**非工具事件**里的迹象
 * 不再告警，例如审批决策记录、沙箱模式变更记录、以及纯文本日志。
 * 想恢复"全文本扫描"设 `audit: 'all-text'`；纯文本日志（非 JSONL）始终按文本扫描。
 *
 * @param text 本次新增的文本（保留未完结的尾行）。
 * @param sources 来源标签。
 * @param mode `'tool-calls'`（默认）或 `'all-text'`。
 * @returns `{text, skipped, calls}`：text 为待扫描文本（工具调用行或非 JSON 文本行）。
 */
function prepareScanText(text, sources, mode = 'tool-calls') {
  const parts = []
  const calls = []
  let skipped = 0
  const auditAll = mode === 'all-text'

  for (const line of text.split('\n')) {
    if (line.trim() === '') continue
    const event = parseJsonLine(line)

    // 非 JSON 行：不是 DSH 事件日志，当作普通文本审计。
    if (event === null) {
      parts.push(line)
      continue
    }

    const call = toolCallOf(event)
    if (call !== null) {
      calls.push({ ...call, sources })
      scanCounters.auditedCalls++
      // 文本规则也对工具参数生效（例如 pwsh 参数里出现 danger-full-access）。
      // 摘录用原始行，这样命中上下文就是日志原文，便于核查。
      parts.push(auditAll ? line : auditLineOf(call))
      continue
    }

    // 没有 type 字段的 JSON 行：不确定是什么，保守地按文本审计。
    if (typeof event.type !== 'string') {
      parts.push(line)
      continue
    }

    if (auditAll) {
      parts.push(line)
    } else {
      skipped++
    }
  }

  scanCounters.skippedEvents += skipped
  return { text: parts.length > 0 ? parts.join('\n') : '', skipped, calls }
}

/**
 * 把一次工具调用渲染成"被审计的文本"。
 *
 * 格式刻意设计成三段，每一段都有用途：
 *   1. `"type":"tool/call"` + `"name":"<工具>"` —— 让摘录里能看出**这是调用而非消息**，
 *      便于归因"到底谁触发的"。
 *   2. `args:<解析后的 JSON>` —— 既能命中参数里的**转义形式**（如 `subprocess`），
 *      也能命中结构化的键值。
 *   3. `<参数原文>` —— 命中位置/摘录可读，且能匹配字面文本。
 *
 * @param call 工具调用。
 * @returns 审计文本。
 */
function auditLineOf(call) {
  const head = `"type":"tool/call","name":${JSON.stringify(call.name)}`
  if (call.argumentsRaw === '') return head
  let parsed
  try {
    parsed = JSON.parse(call.argumentsRaw)
  } catch {
    return `${head} ${call.argumentsRaw}`
  }
  let rendered
  try {
    rendered = JSON.stringify(parsed)
  } catch {
    rendered = call.argumentsRaw
  }
  return `${head} args:${rendered} ${call.argumentsRaw}`
}

// ---------------------------------------------------------------------------
// 规则匹配
// ---------------------------------------------------------------------------

/**
 * 编译配置里用户自定义的规则（JSON 无法写正则，所以接受 `pattern` 字符串）。
 * @param raw 配置里的 rules 数组。
 * @returns 编译后的规则数组；非法项被丢弃。
 */
function compileRules(raw) {
  if (!Array.isArray(raw)) return []
  const out = []
  for (const item of raw) {
    if (!isObject(item) || typeof item.id !== 'string' || item.id === '') continue
    const rule = {
      id: item.id,
      severity: typeof item.severity === 'string' ? item.severity : 'medium',
      description: typeof item.description === 'string' ? item.description : '(自定义规则)',
      custom: true,
    }
    if (typeof item.tool === 'string' && item.tool !== '') rule.tool = item.tool
    if (typeof item.pattern === 'string' && item.pattern !== '') {
      try {
        rule.pattern = new RegExp(item.pattern, 'i')
      } catch {
        continue
      }
    }
    if (rule.tool === undefined && rule.pattern === undefined) continue
    out.push(rule)
  }
  return out
}

/** 用规则集替换/追加默认规则。 */
function buildRules(config) {
  const custom = compileRules(config.rules)
  if (config.replaceDefaultRules === true) return custom
  const disabled = new Set(Array.isArray(config.disabledRules) ? config.disabledRules : [])
  return [...DEFAULT_RULES.filter((r) => !disabled.has(r.id)), ...custom]
}

/**
 * 对一个全新的文本块跑规则。
 *
 * 默认（`mode: 'tool-calls'`）只审计**工具调用的名字与参数**：工具名规则匹配调用名，
 * 正则规则匹配参数文本。`mode: 'all-text'` 时退化为对全部事件行做文本扫描。
 *
 * @param text 本次新增的文本（可能跨多行）。
 * @param sources 该文本来自哪个日志文件。
 * @param rules 编译后的规则。
 * @param mode 审计面，见 `prepareScanText`。
 * @returns 命中的告警对象数组（未去重）。
 */
function scanText(text, sources, rules, mode = 'tool-calls') {
  if (typeof text !== 'string' || text === '') return []
  const prepared = prepareScanText(text, sources, mode)
  const found = []

  for (const rule of rules) {
    if (rule.pattern) {
      // 正则规则扫待审计文本（工具调用参数，或 all-text 下的全部事件）。
      if (prepared.text === '') continue
      rule.pattern.lastIndex = 0
      const m = rule.pattern.exec(prepared.text)
      if (!m) continue
      found.push(
        makeHit(rule, {
          index: m.index,
          matched: m[0],
          text: prepared.text,
          sources,
        }),
      )
      continue
    }

    // 工具名规则：只匹配真正的 tool/call 事件（不会吃消息文本或结果回显）。
    for (const call of prepared.calls) {
      if (call.name !== rule.tool) continue
      // 命中内容取自参数（真正做了什么），没有参数就用工具名。
      const matched = call.argumentsRaw !== '' ? call.argumentsRaw : call.name
      found.push(
        makeHit(rule, {
          index: 0,
          matched,
          text: `${call.name} ${auditLineOf(call)}`,
          from: 0,
          sources: call.sources ?? sources,
        }),
      )
      break
    }
  }

  return found
}

/**
 * 组装一条告警。
 * @param rule 命中的规则。
 * @param detail 命中详情。
 * @param detail.index 命中在文本中的下标。
 * @param detail.matched 命中内容。
 * @param detail.text 被扫描的文本。
 * @param detail.from 摘录起始下标。
 * @param detail.sources 来源日志标签。
 * @returns 告警对象（未去重）。
 */
function makeHit(rule, { index, matched, text, sources }) {
  const start = typeof index === 'number' ? index : 0
  return {
    at: Date.now(),
    severity: rule.severity,
    ruleId: rule.id,
    description: rule.description,
    sources,
    matched: snippetOf(matched).slice(0, 160),
    // 摘录以命中串为中心，保证"命中在哪"一眼可见。
    snippet: snippetAround(text, start, matched),
  }
}

// ---------------------------------------------------------------------------
// 告警渲染与去重
// ---------------------------------------------------------------------------

const SEVERITY_LABEL = {
  critical: '严重',
  high: '高',
  medium: '中',
  low: '低',
}

/**
 * 单行告警摘要，用于宿主 stderr。
 *
 * 刻意**先给命中内容、再给一小段上下文**：实测最初只打 `snippet`，遇到
 * `cordis_define` 这类"命中串只是长文本里一小段"的情况时，行首会被无关的前文占满、
 * 反而看不到到底命中了什么。一眼能看出"报的是什么"比"上下文多"更重要。
 *
 * @param alert 告警。
 * @returns 单行文本。
 */
function renderAlertLine(alert) {
  const severity = SEVERITY_LABEL[alert.severity] ?? alert.severity
  const head = `[${severity}] ${alert.ruleId}`
  const matched = String(alert.matched ?? '')
  const snippet = String(alert.snippet ?? '')
  const clipped = snippet.length > 90 ? `${snippet.slice(0, 87)}...` : snippet
  // 命中内容与上下文重复时（命中串就是整条文本）不重复打印。
  if (matched !== '' && snippet.includes(matched)) return `${head} :: ${snippet.slice(0, 140)}`
  return matched === '' ? `${head} :: ${clipped}` : `${head} :: 命中「${matched.slice(0, 80)}」 上下文:${clipped}`
}

/**
 * 读取会话日志**第一帧**里的会话头，取出 `id`。
 *
 * 为什么需要它：判断"这个日志文件是不是插件自己所在的那个会话"。
 * 最早的实现读 `process.env.DSH_SESSION_ID` —— 但那是 harness 给 **bash/pwsh 子进程**
 * 注入的变量，**Host（Electron 主进程）里根本没有**，于是自身识别静默失效，
 * 自身会话照旧被扫描并自我触发。文件头里的 `{"type":"session",...,"id":...}` 是
 * 可靠来源，不依赖任何环境变量。
 *
 * 只解第一帧（用第二帧起点或文件末尾作为上界），开销可忽略。
 *
 * @param buf 整个文件的字节。
 * @returns 会话 id；无法确定时返回 null。
 */
function sessionIdOf(buf) {
  if (typeof zlib.zstdDecompressSync !== 'function') return null
  const starts = frameStarts(buf)
  if (starts.length === 0) return null
  const end = starts.length > 1 ? starts[1] : buf.length
  try {
    const head = zlib.zstdDecompressSync(buf.subarray(starts[0], end)).toString('utf8')
    const parsed = JSON.parse(head.split('\n')[0])
    return parsed && parsed.type === 'session' && typeof parsed.id === 'string' ? parsed.id : null
  } catch {
    return null
  }
}

/**
 * 在会话目录里**有界递归**收集日志文件。
 *
 * 不假设固定深度：实测布局是 `<root>/<workspace-slug>/<session-id>/<filename>`，
 * 但把深度写死会在其它 profile / 命名方案下再次静默失效，所以按深度上限递归。
 *
 * @param dir 当前目录。
 * @param wanted 目标文件名集合。
 * @param depthLeft 还能往下走几层。
 * @param out 结果累加数组。
 * @param limit 结果数量上限（防止超大目录拖慢宿主）。
 */
function collectLogFiles(dir, wanted, depthLeft, out, limit) {
  if (depthLeft < 0 || out.length >= limit) return
  let entries
  try {
    entries = readdirSync(dir, { withFileTypes: true })
  } catch {
    return // 目录不存在/无权限：正常情况（会话目录可能还没建）
  }
  for (const entry of entries) {
    if (out.length >= limit) return
    const full = join(dir, entry.name)
    if (entry.isDirectory()) {
      collectLogFiles(full, wanted, depthLeft - 1, out, limit)
    } else if (entry.isFile() && wanted.has(entry.name)) {
      out.push(full)
    }
  }
}

/**
 * 内存窗口裁剪：只裁掉游标**之前**的已消费内容，绝不丢掉未扫描的部分。
 * 返回新的文本；已消费游标（`lineStart`）与忽略边界（`ignoreBefore`）随之前移。
 *
 * @param state 来源状态（会被就地修改）。
 * @param ignoreBefore 需要跳过的历史字符数（也属于"已消费"）。
 * @param text 待裁剪文本。
 * @returns 裁剪后的文本。
 */
function trimWindow(state, ignoreBefore, text) {
  if (text.length <= MAX_TEXT_BYTES) return text
  const floor = Math.max(state.lineStart, ignoreBefore)
  const keepFrom = Math.max(floor, text.length - TRIM_STEP)
  state.lineStart = Math.max(0, state.lineStart - keepFrom)
  return text.slice(keepFrom)
}

/**
 * 找到 `[from, text.length)` 内**最后一个完整行**的结束下标。
 * 末尾没有换行的半成品行留给下一轮，避免把 `tool/call` 与它的工具名割裂开。
 *
 * @param text 全文。
 * @param from 起始游标。
 * @returns 完整行末尾下标；没有完整行时返回 `from`。
 */
function completedLineEnd(text, from) {
  const tail = text.lastIndexOf('\n', text.length - 1)
  return tail >= from ? tail + 1 : from
}

/**
 * zstd 解码文本里的安全扫描终点。
 *
 * 必须停在**完整行**边界上：半截帧会解出"没有换行的半行 JSON"，如果让游标越过它，
 * 等帧补全后新增的那一段就落在行中间，`parseJsonLine` 解析失败 → **告警被静默丢掉**。
 * 所以把不完整的尾行留在游标之后，等它完整了再连同上文一起扫。
 * 若一直没有换行（非 JSONL 日志），积压超过阈值就照扫，避免无限累积。
 *
 * @param text 解码文本。
 * @param cursor 当前游标。
 * @returns 扫描终点。
 */
function zstdScanEnd(text, cursor) {
  const end = completedLineEnd(text, cursor)
  if (end > cursor) return end
  return text.length - cursor > MAX_HOLD_BYTES ? text.length : cursor
}

/**
 * 从会话相关事件的载荷里宽松地取出会话 id。
 *
 * 签名随版本不同：`session/event(session, event)`、`session/created(session)`、
 * `api-session/activity(sessionId, updatedAt)`。这里按"字符串 → 对象的 id/session.id"顺次尝试，
 * 取不到就返回 null（调用方等下一次事件）。
 *
 * @param args 事件参数。
 * @returns 会话 id 或 null。
 */
function pickSessionId(...args) {
  for (const arg of args) {
    if (typeof arg === 'string' && arg !== '') return arg
    if (isObject(arg)) {
      if (typeof arg.id === 'string' && arg.id !== '') return arg.id
      if (isObject(arg.session)) {
        if (typeof arg.session.id === 'string' && arg.session.id !== '') return arg.session.id
        if (isObject(arg.session.header) && typeof arg.session.header.id === 'string') {
          return arg.session.header.id
        }
      }
      if (isObject(arg.header) && typeof arg.header.id === 'string') return arg.header.id
    }
  }
  return null
}

/**
 * 轮询日志文件、扫描新增内容并发告警的引擎。
 */
class LogGuard {
  /**
   * @param ctx Cordis 上下文。
   * @param config 已规整的插件配置。
   */
  constructor(ctx, config) {
    this.ctx = ctx
    this.config = config
    this.rules = buildRules(config)
    /** @type {Map<string, {text: string, cursor: number, size: number, initialized: boolean}>} */
    this.sources = new Map()
    /** 待确认告警：fingerprint → 告警（**常驻展示直到用户确认**，与提示通道分开）。 */
    this.unackedAlerts = new Map()
    /** 待确认队列的版本号：页面轮询到它变化就播一次声音、并重新渲染。 */
    this.uiSeq = 0
    /** 去重表：key -> 过期时间。 */
    this.seen = new Map()
    /** 已完成的扫描统计。 */
    this.stats = { cycles: 0, scannedBytes: 0, alerts: 0, errors: 0, files: 0 }
    /** UI 告警横幅：注入行是否已挂上（只挂一次，宿主启动时只收集一次注入表）。 */
    this.bannerInjected = false
    /** UI 告警横幅：webServer 路由是否已注册成功。 */
    this.bannerRegistered = false
    /** 需要跳过的会话 id（含"自己"）。自身会话始终忽略，不再提供开关 —— 关掉只会让"讨论敏感词"自我触发，制造永不停歇的噪声。 */
    this.ignoredSessionIds = new Set(config.ignoreSessionIds)
    // Host 进程通常没有 DSH_SESSION_ID（它只注入给 bash/pwsh 子进程），所以这里只是"有就用"。
    const own = process.env.DSH_SESSION_ID
    if (typeof own === 'string' && own !== '') this.ignoredSessionIds.add(own)
    // 关键补充：**启动即生效**。仅靠环境变量 + session/event 会留一个空窗 ——
    // 首个事件到达之前自身会话仍会被扫描（正是"重启后头几轮自己报自己"的成因）。
    // 同一会话跨重启 id 不变，所以把上次识别到的自身会话持久化，这次启动立刻读回来。
    this.loadIgnoredSessions()
    // 未确认的告警同样跨重启保留：横幅要一直挂着，直到用户点「已确认」。
    this.loadUnacked()
    /** 文件 → 会话 id 缓存（文件头只读一次）。 */
    this.sessionIdCache = new Map()
    /** 已被判定为忽略的来源。 */
    this.ignoredFiles = new Set()
    /** 蜂鸣/弹窗的冷却截止时间（模态弹框必须限流，见 beep）。 */
    this.notifyCooldownUntil = 0
    this.stderrBroken = false
    this.timer = null
    this.stopped = false
    /** 排查用：被排除的非工具事件行数（tool-calls 模式下不看这些）。 */
    this.skippedEvents = 0
    /** 排查用：已审计的工具调用条数。 */
    this.auditedCalls = 0
    /** 排查用：本插件挂上的生命周期事件数。 */
    this.lifecycleHooks = 0
  }

  /**
   * 补挂生命周期钩子。
   *
   * DSH 的 Loader 会把配置变更即时 reconcile，`app-boot/config-reload` 因此是
   * 一个天然的、不依赖任何业务服务的时机 —— 用它（以及智能体创建）来确保 UI
   * 告警横幅的路由最终一定注册上，避免"插件加载早于 webServer 服务就绪"这个竞态。
   * （注入行不依赖任何服务，在 `apply()` 里就已挂上；这里只负责补装 webServer 路由。）
   */
  attachLifecycle() {
    const events = ['app-boot/config-reload', 'agent/created', 'session/created']
    for (const event of events) {
      try {
        this.ctx.effect(() =>
          // 事件载荷我们不关心，只借这个时机做幂等注册。
          this.ctx.on(event, () => {
            ensureUiBanner(this.ctx, this, this.config)
          }),
        )
        this.lifecycleHooks++
      } catch {
        // 该事件在当前宿主版本里可能不存在，忽略即可。
      }
    }

    // 单独订阅会话事件：这是拿到"当前活动会话 id"的可靠通道，用来把自身会话
    // 加进忽略名单（见 noteActiveSession 的说明）。载荷形态随版本而异，所以
    // 只做宽松提取，取不到就等下一次事件。
    for (const event of ['session/event', 'session/created', 'api-session/activity']) {
      try {
        this.ctx.effect(() =>
          this.ctx.on(event, (a, b) => {
            const id = pickSessionId(a, b)
            if (id !== null) {
              if (this.noteActiveSession(id)) this.ignoredFiles.clear()
            }
          }),
        )
      } catch {
        // 同上：事件不存在也不影响主体功能。
      }
    }
  }

  /**
   * 启动轮询。
   *
   * 刻意用 **全局 `setInterval`** 而不是 `ctx.setInterval`：后者是 `timer` 服务上的
   * 属性访问，Cordis 会强制走 inject 检查 —— 实测会直接抛
   * `cannot get property "timer" without inject`，插件整个 activate 失败。
   * 而给插件加对象级 `inject` 恰恰是本插件要避免的事（缺服务就完全不 apply，
   * 告警静默失效）。用全局定时器 + `ctx.effect` 清理，既没有服务依赖，也不泄漏。
   */
  start() {
    this.tick()
    this.timer = setInterval(() => this.tick(), this.config.scanIntervalMs)
  }

  /**
   * 停止轮询。
   *
   * 必须用 `globalThis.clearInterval` 清掉 `globalThis.setInterval` 的返回值：
   * 从 `node:timers` 单独 import 进来的 `clearInterval` 会**遮蔽全局**，清不掉全局
   * 定时器（两者不是同一套东西）。同时兼容"disposer 函数"返回形态。
   */
  stop() {
    this.stopped = true
    const timer = this.timer
    this.timer = null
    if (timer == null) return
    try {
      if (typeof timer === 'function') timer()
      else globalThis.clearInterval(timer)
    } catch {
      // 清理失败不应影响卸载流程。
    }
  }

  /**
   * 解析当前应当监控的文件清单。
   *
   * 会话日志的真实布局是 **三层**：`<sessionDir>/<workspace-slug>/<session-id>/<filename>`。
   * 早期实现按 `<sessionDir>/<dir>/<filename>` 拼路径，结果拼出来的全是**不存在的路径**，
   * `consume()` 逐个 stat 失败后静默返回 —— 插件看起来"在运行"，实际一个文件都没监控。
   * 所以这里改为**有界递归查找**，不假设固定深度。
   */
  resolveFiles() {
    const files = new Set(this.config.files.map((f) => resolve(f)))
    if (this.config.watchSessionLogs) {
      const wanted = new Set(this.config.sessionFileNames)
      const found = []
      collectLogFiles(this.config.sessionDir, wanted, this.config.maxSessionScanDepth, found, this.config.maxWatchedFiles)
      for (const file of found) files.add(file)
      this.sessionFilesFound = found.length
    }
    this.stats.files = files.size
    return [...files]
  }

  /** 一轮轮询：读取所有来源，扫描新增文本。 */
  tick() {
    if (this.stopped) return
    this.stats.cycles++
    const now = Date.now()
    const batch = []
    const sources = []

    let files
    try {
      files = this.resolveFiles()
    } catch (error) {
      this.stats.errors++
      this.warn(`无法枚举日志文件：${error?.message ?? error}`)
      return
    }

    for (const file of files) {
      // 忽略名单里的会话（默认含"自己"）直接跳过读取：既然完全不扫，就不可能误报，
      // 也省掉整文件 zstd 解压的开销。注意新会话文件可能运行中才出现，所以每轮都判断。
      if (this.isIgnoredSession(file)) {
        if (!this.ignoredFiles.has(file)) {
          this.ignoredFiles.add(file)
          this.stats.ignored = (this.stats.ignored ?? 0) + 1
          this.warn(`跳过自身/忽略名单内的会话日志：${this.labelFor(file)}`)
        }
        continue
      }
      const added = this.consume(file, now)
      if (added && added.text) {
        sources.push(added)
      }
    }
    // 统计本次的审计面：被排除的非工具事件行、以及实际审计的工具调用条数。
    // **必须在扫描之后取**：计数是 `scanText` → `prepareScanText` 递增的，
    // 放在这里（扫描前）会让统计永远滞后一轮 —— 实测 tick#1 报 0、tick#2 才报 2。
    if (sources.length === 0) return

    for (const source of sources) {
      const hits = scanText(source.text, [source.label], this.rules, this.config.audit)
      for (const hit of hits) {
        const key = `${hit.ruleId}|${hit.sources.join(',')}|${normKey(hit.matched)}`
        const expires = this.seen.get(key)
        if (expires !== undefined && expires > now) continue
        this.seen.set(key, now + this.config.dedupeWindowMs)
        hit.fingerprint = hash(key)
        batch.push(hit)
      }
      this.stats.scannedBytes += Buffer.byteLength(source.text, 'utf8')
    }

    // 扫描之后再取审计面统计（见 drainScanCounters 的说明）。
    this.drainScanCounters()

    this.pruneSeen(now)
    if (batch.length > 0) this.raise(batch)
  }

  /**
   * 把模块级扫描计数累加进本实例统计。
   *
   * **只能在扫描之后调用**：计数是 `scanText` → `prepareScanText` 递增的。
   * 放在扫描之前会让统计永远滞后一轮（实测 tick#1 报 0、tick#2 才报 2）。
   */
  drainScanCounters() {
    const counters = takeScanCounters()
    this.skippedEvents += counters.skippedEvents
    this.auditedCalls += counters.auditedCalls
    return counters
  }

  /** 清理过期的去重记录。 */
  pruneSeen(now) {
    if (this.seen.size <= 4096) {
      for (const [key, expires] of this.seen) if (expires <= now) this.seen.delete(key)
      return
    }
    for (const [key, expires] of this.seen) if (expires <= now) this.seen.delete(key)
  }

  /**
   * 读取单个文件的新增文本（首次出现时按 scanExisting 决定是否从 0 开始）。
   *
   * **游标只进不退**（除真正的文件轮转以外）。这一条是硬要求：
   * 本插件对多帧 zstd 是"整文件逐帧解压"，而会话日志正被边写边刷；只要某一轮有帧
   * 写到一半没解出来，`decoded.length` 就会比上一轮**短**。旧实现遇到变短就把游标
   * 重置为 0，于是下一轮解压成功时**把整份历史全量重扫**，把一小时前的用户消息、
   * 我写的正则字面量全部当成"敏感操作"再告警一遍。实测就是这样稳定复现的。
   * 正确做法：变短说明"本轮少解出了东西"，保持游标不动，等帧补全后自然接上。
   *
   * @param file 绝对路径。
   * @param now 当前时间戳。
   * @returns 新增文本与该来源标签；无新增返回 null。
   */
  consume(file, now) {
    let stat
    try {
      stat = statSync(file)
    } catch {
      return null // 文件还没生成，下一次再说
    }
    if (!stat.isFile()) return null

    const size = stat.size
    let state = this.sources.get(file)
    if (!state) {
      state = {
        kind: 'unknown',
        text: '',
        lineStart: 0,
        bytes: 0,
        size: -1,
        initialized: false,
        decoder: null,
      }
      this.sources.set(file, state)
    }

    // 真正的轮转/截断：文件明显变小，只能从头开始。
    const rotated = state.size >= 0 && size < state.size
    if (rotated) {
      state.kind = 'unknown'
      state.text = ''
      state.lineStart = 0
      state.bytes = 0
      state.initialized = false
      state.decoder = null
    }
    state.size = size

    // 增量读取只适用于纯文本；zstd 必须整文件解压，所以不能靠 size 相等来跳过
    // （上一轮坏掉的帧这一轮可能就好了，文件大小却可能没变）。
    if (state.kind !== 'zstd' && state.initialized && state.bytes >= size) return null

    const result = readSourceText(file)
    if (result.error) {
      this.stats.errors++
      this.warn(`读取 ${file} 失败：${result.error.message}`)
      return null
    }

    const label = this.labelFor(file)
    state.file = file

    if (result.zstd === true) {
      state.kind = 'zstd'
      const decoded = result.text
      if (!state.initialized) {
        state.initialized = true
        const scanFromZero = this.config.scanExisting
        state.text = decoded
        state.lineStart = scanFromZero ? 0 : decoded.length
        if (!scanFromZero) return null
        const firstEnd = zstdScanEnd(decoded, 0)
        return firstEnd > 0 ? this.emitDelta(state, 0, label, result, firstEnd) : null
      }

      // 游标**只进不退**：本轮少解出的东西等下一轮补全，绝不回头重扫历史。
      const cursor = Math.min(state.lineStart, decoded.length)
      state.text = decoded
      if (cursor >= decoded.length) return null

      const scanEnd = zstdScanEnd(decoded, cursor)
      if (scanEnd <= cursor) return null
      return this.emitDelta(state, cursor, label, result, scanEnd)
    }

    // ---- 纯文本：按字节增量读取，流式解码器跨轮保持，避免切断多字节字符 ----
    if (state.kind === 'zstd') {
      state.kind = 'text'
      state.text = ''
      state.lineStart = 0
      state.bytes = 0
      state.decoder = null
    }
    state.kind = 'text'

    let chunk = ''
    if (size > state.bytes) {
      try {
        const bytes = readFileSync(file).subarray(state.bytes)
        if (!state.decoder) state.decoder = new TextDecoder('utf-8')
        chunk = state.decoder.decode(bytes, { stream: true })
      } catch (error) {
        this.stats.errors++
        this.warn(`读取 ${file} 失败：${error?.message ?? error}`)
        return null
      }
      state.bytes = size
    }

    if (chunk !== '') {
      state.text += chunk
      state.text = trimWindow(state, this.config.ignoreBefore, state.text)
    }

    if (!state.initialized) {
      state.initialized = true
      if (!this.config.scanExisting) {
        state.lineStart = state.text.length
        return null
      }
      state.lineStart = 0
    }

    if (state.lineStart >= state.text.length) return null

    // 只扫描"完整的行"：保留最后一段未完结的行，等下一次轮询补全。
    // 半行 JSON 既解析失败，也可能把 tool/call 与它的工具名割裂开。
    const end = completedLineEnd(state.text, state.lineStart)
    let scanEnd = end
    if (scanEnd <= state.lineStart && state.text.length - state.lineStart > MAX_HOLD_BYTES) {
      scanEnd = state.text.length // 积压了整块却没有换行（非 JSONL 日志）：也照扫
    }
    if (scanEnd <= state.lineStart) return null

    return this.emitDelta(state, state.lineStart, label, { zstd: false }, scanEnd)
  }

  /**
   * 切出 `[cursor, end)` 的新增文本、把已消费游标推进到完整行边界、并裁剪内存窗口。
   * @param state 来源状态。
   * @param cursor 起始游标。
   * @param label 来源标签。
   * @param result 解码结果（用于附带 zstd/degraded 标记）。
   * @param end 扫描终点，默认取文本末尾。
   * @returns 新增文本描述；无新增返回 null。
   */
  emitDelta(state, cursor, label, result, end = state.text.length) {
    if (cursor >= end) return null
    const from = this.config.ignoreBefore > 0 ? Math.max(cursor, this.config.ignoreBefore) : cursor
    const text = state.text.slice(from, end)
    // 游标推进到**本次真正扫到的地方**（可能是行边界，而不是文本末尾）。
    state.lineStart = end
    state.text = trimWindow(state, this.config.ignoreBefore, state.text)
    if (text === '') return null
    return {
      text,
      label,
      file: state.file,
      zstd: result.zstd === true,
      degraded: result.degraded === true,
    }
  }

  /**
   * 该文件是否属于"要忽略的会话"。
   *
   * 为什么必须能忽略：插件监控的是会话日志，而**当前会话的日志里就写着本次对话本身**。
   * 于是用户或模型只要在对话里提到 `cordis_define` / `subprocess` / `danger-full-access`
   * 这些词（写插件、讨论规则、读工具清单都会提到），就会被当成"敏感操作"报出来，
   * 而且是永不停止的自我触发。
   *
   * 判定顺序（两条都必要）：
   *   1. **路径匹配** `ignoreSessionIds`（含用户显式指定的）。
   *   2. **读文件头的 session id** 再匹配 —— 这才是可靠通道。
   *      起初实现读 `process.env.DSH_SESSION_ID`，但那是 harness 注入给 bash/pwsh
   *      **子进程**的变量，Host（Electron 主进程）里没有，于是自身识别静默失效、
   *      自身会话照旧被扫描。文件头不依赖任何环境变量。
   *
   * 注意：自身会话**始终**忽略，没有开关。关掉它只会让"对话里讨论敏感词"自我触发，
   * 制造永不停歇的噪声。
   *
   * @param file 绝对路径。
   * @returns 命中忽略名单返回 true。
   */
  isIgnoredSession(file) {
    if (this.ignoredSessionIds.size === 0) return false
    for (const id of this.ignoredSessionIds) {
      if (file.includes(id)) return true
    }
    const headerId = this.sessionIdOfFile(file)
    return headerId !== null && this.ignoredSessionIds.has(headerId)
  }

  /**
   * 带缓存的"文件 → 会话 id"。会话 id 写死在文件头且不变，所以一个文件只读一次。
   * @param file 绝对路径。
   * @returns 会话 id 或 null。
   */
  sessionIdOfFile(file) {
    if (this.sessionIdCache.has(file)) return this.sessionIdCache.get(file)
    let id = null
    try {
      id = sessionIdOf(readFileSync(file))
    } catch {
      id = null
    }
    this.sessionIdCache.set(file, id)
    return id
  }

  /**
   * 记下"当前活动会话"并把它加入忽略名单。
   *
   * 会话 id 来自 `session/event` 等事件（宿主会带上真实的会话）。这是**自我修复**的：
   * 就算插件启动瞬间还没拿到 id，下一轮拿到后自身会话立刻被跳过。
   *
   * @param id 会话 id。
   * @returns 是否是新增的忽略项。
   */
  noteActiveSession(id) {
    if (typeof id !== 'string' || id === '') return false
    if (this.ignoredSessionIds.has(id)) return false
    this.ignoredSessionIds.add(id)
    this.saveIgnoredSessions()
    this.warn(`会话 ${id} 被记入忽略名单（自身会话不再自我触发）`)
    return true
  }

  /**
   * 从状态文件读回"已识别为自身的会话 id"。
   *
   * 目的：消除**启动空窗**。自身识别原本只靠 `DSH_SESSION_ID`（Host 里通常没有）
   * 和 `session/event`（要等首个事件），于是插件刚启动、首个事件还没来之前，
   * 自身会话仍会被扫描 —— 表现就是"重启后头几轮自己报自己"。同一会话跨重启 id 不变，
   * 所以持久化后这次启动立刻就能忽略。
   *
   * 读失败/文件损坏一律当作空，不影响启动。
   */
  loadIgnoredSessions() {
    const file = this.config.ignoredStateFile
    if (!file) return
    try {
      const raw = JSON.parse(readFileSync(file, 'utf8'))
      const ids = Array.isArray(raw?.sessionIds) ? raw.sessionIds : []
      for (const id of ids) {
        if (typeof id === 'string' && id !== '') this.ignoredSessionIds.add(id)
      }
      if (ids.length > 0) {
        this.warn(`启动即忽略 ${ids.length} 个已知自身会话（消除启动空窗）`)
      }
    } catch {
      // 首次运行没有这个文件，属正常情况。
    }
  }

  /** 把当前忽略名单写回状态文件（失败只记 warn，不影响功能）。 */
  saveIgnoredSessions() {
    const file = this.config.ignoredStateFile
    if (!file) return
    try {
      mkdirSync(dirname(file), { recursive: true })
      writeFileSync(
        file,
        JSON.stringify({ updatedAt: new Date().toISOString(), sessionIds: [...this.ignoredSessionIds] }, null, 2),
        'utf8',
      )
    } catch (error) {
      this.warn(`写入自身会话状态失败：${error?.message ?? error}`)
    }
  }

  /** 把绝对路径压成便于阅读的来源标签。 */
  labelFor(file) {
    const root = this.config.sessionDir
    const relative = file.startsWith(root) ? file.slice(root.length + 1) : file
    const parts = relative.split(/[\\/]/).filter(Boolean)
    return parts.length >= 2 ? parts.slice(-2).join('/') : basename(file)
  }

  /**
   * 发出告警：写文件/stderr，并进入**待确认队列**（供 UI 横幅常驻展示）。
   *
   * 注意这里**不再播放声音**。声音改由页面里的 banner.js 用 Web Audio 合成
   * （见 `BANNER_JS` 的 audio 段）——宿主侧不 spawn 任何子进程、不弹任何窗口。
   * 服务端只负责推进 `uiSeq`：页面每轮询到 seq 变化就播一次，避免重复播放。
   *
   * @param alerts 本轮告警。
   */
  raise(alerts) {
    this.stats.alerts += alerts.length
    const now = Date.now()
    for (const alert of alerts) {
      const item = {
        severity: alert.severity,
        ruleId: alert.ruleId,
        description: alert.description,
        sources: alert.sources,
        matched: alert.matched,
        snippet: alert.snippet,
        raisedAt: now,
        fingerprint: alert.fingerprint,
      }
      // 同一 fingerprint 已在待确认队列里就不重复堆叠，只刷新时间。
      if (this.unackedAlerts.has(item.fingerprint)) {
        this.unackedAlerts.set(item.fingerprint, item)
      } else {
        this.unackedAlerts.set(item.fingerprint, item)
      }
    }
    // 只保留最近 N 条，避免无限增长（超出丢最旧的）。
    if (this.unackedAlerts.size > this.config.maxPendingAlerts) {
      const drop = this.unackedAlerts.size - this.config.maxPendingAlerts
      let i = 0
      for (const key of this.unackedAlerts.keys()) {
        if (i++ >= drop) break
        this.unackedAlerts.delete(key)
      }
    }
    this.uiSeq += 1
    this.persistUnacked()

    this.appendToAlertFile(alerts, now)
    if (this.config.printToHostConsole) {
      for (const alert of alerts) this.warn(renderAlertLine(alert))
    }
    // 声音由页面播放；这里只推进序号并留一条可排查的记录。
    if (this.config.notifySound) this.notifySoundSignal(`uiSeq=${this.uiSeq} 条数=${alerts.length}`)
  }

  /**
   * 判断一次**即将执行**的工具调用是否命中执行策略（blocker/jammer）。
   *
   * 这里匹配的是**工具名**，不是参数文本。
   * critical 规则（`cordis-define` / `cordis-run`）本身就是工具名，按名字匹配
   * 零误报；若默认扫参数，"编辑本插件源码"（内容含这些字面量）会被自己拦住。
   * 需要更严格时用 `enforce.enforceArguments: true` 显式打开。
   *
   * @param exec 待执行的调用（`{ name, arguments, callId }`）。
   * @returns 命中的规则数组；未命中或未启用时为空数组。
   */
  enforcementMatches(exec) {
    const policy = this.config.enforce
    if (!policy || policy.enabled !== true) return []
    const name = typeof exec?.name === 'string' ? exec.name : ''
    if (name === '') return []
    const wanted = policy.rules
    const out = []
    for (const rule of this.rules) {
      if (!policy.severities.includes(rule.severity)) continue
      if (wanted.length > 0 && !wanted.includes(rule.id)) continue
      let hit = rule.tool ? rule.tool === name : false
      if (!hit && rule.pattern) {
        rule.pattern.lastIndex = 0
        hit = rule.pattern.test(name)
      }
      if (!hit && policy.enforceArguments && rule.pattern) {
        const argsText = typeof exec.arguments === 'string' ? exec.arguments : toText(exec.arguments ?? '')
        rule.pattern.lastIndex = 0
        hit = rule.pattern.test(argsText)
      }
      if (hit) out.push(rule)
    }
    return out
  }

  /**
   * 记录一次拦截/阻断，并让它进入告警通道（横幅、告警文件、提示音）。
   *
   * @param exec 被处理的调用。
   * @param matched 命中的规则。
   * @param channel `'blocker'` 或 `'jammer'`。
   * @param action 具体动作（ask/deny/cancel/block）。
   */
  recordEnforcement(exec, matched, channel, action) {
    const callId = typeof exec?.callId === 'string' ? exec.callId : ''
    const noun = channel === 'blocker' ? '拦截' : '阻断结果'
    this.raise(
      matched.map((rule) => ({
        severity: rule.severity,
        ruleId: rule.id,
        description: `${noun}：${rule.description}`,
        sources: [`tool:${exec?.name ?? '?'}`],
        matched: String(exec?.name ?? ''),
        snippet: `调用 ${exec?.name ?? '?'} 命中 ${rule.id} → ${noun}（${action}）`,
        // 同一调用同一规则只算一条，避免重复堆叠。
        fingerprint: hash(`${rule.id}|${exec?.name ?? ''}|${channel}|${callId}`),
      })),
    )
    this.warn(`[${channel}] ${exec?.name ?? '?'} 命中 ${matched.map((r) => r.id).join(',')} → ${action}`)
  }

  /**
   * 给模型看的拦截原因（`ask` / `deny` 的 `reason`）。
   * @param matched 命中的规则。
   * @param channel 通道。
   * @returns 单行原因。
   */
  enforcementReason(matched, channel = 'blocker') {
    const ids = matched.map((r) => r.id).join(', ')
    const label = this.config.enforce?.label ?? 'dsh-log-guard'
    return channel === 'blocker'
      ? `${label}：该调用命中敏感操作规则 ${ids}，需要你明确授权才会执行。`
      : `${label}：该调用的结果已被阻断（命中 ${ids}）。`
  }

  /**
   * Jammer 用的结果反馈：模型看到的就是这段文字，而不是真实输出。
   * @param exec 被阻断的调用。
   * @param matched 命中的规则。
   * @returns 反馈文本。
   */
  enforcementFeedback(exec, matched) {
    const label = this.config.enforce?.label ?? 'dsh-log-guard'
    const lines = [
      `【${label} 已阻断本次调用的结果】`,
      `工具：${exec?.name ?? '?'}`,
      `命中规则：${matched.map((r) => `${r.id}(${r.severity})`).join(', ')}`,
      '',
      '该调用可能已经实际执行，但它的输出被策略封存，不会进入你的上下文。',
      '需要真实结果时，请让用户先确认这条操作，再重试；不要靠猜测补全输出。',
    ]
    return lines.join('\n')
  }

  /**
   * 当前**未确认**的告警（供 `/dsh-log-guard/alerts.json` 轮询）。
   *
   * 与"注入模型上下文"那条通道刻意分开：
   *   - 提示通道（若启用）是**取走即清**，避免同一批告警反复占用上下文；
   *   - 这条是**常驻到用户确认**，即使用户刷新页面、或宿主重启（已持久化）也还在。
   *
   * @returns 未确认告警数组（按时间升序）与当前序号。
   */
  unackedList() {
    return {
      seq: this.uiSeq,
      alerts: [...this.unackedAlerts.values()].sort((a, b) => (a.raisedAt ?? 0) - (b.raisedAt ?? 0)),
    }
  }

  /**
   * 用户点了「已确认」：清空待确认队列。
   * @param fingerprints 要确认的指纹；为空/非数组时表示全部确认。
   * @returns 确认掉的条数。
   */
  acknowledgeAlerts(fingerprints) {
    let removed = 0
    if (Array.isArray(fingerprints) && fingerprints.length > 0) {
      for (const fp of fingerprints) {
        if (typeof fp === 'string' && this.unackedAlerts.delete(fp)) removed++
      }
    } else {
      removed = this.unackedAlerts.size
      this.unackedAlerts.clear()
    }
    this.persistUnacked()
    if (removed > 0) this.warn(`用户确认了 ${removed} 条告警（横幅收起）`)
    return removed
  }

  /** 把待确认队列落盘，保证"常态展示"跨重启也成立。 */
  persistUnacked() {
    const file = this.config.unackedStateFile
    if (!file) return
    try {
      mkdirSync(dirname(file), { recursive: true })
      writeFileSync(
        file,
        JSON.stringify({ updatedAt: new Date().toISOString(), seq: this.uiSeq, alerts: [...this.unackedAlerts.values()] }, null, 2),
        'utf8',
      )
    } catch (error) {
      this.warn(`写入待确认告警失败：${error?.message ?? error}`)
    }
  }

  /** 启动时读回待确认队列（宿主重启后告警仍然挂着，直到用户确认）。 */
  loadUnacked() {
    const file = this.config.unackedStateFile
    if (!file) return
    try {
      const raw = JSON.parse(readFileSync(file, 'utf8'))
      const list = Array.isArray(raw?.alerts) ? raw.alerts : []
      for (const item of list) {
        if (item && typeof item.fingerprint === 'string') this.unackedAlerts.set(item.fingerprint, item)
      }
      if (typeof raw?.seq === 'number' && raw.seq > this.uiSeq) this.uiSeq = raw.seq
      if (list.length > 0) this.warn(`启动即恢复 ${list.length} 条未确认告警（继续常驻展示直到确认）`)
    } catch {
      // 首次运行没有这个文件，属正常。
    }
  }

  /**
   * 追加写入告警文件。
   * @param alerts 本轮告警。
   * @param now 时间戳。
   */
  appendToAlertFile(alerts, now) {
    const target = this.config.alertFile
    if (!target) return
    try {
      mkdirSync(dirname(target), { recursive: true })
      const lines = alerts
        .map((alert) =>
          JSON.stringify({
            time: stamp(now),
            severity: alert.severity,
            ruleId: alert.ruleId,
            description: alert.description,
            sources: alert.sources,
            matched: alert.matched,
            snippet: alert.snippet,
            fingerprint: alert.fingerprint,
          }),
        )
        .join('\n')
      appendFileSync(target, `${lines}\n`, 'utf8')
    } catch (error) {
      this.warn(`写入告警文件失败：${error?.message ?? error}`)
    }
  }

  /**
   * 告警声音。
   *
   * **已改为由页面播放**：宿主侧不再 spawn 任何子进程、不弹任何窗口。
   * 早先用 powershell 做 `[console]::beep()` + `MessageBox`，问题有三：
   *   1. 弹框是**模态**的，会把界面按住（实测一次等 6.7 秒）；
   *   2. spawn 的 spec 与 `SubprocessSpawnSpec` 不符，日志只显示"已启动"却根本没响；
   *   3. 声音与界面分属两个世界，音量/静音无法统一控制。
   * 现在由 banner.js 用 Web Audio 合成三声（高-低-高），与界面同一套开关。
   *
   * 本方法只负责记录"该响的一批"（可排查），真正的播放发生在页面里。
   *
   * @param detail 记录内容。
   * @returns 恒为 true（信号已发出）。
   */
  notifySoundSignal(detail) {
    const now = Date.now()
    if (now < this.notifyCooldownUntil) {
      this.noteNotify('sound-skipped', '冷却窗口内')
      return false
    }
    this.notifyCooldownUntil = now + this.config.notifyCooldownMs
    this.noteNotify('sound-signal', detail)
    return true
  }

  /**
   * 把蜂鸣的每一次决策落盘，作为**可检查的证据**。
   *
   * 为什么需要：蜂鸣是纯感官输出（声音 + 弹框），插件那边没有任何可观察状态。
   * 加上模态弹框只在冷却窗口内弹一次，"没听到"时根本无法区分下面几种情况：
   * 压根没触发 / 服务取不到 / spawn 失败 / 响了但用户没注意。
   * 所以每次都往 `<alertFile 同目录>/notify.log` 追加一行结论。
   *
   * @param outcome 结果代号。
   * @param detail 补充说明。
   */
  noteNotify(outcome, detail) {
    const target = this.config.notifyLog
    if (!target) return
    try {
      mkdirSync(dirname(target), { recursive: true })
      appendFileSync(
        target,
        `${new Date().toISOString()}\t${outcome}\t${detail}\n`,
        'utf8',
      )
    } catch {
      // 诊断日志写不进去也不能影响告警本身。
    }
  }

  /** 往宿主 stderr 打一条醒目告警。 */
  warn(message) {
    if (this.stderrBroken) return
    try {
      process.stderr.write(`${STDERR_PREFIX} ${message}\n`)
    } catch {
      this.stderrBroken = true
    }
  }
}

// ---------------------------------------------------------------------------
// 配置规整
// ---------------------------------------------------------------------------

/** Blocker 允许的动作。`off` 表示只告警不拦截。 */
const BLOCKER_ACTIONS = Object.freeze(['ask', 'deny', 'cancel', 'off'])
/** Jammer 允许的动作。`off` 表示不干预结果。 */
const JAMMER_ACTIONS = Object.freeze(['block', 'off'])

/**
 * 规整 `enforce` 配置块（blocker / jammer）。
 *
 * **默认关闭**：这是从"检测器"升级为"策略执行器"，默认开启等于擅自改变
 * 宿主行为；必须由用户在 profile 的 `cordis.patch.yml` 里显式 `enabled: true`。
 *
 * @param raw 原始 `enforce` 值。
 * @returns 规整后的执行策略。
 */
function normalizeEnforce(raw) {
  const input = isObject(raw) ? raw : {}
  const severities =
    Array.isArray(input.severities) && input.severities.length > 0
      ? input.severities.filter((s) => typeof s === 'string' && s !== '')
      : ['critical']
  return {
    enabled: input.enabled === true,
    /** `ask` = 询问用户后放行（推荐）；`deny` = 直接拒；`cancel` = 静默取消。 */
    blocker: BLOCKER_ACTIONS.includes(input.blocker) ? input.blocker : 'ask',
    /** `block` = 阻断结果并给模型一段反馈。 */
    jammer: JAMMER_ACTIONS.includes(input.jammer) ? input.jammer : 'block',
    /** 只对这些级别生效；默认仅 critical（即 cordis_define / cordis_run）。 */
    severities,
    /** 可选：只对这些规则 id 生效（空 = 由 severities 决定）。 */
    rules: Array.isArray(input.rules) ? input.rules.filter((r) => typeof r === 'string' && r !== '') : [],
    /**
     * 是否连**参数文本**一起匹配。默认 false —— 只匹配工具名。
     *
     * 为什么默认不扫参数：critical 规则本身就是工具名（cordis_define / cordis_run），
     * 按名字匹配零误报；而扫参数会让"用 write 编辑本插件源码"（内容含这些字面量）
     * 被自己拦住。需要更严格时再显式打开，并接受噪声。
     */
    enforceArguments: input.enforceArguments === true,
    /** 询问框的标题，用于 `displayReason` 与告警文案。 */
    label: typeof input.label === 'string' && input.label !== '' ? input.label : 'dsh-log-guard',
  }
}

/**
 * 把 Loader 传入的原始 config 规整为引擎配置。
 * 所有字段都可省略；非法值回落到默认值，插件绝不因为配置而加载失败。
 * @param raw 原始 config（可能为 undefined）。
 * @returns 已规整的配置。
 */
function normalizeConfig(raw) {
  const input = isObject(raw) ? raw : {}
  const home = homedir()
  const dshHome = pick(process.env.DSH_HOME, join(home, '.dsh'))
  const profileDir = pick(process.env.DSH_PROFILE_DIR, join(dshHome, 'profiles', 'desktop'))
  const alertDir = pick(input.alertDir, join(dshHome, 'log-guard'))
  const alertFile =
    typeof input.alertFile === 'string'
      ? input.alertFile
      : input.alertFile === null
        ? null
        : join(alertDir, 'alerts.jsonl')

  const toPositiveInt = (value, fallback, min = 1) => {
    const n = Number(value)
    return Number.isFinite(n) && n >= min ? Math.floor(n) : fallback
  }

  /** 规整为非负整数毫秒。 */
  const toMillis = (value, fallback) => {
    const n = Number(value)
    return Number.isFinite(n) && n >= 0 ? Math.floor(n) : fallback
  }

  return {
    enabled: input.enabled !== false,
    scanIntervalMs: toPositiveInt(input.scanIntervalMs, 1000, 50),
    scanExisting: input.scanExisting === true,
    watchSessionLogs: input.watchSessionLogs !== false,
    sessionDir: pick(input.sessionDir, join(dshHome, 'sessions')),
    sessionFileNames: Array.isArray(input.sessionFileNames) && input.sessionFileNames.length > 0
      ? input.sessionFileNames.filter((n) => typeof n === 'string' && n !== '')
      : ['session.v4.jsonl.zstd'],
    files: Array.isArray(input.files) ? input.files.filter((f) => typeof f === 'string' && f !== '') : [],
    alertFile,
    /**
     * 是否往界面注入告警横幅（默认 true）。
     * 这是用户真正"看得见"的通道：命中后在页面右上角弹出 banner。
     * （旧版的 `systemPrompt.context()` 注入已移除 —— 那段只是喂给模型的隐藏上下文，
     * 聊天流默认不渲染，用户看不见。）
     */
    uiBanner: input.uiBanner !== false,
    notifySound: input.notifySound === true,
    /**
     * 声音冷却窗口：同一窗口内不重复发声。
     * 声音由页面用 Web Audio 播放（宿主侧不再 spawn 任何进程、不弹窗）。
     */
    notifyCooldownMs: toMillis(input.notifyCooldownMs, 30_000),
    /**
     * 蜂鸣诊断日志位置。每次蜂鸣决策（spawned / no-subprocess / spawn-error /
     * skipped）都追加一行，用来回答"我配了为什么没响"。
     */
    notifyLog:
      typeof input.notifyLog === 'string' && input.notifyLog !== ''
        ? input.notifyLog
        : input.notifyLog === null
          ? null
          : join(alertDir, 'notify.log'),
    /**
     * "已识别为自身的会话 id"的持久化位置。
     * 用于消除启动空窗：重启后立刻忽略自身会话，不必等首个 session 事件。
     */
    ignoredStateFile:
      typeof input.ignoredStateFile === 'string' && input.ignoredStateFile !== ''
        ? input.ignoredStateFile
        : input.ignoredStateFile === null
          ? null
          : join(alertDir, 'ignored-sessions.json'),
    /**
     * 待确认告警的持久化位置。
     * 告警要**常驻展示直到用户确认**，所以状态落在服务端：刷新页面、宿主重启后
     * 未确认的告警仍然挂着，不会因为一次重启就"自己消失"。
     */
    unackedStateFile:
      typeof input.unackedStateFile === 'string' && input.unackedStateFile !== ''
        ? input.unackedStateFile
        : input.unackedStateFile === null
          ? null
          : join(alertDir, 'unacked-alerts.json'),
    printToHostConsole: input.printToHostConsole !== false,
    maxPendingAlerts: toPositiveInt(input.maxPendingAlerts, 20),
    dedupeWindowMs: toPositiveInt(input.dedupeWindowMs, 60_000, 0),
    disabledRules: Array.isArray(input.disabledRules) ? input.disabledRules : [],
    replaceDefaultRules: input.replaceDefaultRules === true,
    rules: Array.isArray(input.rules) ? input.rules : [],
    maxSessionScanDepth: Number.isInteger(Number(input.maxSessionScanDepth)) && Number(input.maxSessionScanDepth) >= 0
      ? Number(input.maxSessionScanDepth)
      : DEFAULT_SESSION_SCAN_DEPTH,
    maxWatchedFiles: toPositiveInt(input.maxWatchedFiles, 400),
    /**
     * 跳过每个日志文件开头的前 N 个字符。
     * 会话日志的第 1 行是 `{"type":"session",...}` 头，里面写着 cwd 与 agentPreset；
     * 而系统提示里的 cwd、以及插件包源码，都可能在日志里出现 `cordis.yml` 之类的
     * 字面量，造成噪声。默认跳过一点点开头，压掉这类结构性噪声。
     */
    ignoreBefore: toMillis(input.ignoreBefore, 0),
    /**
     * 审计面。
     *  - `'tool-calls'`（默认）：只审计工具调用的名字与参数。
     *  - `'all-text'`：对全部事件行做文本扫描（旧行为，噪声大）。
     */
    audit: input.audit === 'all-text' ? 'all-text' : 'tool-calls',
    /** 额外要忽略的会话 id 列表。 */
    ignoreSessionIds: Array.isArray(input.ignoreSessionIds)
      ? input.ignoreSessionIds.filter((id) => typeof id === 'string' && id !== '')
      : [],
    /** blocker / jammer 执行策略（默认关闭）。 */
    enforce: normalizeEnforce(input.enforce),
    profileDir,
  }
}

// ---------------------------------------------------------------------------
// 插件入口
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// UI 告警横幅（用户真正"看得见"的通道）
// ---------------------------------------------------------------------------

/**
 * 横幅脚本在页面里加载的路径。由 webServer 路由 `/dsh-log-guard/banner.js` 提供，
 * 通过 `webserver/index-inject` 注入一行 `<script src=…>` 让页面加载它。
 */
const BANNER_SCRIPT_SRC = '/dsh-log-guard/banner.js'

/**
 * 往桌面端 `index.html` 注入的那一行结构化数据（`webserver/index-inject` 推的行）。
 *
 * 学 `dsh-whale-widget` 的做法：桌面壳的 index.html 从安装包静态 dist 直出，任何
 * 函数变换（tapIndex）都过不去；唯一通道是这个结构化行，经 IPC 交给页面解释器
 * 逐行应用。内联 script 由我们自己建 `<script src=…>` 并吞掉 onerror —— 路由在就
 * 正常加载，路由不在就静默失败，宿主永远不会因为我们起不来。
 */
const BANNER_INJECT_ROW =
  '(function(){try{var d=document.body||document.head||document.documentElement;if(!d)return;' +
  'var s=document.createElement("script");' +
  `s.src=${JSON.stringify(BANNER_SCRIPT_SRC)};` +
  's.onerror=function(){};d.appendChild(s)}catch(e){}})()'

/**
 * 横幅脚本源码。运行在页面上下文里：
 *   - **常驻在线徽标**：启动即显示（绿点 + "dsh-log-guard 在线"），作为插件在线
 *     的可见信号。**默认在右下角** —— 右上角是 DSH 窗口自己的标题栏控制按钮，
 *     实测会被遮挡（用户截图确认），右下角与 whale-widget 一致。
 *   - **可拖拽 + 位置记忆**：按住拖到任意位置（pointer 事件），松手 clamp 回视口
 *     并存 localStorage（`dsh-log-guard-banner-pos`）；未拖过用 right/bottom 定位，
 *     一拖就切换成 left/top。窗口 resize 时也会 clamp 防止跑出屏幕。
 *   - **命中告警时展开**：轮询 `/dsh-log-guard/alerts.json` 拿到新告警，把徽标
 *     展开成完整 banner（级别徽标 + 规则 + 描述 + 命中内容），带「×」关闭按钮，
 *     15s 后自动收回收起态。
 *
 * 注意这段是**字符串**：里面只用单/双引号，不用反引号与 `${`，避免与外层模板
 * 字符串冲突。所有告警文本插入 DOM 前都做了 HTML 转义（防止日志里的尖括号注入页面）。
 */
const BANNER_JS = `(function () {
  if (window.__dshLogGuardBanner) return
  window.__dshLogGuardBanner = true
  var POLL_MS = 1000
  var POS_KEY = 'dsh-log-guard-banner-pos'
  var MIN_TOP = 48
  var SEV = {
    critical: { label: '严重', color: '#a32d2d', bg: '#fcebeb' },
    high: { label: '高', color: '#854f0b', bg: '#faeeda' },
    medium: { label: '中', color: '#5f5e5a', bg: '#f1efe8' },
    low: { label: '低', color: '#0f6e56', bg: '#e1f5ee' }
  }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[<>&"]/g, function (c) {
      return c === '<' ? '&lt;' : c === '>' ? '&gt;' : c === '&' ? '&amp;' : '&quot;'
    })
  }
  var root = null
  var pos = null
  try {
    var saved = JSON.parse(localStorage.getItem(POS_KEY) || 'null')
    if (saved && typeof saved.left === 'number' && typeof saved.top === 'number') pos = saved
  } catch (e) {}

  // ---- 音效：Web Audio 合成三声（高-低-高），与旧 powershell beep 同一种听感。
  //      不再 spawn 任何子进程、不弹系统窗口。
  var audioCtx = null
  var lastSeq = null
  function initAudio() {
    try {
      if (audioCtx) return audioCtx
      var AC = window.AudioContext || window.webkitAudioContext
      if (!AC) return null
      audioCtx = new AC()
      // 自动播放策略：新建时是 suspended，必须有**用户手势**才能出声。
      // 所以下面在首次点击/按键时 resume 一次，此后就一直可用。
      if (audioCtx.state === 'suspended') {
        var resume = function () {
          try { audioCtx.resume() } catch (e) {}
          document.removeEventListener('pointerdown', resume, true)
          document.removeEventListener('keydown', resume, true)
        }
        document.addEventListener('pointerdown', resume, true)
        document.addEventListener('keydown', resume, true)
      }
    } catch (e) { audioCtx = null }
    return audioCtx
  }
  function tone(freq, dur) {
    var ctx = initAudio()
    if (!ctx || ctx.state !== 'running') return
    try {
      var osc = ctx.createOscillator()
      var gain = ctx.createGain()
      osc.type = 'square'
      osc.frequency.value = freq
      gain.gain.setValueAtTime(0.0001, ctx.currentTime)
      gain.gain.exponentialRampToValueAtTime(0.14, ctx.currentTime + 0.01)
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + dur / 1000)
      osc.connect(gain)
      gain.connect(ctx.destination)
      osc.start()
      osc.stop(ctx.currentTime + dur / 1000 + 0.02)
    } catch (e) {}
  }
  function playAlertSound() {
    tone(1200, 180)
    setTimeout(function () { tone(800, 180) }, 200)
    setTimeout(function () { tone(1200, 180) }, 400)
  }

  function clamp(p) {
    var w = root ? root.offsetWidth : 150
    var h = root ? root.offsetHeight : 34
    var maxL = Math.max(0, window.innerWidth - w - 4)
    var maxT = Math.max(MIN_TOP, window.innerHeight - h - 4)
    return { left: Math.min(Math.max(0, p.left), maxL), top: Math.min(Math.max(MIN_TOP, p.top), maxT) }
  }
  function applyPos() {
    if (!root) return
    if (pos) {
      pos = clamp(pos)
      root.style.left = pos.left + 'px'
      root.style.top = pos.top + 'px'
      root.style.right = 'auto'
      root.style.bottom = 'auto'
    } else {
      root.style.left = 'auto'
      root.style.top = 'auto'
      root.style.right = '16px'
      root.style.bottom = '16px'
    }
  }
  function baseStyle() {
    return 'position:fixed;z-index:2147483000;max-width:400px;max-height:70vh;overflow:auto;' +
      'font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#fff;' +
      'border-radius:10px;box-shadow:0 6px 18px rgba(0,0,0,.12);padding:8px 12px;color:#1a1a1a;' +
      'user-select:none;'
  }
  function ensureRoot() {
    if (root) return root
    if (!document.body) return null
    root = document.getElementById('dsh-log-guard-banner')
    if (root) return root
    root = document.createElement('div')
    root.id = 'dsh-log-guard-banner'
    document.body.appendChild(root)
    return root
  }
  function headerHtml(extra) {
    return '<div data-dsh-lg-drag="1" style="display:flex;align-items:center;gap:8px;cursor:grab;">' +
      extra + '</div>'
  }
  function idleHtml() {
    return headerHtml(
      '<svg viewBox="0 0 24 24" width="18" height="18" style="flex:0 0 auto;"><path d="M12 2L4 5v6c0 5 3.5 9 8 11 4.5-2 8-6 8-11V5l-8-3z" fill="#1d9e75"/><path d="M9 12l2 2 4-4" stroke="#fff" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>' +
      '<span style="font-size:12px;font-weight:600;color:#0f6e56;">dsh-log-guard 在线</span>')
  }
  function itemHtml(a) {
    var s = SEV[a.severity] || SEV.medium
    var head = '<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">' +
      '<span style="font-size:11px;font-weight:600;color:' + s.color + ';background:' + s.bg + ';border-radius:4px;padding:1px 6px;">' + s.label + '</span>' +
      '<b style="font-size:13px;">' + esc(a.ruleId) + '</b>' +
      '<span style="font-size:12px;color:#666;">' + esc(a.description) + '</span>' +
      '</div>'
    var m = esc(a.matched)
    var src = esc((a.sources || []).join(', '))
    return '<div style="margin:6px 0 0;padding:8px 10px;border:1px solid #eee;border-radius:6px;">' + head +
      (m ? '<div style="font-size:12px;color:#555;margin-top:4px;word-break:break-all;">命中：' + m + '</div>' : '') +
      (src ? '<div style="font-size:11px;color:#888;margin-top:3px;word-break:break-all;">来源：' + src + '</div>' : '') +
      '</div>'
  }
  function collapse() {
    var el = ensureRoot()
    if (!el) return
    el.style.cssText = baseStyle() + 'border:1px solid #e2e2e2;'
    el.innerHTML = idleHtml()
    applyPos()
  }
  function show(alerts) {
    var el = ensureRoot()
    if (!el || !alerts || !alerts.length) return
    el.style.cssText = baseStyle() + 'border:1px solid #e24b4a;border-left:4px solid #e24b4a;'
    el.innerHTML =
      headerHtml(
        '<svg viewBox="0 0 24 24" width="18" height="18" style="flex:0 0 auto;"><path d="M12 2L4 5v6c0 5 3.5 9 8 11 4.5-2 8-6 8-11V5l-8-3z" fill="#e24b4a"/><path d="M12 7v6M12 16.5v.5" stroke="#fff" stroke-width="2" fill="none" stroke-linecap="round"/></svg>' +
        '<b style="font-size:13px;color:#a32d2d;">安全告警 · dsh-log-guard</b>' +
        '<span style="flex:1;"></span>' +
        '<button id="dsh-lg-detail" style="font-size:12px;color:#185fa5;background:transparent;border:1px solid #c9d8ee;border-radius:6px;padding:2px 8px;cursor:pointer;">详情</button>' +
        '<button id="dsh-lg-ack" style="font-size:12px;color:#fff;background:#1d9e75;border:1px solid #1d9e75;border-radius:6px;padding:2px 8px;cursor:pointer;">已确认</button>') +
      '<div style="font-size:12px;color:#888;margin:4px 0 0;">检测到 ' + alerts.length + ' 条敏感操作（需确认后才会收起）</div>' +
      alerts.map(itemHtml).join('') +
      '<div id="dsh-lg-detail-wrap" style="display:none;margin-top:8px;">' +
      '<iframe id="dsh-lg-frame" data-dsh-lg-drag="1" style="width:100%;height:340px;border:1px solid #eee;border-radius:6px;background:#fff;"></iframe>' +
      '</div>'
    var ack = el.querySelector('#dsh-lg-ack')
    if (ack) {
      ack.onclick = function () {
        ack.disabled = true
        ack.textContent = '确认中…'
        fetch('/dsh-log-guard/ack', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
          .then(function () { collapse() })
          .catch(function () { collapse() })
      }
    }
    var det = el.querySelector('#dsh-lg-detail')
    if (det) {
      det.onclick = function () {
        var wrap = el.querySelector('#dsh-lg-detail-wrap')
        var frame = el.querySelector('#dsh-lg-frame')
        if (!wrap || !frame) return
        var open = wrap.style.display !== 'none'
        if (open) {
          wrap.style.display = 'none'
          det.textContent = '详情'
        } else {
          if (!frame.getAttribute('src')) frame.setAttribute('src', '/dsh-log-guard/history')
          wrap.style.display = 'block'
          det.textContent = '收起详情'
        }
        applyPos()
      }
    }
    applyPos()
  }
  var drag = null
  function inDragHandle(t) {
    if (!t || !t.closest) return false
    if (t.closest('button')) return false
    if (t.closest('iframe')) return false
    return !!t.closest('[data-dsh-lg-drag]')
  }
  function onDown(e) {
    if (e.button !== 0) return
    if (!inDragHandle(e.target)) return
    var el = ensureRoot()
    if (!el) return
    var r = el.getBoundingClientRect()
    drag = { dx: e.clientX - r.left, dy: e.clientY - r.top }
    try { el.setPointerCapture(e.pointerId) } catch (err) {}
    e.preventDefault()
  }
  function onMove(e) {
    if (!drag) return
    pos = { left: e.clientX - drag.dx, top: e.clientY - drag.dy }
    applyPos()
  }
  function snapEdge(p) {
    var SNAP = 12
    var w = root ? root.offsetWidth : 150
    var h = root ? root.offsetHeight : 34
    var out = { left: p.left, top: p.top }
    if (p.left < SNAP) out.left = 0
    else if (p.left + w > window.innerWidth - SNAP) out.left = window.innerWidth - w
    if (p.top < MIN_TOP + SNAP) out.top = MIN_TOP
    else if (p.top + h > window.innerHeight - SNAP) out.top = window.innerHeight - h
    return out
  }
  function onUp() {
    if (!drag) return
    drag = null
    if (pos) {
      pos = clamp(snapEdge(pos))
      applyPos()
      try { localStorage.setItem(POS_KEY, JSON.stringify(pos)) } catch (err) {}
    }
  }
  function bindDrag() {
    var el = ensureRoot()
    if (!el) return
    el.addEventListener('pointerdown', onDown)
    el.addEventListener('pointermove', onMove)
    el.addEventListener('pointerup', onUp)
    el.addEventListener('pointercancel', onUp)
    window.addEventListener('resize', applyPos)
  }
  function poll() {
    try {
      fetch('/dsh-log-guard/alerts.json', { cache: 'no-store' })
        .then(function (r) { return r.ok ? r.json() : null })
        .then(function (j) {
          if (!j) return
          var alerts = j.alerts || []
          var seq = typeof j.seq === 'number' ? j.seq : 0
          // seq 变化 = 有一批新的告警进来 → 播一次声音（不因每轮询重复响）。
          if (lastSeq !== null && seq > lastSeq && alerts.length) playAlertSound()
          lastSeq = seq
          // 常驻展示：只要还有未确认的告警就一直显示；全部确认后才收起。
          if (alerts.length) show(alerts)
          else collapse()
        })
        .catch(function () {})
    } catch (e) {}
  }
  function boot() {
    var el = ensureRoot()
    if (!el) return
    bindDrag()
    collapse()
    initAudio()
    setInterval(poll, POLL_MS)
    poll()
  }
  if (document.body) boot()
  else document.addEventListener('DOMContentLoaded', boot)
})()`

/** alerts.json 的响应头：必须 no-store，否则告警被缓存会重复或丢失。 */
const BANNER_JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }

/**
 * 读取告警文件（JSONL），返回倒序数组（最新在前）。
 * 文件不存在、为空、或某行损坏时都不抛：分别返回空数组 / 跳过坏行。
 * @param file 告警文件绝对路径。
 * @returns 告警记录数组（倒序）。
 */
function readAlertHistory(file) {
  if (!file) return []
  try {
    const raw = readFileSync(file, 'utf8')
    const rows = []
    for (const line of raw.split('\n')) {
      const trimmed = line.trim()
      if (trimmed === '') continue
      try {
        rows.push(JSON.parse(trimmed))
      } catch {
        // 写到一半的坏行跳过，不影响其余记录。
      }
    }
    return rows.reverse()
  } catch {
    return []
  }
}

/**
 * 把告警历史渲染成一张自包含 HTML 页（`/dsh-log-guard/history` 的响应体）。
 * @param rows 告警记录数组。
 * @returns HTML 字符串。
 */
function renderHistoryHtml(rows) {
  const esc = (s) => String(s ?? '').replace(/[&<>]/g, (c) => (c === '&' ? '&amp;' : c === '<' ? '&lt;' : '&gt;'))
  const SEV_COLOR = { critical: '#a32d2d', high: '#854f0b', medium: '#5f5e5a', low: '#0f6e56' }
  const SEV_BG = { critical: '#fcebeb', high: '#faeeda', medium: '#f1efe8', low: '#e1f5ee' }
  const items = rows
    .map((r) => {
      const color = SEV_COLOR[r.severity] ?? '#5f5e5a'
      const bg = SEV_BG[r.severity] ?? '#f1efe8'
      const matched = r.matched ? `<div style="font-size:12px;color:#555;word-break:break-all;margin-top:4px;">命中：${esc(r.matched)}</div>` : ''
      return `<div style="border:1px solid #eee;border-radius:8px;padding:10px 12px;margin:8px 0;">
<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
<span style="font-size:12px;font-weight:600;color:${color};background:${bg};border-radius:4px;padding:1px 7px;">${esc(r.severity)}</span>
<b style="font-size:14px;">${esc(r.ruleId)}</b>
<span style="font-size:12px;color:#888;">${esc(r.time)}</span>
</div>
<div style="font-size:13px;color:#444;margin:6px 0 2px;">${esc(r.description)}</div>
<div style="font-size:12px;color:#666;">来源：${esc((r.sources ?? []).join(', '))}</div>
${matched}
</div>`
    })
    .join('')
  return `<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8"><title>dsh-log-guard 告警历史</title>
<style>body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;max-width:860px;margin:0 auto;padding:24px;color:#1a1a1a;background:#fff}</style>
</head><body>
<h1 style="font-size:18px;font-weight:600;margin:0 0 4px;">dsh-log-guard 告警历史</h1>
<p style="font-size:13px;color:#888;margin:0 0 16px;">共 ${rows.length} 条（最新在前）</p>
${items}
</body></html>`
}

/**
 * 装配 UI 告警横幅：① 挂注入行（不依赖任何服务，必须早）；② 注册 webServer 路由。
 *
 * ② 依赖 `webServer` 服务，插件加载时它可能还没就绪，所以与旧实现一样在
 * `attachLifecycle()` 里"来一次装一次"幂等重试；注册失败也不影响扫描与
 * 告警文件/stderr 那几条通道。
 *
 * @param ctx Cordis 根上下文。
 * @param guard 引擎实例。
 * @param config 已规整配置。
 * @returns 路由是否已注册成功。
 */
function ensureUiBanner(ctx, guard, config) {
  if (!config.uiBanner) return false

  // ① 注入行：只挂一次。桌面端宿主启动时只收集一次注入表，所以必须在 apply()
  //    里尽早订阅；晚于那次收集就永远进不去了。这里不依赖任何服务。
  if (!guard.bannerInjected) {
    guard.bannerInjected = true
    try {
      ctx.effect(() =>
        ctx.on('webserver/index-inject', (table) => {
          if (!Array.isArray(table)) return
          for (const row of table) {
            if (row && row.kind === 'script' && typeof row.text === 'string' && row.text.indexOf(BANNER_SCRIPT_SRC) >= 0) {
              return // 已经推过（宿主可能重发该事件）
            }
          }
          table.push({ kind: 'script', placement: 'body', text: BANNER_INJECT_ROW })
        }),
      )
    } catch {
      // web 形态没有这个事件；那条线用下面的 tapIndex 兜底。
    }
  }

  // ② 路由：依赖 webServer 服务，晚就绪时靠 attachLifecycle 幂等补装。
  if (guard.bannerRegistered) return true
  const webServer = ctx.get('webServer')
  if (!webServer || typeof webServer.register !== 'function') return false
  try {
    ctx.effect(() =>
      webServer.register({
        path: '/dsh-log-guard/alerts.json',
        handler: async (req, res) => {
          // 返回**未确认**的告警（不是取走即清）：横幅要常驻展示，直到用户点「已确认」。
          // seq 供页面判断"有没有新的一批"来决定是否播声音（避免每轮询都响）。
          const { seq, alerts } = guard.unackedList()
          res.writeHead(200, BANNER_JSON_HEADERS)
          res.end(JSON.stringify({ ok: true, seq, alerts }))
        },
      }),
    )
    ctx.effect(() =>
      webServer.register({
        path: '/dsh-log-guard/ack',
        handler: async (req, res) => {
          // 用户确认：清空待确认队列（横幅随之收起）。body 可带 fingerprints 做部分确认。
          let fingerprints = []
          try {
            const chunks = []
            for await (const chunk of req) chunks.push(chunk)
            const body = Buffer.concat(chunks).toString('utf8').trim()
            if (body !== '') {
              const parsed = JSON.parse(body)
              if (Array.isArray(parsed?.fingerprints)) fingerprints = parsed.fingerprints
            }
          } catch {
            // body 不合法就按"全部确认"处理，不因为解析失败让用户点不动按钮。
          }
          const removed = guard.acknowledgeAlerts(fingerprints)
          res.writeHead(200, BANNER_JSON_HEADERS)
          res.end(JSON.stringify({ ok: true, removed }))
        },
      }),
    )
    ctx.effect(() =>
      webServer.register({
        path: BANNER_SCRIPT_SRC,
        handler: async (req, res) => {
          res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8', 'Cache-Control': 'no-store' })
          res.end(BANNER_JS)
        },
      }),
    )
    // banner 上的「详情」入口：打开一个页面，列出 alerts.jsonl 里的历史告警。
    ctx.effect(() =>
      webServer.register({
        path: '/dsh-log-guard/history',
        handler: async (req, res) => {
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' })
          res.end(renderHistoryHtml(readAlertHistory(guard.config.alertFile)))
        },
      }),
    )
    // web 形态的注入通道：函数变换 index.html（桌面端走 index-inject，这里兜底）。
    if (typeof webServer.tapIndex === 'function') {
      ctx.effect(() =>
        webServer.tapIndex((html) => {
          if (typeof html !== 'string' || html.indexOf(BANNER_SCRIPT_SRC) !== -1) return html
          const tag = `<script src="${BANNER_SCRIPT_SRC}"></script>`
          return html.indexOf('</body>') !== -1 ? html.replace('</body>', `${tag}</body>`) : html + tag
        }),
      )
    }
    guard.bannerRegistered = true
    return true
  } catch (error) {
    guard.warn(`注入 UI 告警横幅失败：${error?.message ?? error}`)
    return false
  }
}

/**
 * 装配 blocker / jammer。
 *
 * - **blocker** 走 `tools/pre-execute` waterfall：返回 `ask` 时宿主会弹审批，
 *   用户批准才执行；`ask` 在没有审批支持时会被宿主转成拒绝（fail-closed，符合预期）。
 *   之所以不用 `ctx.tools.guard()`：guard 是**同步**的，无法等待用户，
 *   而 `deny` 又不可被任何东西放行 —— 用户选的是"询问后放行"，只能走 `ask`。
 * - **jammer** 走 `tools/post-execute` waterfall：调用已执行，但返回 `block` +
 *   `feedback`，模型只看到这段反馈，看不到真实输出。
 *
 * @param ctx Cordis 根上下文。
 * @param guard 引擎实例。
 * @param config 已规整配置。
 * @returns 实际装了监听器的条数（0 = 未启用或全部 off）。
 */
function installEnforcement(ctx, guard, config) {
  const policy = config.enforce
  if (!policy || policy.enabled !== true) return 0
  const label = policy.label
  let installed = 0

  // 自检：`tools` 服务取不到时，`tools/*` 事件永远不会派发 —— 策略会**静默失效**。
  // 与其让用户以为开了防护，不如明确警告。
  let toolsReady = false
  try {
    toolsReady = Boolean(ctx.get('tools'))
  } catch {
    toolsReady = false
  }
  if (!toolsReady) {
    guard.warn('⚠ 未取到 tools 服务：blocker/jammer 已挂监听器，但可能不会被派发（策略可能静默不生效）。')
  }

  if (policy.blocker !== 'off') {
    ctx.effect(() =>
      ctx.on('tools/pre-execute', async (exec, next) => {
        const matched = guard.enforcementMatches(exec)
        // 未命中必须委托下一环 —— 不拥有决策的 waterfall 监听器必须 return next()。
        if (matched.length === 0) return next()
        guard.recordEnforcement(exec, matched, 'blocker', policy.blocker)
        if (policy.blocker === 'deny') {
          return {
            kind: 'deny',
            reason: guard.enforcementReason(matched, 'blocker'),
            info: { name: exec.name, code: 'LOG_GUARD_BLOCKED' },
          }
        }
        if (policy.blocker === 'cancel') return { kind: 'cancel' }
        return {
          kind: 'ask',
          reason: guard.enforcementReason(matched, 'blocker'),
          displayReason: {
            en: `${label}: this call hits sensitive rule(s) ${matched.map((r) => r.id).join(', ')}. Approve to run it.`,
            zh: `${label}：该调用命中敏感规则 ${matched.map((r) => r.id).join(', ')}，批准后才会执行。`,
          },
        }
      }),
    )
    installed++
  }

  if (policy.jammer !== 'off') {
    ctx.effect(() =>
      ctx.on('tools/post-execute', async (exec, result, next) => {
        const matched = guard.enforcementMatches(exec)
        if (matched.length === 0) return next()
        guard.recordEnforcement(exec, matched, 'jammer', policy.jammer)
        return {
          kind: 'block',
          feedback: [{ type: 'text', text: guard.enforcementFeedback(exec, matched) }],
        }
      }),
    )
    installed++
  }

  return installed
}

/** Cordis 插件对象。 */
const plugin = {
  name: 'dsh-log-guard',

  /**
   * 插件装配。刻意不用对象级 `inject`：日志监控不依赖任何业务服务，
   * 一旦写进 inject，缺服务时整个插件会完全不 apply（告警就此静默失效）。
   * 需要的能力一律走 `ctx.get(...)` 可选读取。
   *
   * @param ctx Cordis 根上下文。
   * @param rawConfig Loader 传入的配置。
   */
  apply(ctx, rawConfig) {
    const config = normalizeConfig(rawConfig)
    if (!config.enabled) {
      process.stderr.write(`${STDERR_PREFIX} 已被配置禁用（enabled: false）。\n`)
      return
    }

    const guard = new LogGuard(ctx, config)

    // 卸载时停止轮询。
    ctx.effect(() => () => guard.stop())

    // ① 先试着注入一次 UI 横幅（若 webServer 已就绪，命中告警立刻能在界面弹出）。
    ensureUiBanner(ctx, guard, config)

    // ② 再补挂生命周期钩子：webServer 晚就绪也能补装路由，且不依赖任何业务服务的事件。
    guard.attachLifecycle()

    // ③ blocker / jammer（默认关闭；启用时才挂 tools/* 监听器）。
    const enforced = installEnforcement(ctx, guard, config)
    if (enforced > 0) {
      guard.warn(
        `执行策略已启用：blocker=${config.enforce.blocker} jammer=${config.enforce.jammer}` +
          ` 级别=${config.enforce.severities.join('/')}` +
          `${config.enforce.enforceArguments ? '（含参数匹配）' : '（仅工具名匹配）'}` +
          `，已挂 ${enforced} 个监听器。`,
      )
    }

    // ④ 启动轮询。
    guard.start()

    guard.warn(
      `已启动：每 ${config.scanIntervalMs}ms 扫描 ${config.watchSessionLogs ? '会话日志目录' : '指定文件'}` +
        `${config.files.length > 0 ? ` + ${config.files.length} 个显式文件` : ''}；` +
        `规则 ${guard.rules.length} 条；告警文件 ${config.alertFile ?? '(关闭)'}。`,
    )

    // 自检：monitor 到 0 个文件是最隐蔽的失效方式（插件"在跑"但什么都没看）。
    // 明确告警，而不是让用户以为它在工作。
    if (config.watchSessionLogs) {
      const found = guard.sessionFilesFound ?? 0
      if (found === 0) {
        guard.warn(
          `⚠ 在 ${config.sessionDir} 下没有找到任何 ${config.sessionFileNames.join(' / ')}（深度 ${config.maxSessionScanDepth}）。` +
            '插件当前没有监控任何会话日志！请确认 sessionDir 是否正确，或改用 files 显式指定文件。',
        )
      } else {
        guard.warn(`会话日志发现 ${found} 个文件，正在监控。`)
      }
    }
  },
}

export default plugin
export {
  LogGuard,
  normalizeConfig,
  normalizeEnforce,
  installEnforcement,
  scanText,
  buildRules,
  decodeZstd,
  prepareScanText,
  takeScanCounters,
  DEFAULT_RULES,
}
