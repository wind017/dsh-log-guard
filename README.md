# dsh-log-guard

DSH（DeepSeek Harness）Host 插件：**实时监听日志文件，检测敏感操作并显性告警。**

监听日志出现新内容时扫描其中的敏感操作 —— `cordis_define` / `cordis_run` /
`subprocess` / `pwsh` / `danger-full-access` 等 —— 命中后以四条通道**显性提示**用户，
而不是写一条没人看的日志。

```
日志文件(zstd/文本) ──tail──▶ 规则扫描 ──命中──▶ ① UI 告警横幅（界面可见）
                                              ├─▶ ② 告警文件 alerts.jsonl
                                              ├─▶ ③ 宿主 stderr 醒目行
                                              └─▶ ④ 可选提示音（页面合成）
```

## 为什么需要它

DSH 里最危险的几个能力，恰好都会在会话日志里留下痕迹：

| 操作 | 危险点 |
|---|---|
| `cordis_define` | 把**一段新代码**注入运行中的插件注册表 |
| `cordis_run` | 在宿主 `node:vm` 里跑动态插件，其声明的服务会触达真实运行时；官方文档明确写着"沙箱不是安全边界，请像对待 bash 访问一样对待动态包" |
| `subprocess` / `pwsh` | 在宿主上派生进程，可读写任意文件、发起网络请求 |
| `danger-full-access` | 文件沙箱等于关闭 |

这些操作本身是 DSH 的正常能力，但**它们必须是用户知情的**。本插件的作用就是：
只要它们出现在日志里，界面就会弹出告警横幅。

## 快速看效果

```powershell
node test/demo.mjs
```

它会造一份 10 行样本日志（5 行"不该报的" + 4 个真实工具调用 + 1 行纯文本），
跑**插件自己的代码**，把四条通道的真实输出打出来。详见下文「示例验证」。

## 安装

插件是标准的 DSH bundle（`package.json` 里的 `dsh.bundle.patch` + `cordis.patch.yml`），
不需要任何第三方依赖（只用 Node 内置模块）。

### 桌面端（Electron 客户端，当前环境）

**桌面端读的是 `desktop` profile，而 `dsh plugin` 命令行按设计拒绝碰它。**
已开源的同类插件（`dsh-whale-widget`）在文档里记录了这条约束：

```
error: profile "desktop" is managed exclusively by the Electron application
```

所以桌面端要在会话里让宿主内置的 `plugin_manager` 来装：

```
plugin_manager(action: "install_bundle", target: "link:<本目录绝对路径>")
```

### Web 形态（`dsh web`）

```powershell
dsh plugin --profile web add link:<本目录绝对路径>
```

`link:` 是软链安装：源目录改了立即生效，但**之后不能移动或重命名该目录**。
想改成拷贝安装用 `file:<目录>`。

### 生效方式

- `desktop` profile 是 live profile，管理操作**立即生效**；若界面没有反应，完全退出客户端（含托盘）再重开。
- `dsh web` 需要重启宿主。

> ⚠️ **改过 `index.mjs` 之后必须重启宿主。** 宿主进程的 ESM 模块缓存是**按 URL** 命中的，
> 实测 `disable → enable`、甚至 `remove bundle → 重新安装` 都**拿不到新代码**。
> 若之前那次加载是失败的，缓存里的坏模块不会因为重新启用而消失 —— 这时重启是唯一解。

### 装完怎么确认

1. **profile 里登记了**：`%USERPROFILE%\.dsh\profiles\desktop\package.json` 的
   `dsh.profile.bundles` 里应出现 `dsh-log-guard`。
2. **Loader entry 是 active**（不是 `failed`）：用 `plugin_manager(action: "list_plugins")` 查。
3. **宿主侧有启动横幅**：stderr 里会有一条带 `[DSH-LOG-GUARD]` 前缀的
   `已启动：每 1000ms 扫描 …；规则 14 条；告警文件 …`。
4. **常驻在线徽标**：启动后右下角应出现盾牌图标 + "dsh-log-guard 在线"的小徽标（可拖拽换位置、靠近边缘自动吸附）。
5. **真能报**：让 agent 跑一条 `pwsh`，右下角徽标应展开成告警横幅（点「详情」可看历史）。

## 配置

默认配置即可工作（自动跟随 `$DSH_HOME/sessions/**/session.v4.jsonl.zstd`）。
改配置在 profile 的 `cordis.patch.yml` 里按 entry id 覆写：

```yaml
- id: dsh-log-guard
  name: dsh-log-guard
  config:
    scanIntervalMs: 1000         # 轮询间隔（毫秒，最小 50）
    scanExisting: false          # 是否扫描历史内容（默认 false，只跟新增）
    watchSessionLogs: true       # 是否自动跟随会话日志目录
    files:                       # 额外显式监控的文件
      - "C:\\path\\to\\app.log"
    alertFile: null              # 告警文件；null = 关闭，默认 <DSH_HOME>/log-guard/alerts.jsonl
    notifySound: false           # 命中时由**页面**播放三声提示音（Web Audio，不弹窗）
    notifyCooldownMs: 30000      # 提示音冷却窗口
    notifyLog: "%USERPROFILE%\\.dsh\\log-guard\\notify.log"            # 提示音诊断日志；设 null 关闭
    printToHostConsole: true     # 命中时往宿主 stderr 打醒目行
    uiBanner: true               # 往界面注入告警横幅（显性告警主通道）
    audit: tool-calls            # 审计面：只审计工具调用（默认）；all-text 回退全文本
    ignoreSessionIds: []         # 额外忽略的会话 id
    ignoredStateFile: "%USERPROFILE%\\.dsh\\log-guard\\ignored-sessions.json"   # 自身会话 id 持久化；设 null 关闭
    maxPendingAlerts: 20         # 最多挂起多少条未提示告警
    dedupeWindowMs: 60000        # 同一命中的去重窗口
    # —— 拦截与阻断（默认关闭；开启才会挂 tools/* 监听器）——
    enforce:
      enabled: false             # 改成 true 才启用 blocker/jammer
      blocker: ask               # ask（询问后放行）| deny | cancel | off
      jammer: block              # block（阻断结果）| off
      severities: [critical]     # 只对 critical 生效（cordis_define / cordis_run）
      rules: []                  # 可选：只对这些规则 id 生效
      enforceArguments: false    # 默认只匹配工具名（避免误拦"写文件内容含敏感词"）
```

### 全部配置字段

| 字段 | 默认值 | 含义 |
|---|---|---|
| `enabled` | `true` | 置 `false` 时插件完全不接管 |
| `scanIntervalMs` | `1000` | 轮询间隔，最小 50ms |
| `scanExisting` | `false` | `true` 时首次加载会把历史日志全量扫一遍（首次会有一次告警高峰） |
| `watchSessionLogs` | `true` | 自动跟随 `sessionDir` 下的会话日志 |
| `sessionDir` | `$DSH_HOME/sessions` | 会话日志根目录 |
| `sessionFileNames` | `["session.v4.jsonl.zstd"]` | 要跟的文件名（**按名递归匹配，不假设路径深度**） |
| `maxSessionScanDepth` | `3` | 会话目录递归深度上限。真实布局 `slug/session/file` 需要 2 层，留 1 层余量 |
| `maxWatchedFiles` | `400` | 会话日志发现数量上限 |
| `files` | `[]` | 额外的显式文件路径（普通文本日志或 zstd 都可以） |
| `alertFile` | `$DSH_HOME/log-guard/alerts.jsonl` | 告警落盘位置，`null` 关闭 |
| `uiBanner` | `true` | 是否往界面注入告警横幅（常驻盾牌徽标，默认右下角，用户真正看得见的通道） |
| `audit` | `'tool-calls'` | **审计面**：只审计工具调用的名字与参数；`'all-text'` 回退到全文本扫描 |
| `notifySound` | `false` | 是否播放告警提示音（在**页面**用 Web Audio 合成三声，不弹任何窗口） |
| `notifyCooldownMs` | `30000` | 提示音冷却窗口：同一窗口内不重复发声 |
| `notifyLog` | `$DSH_HOME/log-guard/notify.log` | **提示音诊断日志**。见下文"为什么需要它"，`null` 关闭 |
| `printToHostConsole` | `true` | 是否往宿主 stderr 打印 |
| `maxPendingAlerts` | `20` | **未确认告警队列**上限（超出丢最旧的） |
| `dedupeWindowMs` | `60000` | 相同命中的去重窗口（毫秒，`0` = 不去重） |
| `unackedStateFile` | `$DSH_HOME/log-guard/unacked-alerts.json` | 未确认告警的持久化位置（跨重启常驻），`null` 关闭 |
| `ignoreSessionIds` | `[]` | 额外要忽略的会话 id 列表（按路径子串或文件头 id 匹配） |
| `ignoredStateFile` | `$DSH_HOME/log-guard/ignored-sessions.json` | 自身会话 id 的持久化位置（消除启动空窗），`null` 关闭 |
| `ignoreBefore` | `0` | 跳过每个日志文件开头 N 个字符（会话头含 cwd 等噪声，可设几百） |
| `disabledRules` | `[]` | 关掉某些内置规则（填规则 id） |
| `replaceDefaultRules` | `false` | `true` 时只用 `rules` 里的自定义规则 |
| `rules` | `[]` | 追加自定义规则（见下） |
| `enforce.enabled` | `false` | **是否启用 blocker/jammer**（默认关闭，见下文「拦截与阻断」） |
| `enforce.blocker` | `'ask'` | 拦截方式：`ask`（询问后放行）/ `deny` / `cancel` / `off` |
| `enforce.jammer` | `'block'` | 结果处置：`block`（阻断结果）/ `off` |
| `enforce.severities` | `['critical']` | 只对这些级别生效（默认仅 `cordis_define` / `cordis_run`） |
| `enforce.rules` | `[]` | 只对这些规则 id 生效（空 = 由 severities 决定） |
| `enforce.enforceArguments` | `false` | 是否连**参数文本**一起匹配（默认只匹配工具名，见下文） |

### 自定义规则

`rules` 是追加式规则，`pattern` 用字符串写正则（JSON 里没法写正则字面量）：

```yaml
- id: dsh-log-guard
  name: dsh-log-guard
  config:
    rules:
      - id: custom-rm-rf
        pattern: "rm\\s+-rf"
        severity: high
        description: "递归强删"
      - id: custom-exfil
        pattern: "(curl|Invoke-WebRequest).{0,40}(\\.credentials|api[_-]?key|token)"
        severity: critical
        description: "疑似凭据外传"
      # tool 规则只匹配真正的 tool/call 事件
      - id: custom-browser
        tool: browser_use
        severity: medium
        description: "浏览器操作"
```

## 内置规则（14 条）

| 规则 id | 级别 | 命中条件 |
|---|---|---|
| `cordis-define` | critical | 出现 `cordis_define` |
| `cordis-run` | critical | 出现 `cordis_run` |
| `cordis-toolset` | high | `cordis_inspect` / `cordis_stop` / `cordis_undefine` 等 |
| `subprocess-service` | high | 出现 `subprocess` |
| `tool-pwsh` | high | 真正调用了 `pwsh` 工具 |
| `shell-command` | high | `spawn` / `execFile` / `child_process` / `CreateProcess` 等进程创建原语 |
| `tool-run-code` | high | 真正调用了 `run_code` |
| `tool-workflow` | medium | 真正调用了 `workflow` |
| `tool-subagent` | medium | 真正调用了 `subagent` |
| `sandbox-relax` | high | 出现 `danger-full-access` |
| `plugin-mutation` | medium | `plugin_manager` / `install_bundle` / `remove_bundle` 等 |
| `credential-access` | high | `.credentials.yaml` / `deepseekAccount` / 授权流程事件 |
| `network-egress` | low | `curl` / `wget` / `Invoke-WebRequest` / 任意 URL |
| `self-modify` | medium | 改动 `cordis.patch.yml` / `cordis.yml` / profile 的 `package.json` |

## 示例验证

`node test/demo.mjs` 会造一份 10 行样本日志，跑插件自己的代码，打印四条通道的实际输出。

**样本（10 行）**

```
 1. {"type":"user/message","data":{"text":"帮我写个监听 cordis_define 和 subprocess 的插件"}}
 2. {"type":"assistant/message","data":{"content":[{"type":"text","text":"cordis_run 会执行动态代码"}]}}
 3. {"type":"tool/result","data":{"content":[{"type":"text","text":"cordis_define cordis_run subprocess ..."}]}}
 4. {"type":"system/message","data":{"text":"file policy: workspace-write; sandbox 可放宽到 danger-full-access"}}
 5. {"type":"request/context","data":{"text":"plugin_manager / deepseekAccount / cordis.yml"}}
 6. {"type":"tool/call","data":{"name":"pwsh","callId":"call_demo_1","arguments":"{\"command\":\"Get-ChildItem -Recurse\",...}"}}
 7. {"type":"tool/call","data":{"name":"cordis_define","callId":"call_demo_2","arguments":"{\"code\":\"ctx.log(...)\"}"}}
 8. {"type":"tool/call","data":{"name":"subprocess","callId":"call_demo_3","arguments":"{\"command\":\"whoami\"}"}}
 9. {"type":"tool/call","data":{"name":"cordis_run","callId":"call_demo_4","arguments":"{}"}}
10. 2026-01-01 12:00:00 WARN 外部脚本调用了 rm -rf 与 spawn
```

**结果**

```
结果：审计 4 次工具调用，排除 5 个非工具事件
      命中 5 条告警
```

| 行 | 期望 | 实际 |
|---|---|---|
| 1–5（消息 / 结果 / 系统提示 / 上下文） | 静默 | ✓ 排除 5 个非工具事件 |
| 6 `pwsh` | 告警 | ✓ `tool-pwsh`(high) |
| 7 `cordis_define` | 告警 | ✓ `cordis-define`(critical) |
| 8 `subprocess` | 告警 | ✓ `subprocess-service`(high) |
| 9 `cordis_run` | 告警 | ✓ `cordis-run`(critical) |
| 10 纯文本含 `spawn` | 告警 | ✓ `shell-command`(high) |

**通道 1：宿主 stderr（你在宿主日志里会看到的）**

```
[DSH-LOG-GUARD] [严重] cordis-define :: ..."type":"tool/call","name":"cordis_define" args:{"code":"ctx.log(...)"} ...
[DSH-LOG-GUARD] [严重] cordis-run :: ..."type":"tool/call","name":"cordis_run" args:{} {} 2026-01-01 ...
[DSH-LOG-GUARD] [高] subprocess-service :: ..."type":"tool/call","name":"subprocess" args:{"command":"whoami"} ...
[DSH-LOG-GUARD] [高] tool-pwsh :: pwsh "type":"tool/call","name":"pwsh" args:{"command":"Get-ChildItem -Recurse",...
[DSH-LOG-GUARD] [高] shell-command :: ...{} 2026-01-01 12:00:00 WARN 外部脚本调用了 rm -rf 与 spawn
```

摘录刻意**以命中串为中心**，所以每行都能直接看到"报的是什么"。

**通道 2：告警文件 `alerts.jsonl`（一行一条 JSON）**

```json
{"time":"2026-01-01T00:00:00.000Z","severity":"critical","ruleId":"cordis-define",
 "description":"动态 Cordis 包定义…","sources":["log-guard-demo-xxxx/session.v4.jsonl.zstd"],
 "matched":"cordis_define","snippet":"…","fingerprint":"1a2b3c4d"}
```

**通道 3：UI 告警横幅**（常驻盾牌徽标 + 可拖拽吸附 + **命中后常驻直到确认** + 内联详情）

插件通过 `webserver/index-inject` 往页面注入一段脚本。**启动后常驻一个在线徽标**
（盾牌图标 + "dsh-log-guard 在线"，默认右下角 —— 右上角会被窗口标题栏按钮遮挡），
**可拖拽换位置、松手靠近屏幕边缘自动吸附**，位置存 localStorage 下次启动恢复。

脚本每秒轮询 `/dsh-log-guard/alerts.json`。命中后徽标展开成红边 banner，并且
**不会自动收起** —— 只要还有未确认的告警就一直挂着，直到用户点「已确认」。

```
收起态（启动后常驻）：
┌────────────────────────────┐
│ 🛡 dsh-log-guard 在线        │
└────────────────────────────┘

展开态（命中告警后｜常驻直到确认）：
┌──────────────────────────────────────────────┐
│ 🛡 安全告警 · dsh-log-guard  详情  已确认     │
│ 检测到 2 条敏感操作（需确认后才会收起）        │
│ ┌──────────────────────────────────────────┐ │
│ │ [严重] cordis-run  动态 Cordis 包运行      │ │
│ │ 命中：{"name":"cordis_run",…}             │ │
│ │ 来源：session-xxxx/session.v4.jsonl.zstd   │ │
│ └──────────────────────────────────────────┘ │
│ ┌──────────────────────────────────────────┐ │
│ │ [高] tool-pwsh  PowerShell 命令执行        │ │
│ │ 命中：{"command":"whoami",…}              │ │
│ └──────────────────────────────────────────┘ │
└──────────────────────────────────────────────┘
```

**「详情」是内联展开**，不打开新标签：

- **为什么**：Electron 主进程用 `setWindowOpenHandler` 返回 `{ action: 'deny' }`
  （只有 `https:` 才走 `shell.openExternal`），所以 `target="_blank"` 打开相对路径
  **必然被拒** —— 这正是它曾经"点了没反应"的原因。
- **现在**：点「详情」在 banner 内用 `<iframe>` 加载 `/dsh-log-guard/history`
  （同源，不受窗口打开策略限制），再点变为「收起详情」。

**「已确认」** 会 `POST /dsh-log-guard/ack` 清空未确认队列，横幅随之收起。
未确认队列由服务端持有并持久化，所以**刷新页面或重启宿主都不会让告警"自己消失"**。

**通道 4：提示音** —— `notifySound: true` 时响三声（高-低-高，1200/800/1200Hz）。

> 声音由**页面**用 Web Audio 合成（`OscillatorNode`），**不弹任何窗口**。
> 早先用 powershell 做 `[console]::beep()` + `MessageBox`，问题有三：
> 1. 弹框是**模态**的，会把界面按住（实测一次等 6.7 秒）；
> 2. `spawn` 的 spec 与 `SubprocessSpawnSpec` 契约不符，日志只显示"已启动"却根本没响；
> 3. 声音与界面分属两个世界，音量/静音无法统一控制。
>
> 页面负责判断"有没有新的一批"：轮询响应里带 `seq`，只有 `seq` 变化才发声，
> 所以同一批告警不会因为每秒轮询而重复响；`notifyCooldownMs` 再加一层限流。
>
> ⚠️ **浏览器自动播放策略**：`AudioContext` 初始是 `suspended`，必须有**一次用户手势**
> 才能出声。脚本会在首次点击/按键页面时 `resume()` 一次，此后一直可用。
> 也就是说：**页面刚打开、你还没点过任何地方时，第一批告警可能只弹横幅不出声** ——
> 与 `dsh-whale-widget` 面对的是同一条浏览器限制。
>
> 打开方式（profile 的 `cordis.patch.yml`）：
>
> ```yaml
> - id: dsh-log-guard
>   disabled: false
>   config:
>     notifySound: true
> ```
>
> 改完**需要重启宿主**（宿主 ESM 缓存，见上文「生效方式」）。
> 独立验证：`node test/beep-live.mjs` —— 它在 Node 里用假 DOM + 假 AudioContext
> 执行真正送到页面的那段脚本，断言"新一批 → 合成三声 1200/800/1200Hz、同批次不重复"。

### 为什么需要 `notifyLog`

提示音是**纯感官输出**，插件侧没有可观察状态，于是"我没听到"根本无法区分是哪种情况：

| 可能 | 现象 |
|---|---|
| 压根没触发 | 没有告警 |
| 页面没打开 / 注入行没生效 | 无声 |
| 浏览器自动播放策略挡着（还没点过页面） | 无声 |
| `AudioContext` 不可用 | 无声 |
| 冷却窗口内被限流 | 无声（正常） |
| 真响了但你没注意 | 让你白查 |

所以每次决策都会往 `notify.log` 追加一行，`tab` 分隔：

```
2026-10-12T13:16:40.863Z	sound-signal	uiSeq=1 条数=3
2026-10-12T13:16:41.010Z	sound-skipped	冷却窗口内
```

结果代号：

| 代号 | 含义 |
|---|---|
| `sound-signal` | 已发出"该响一批"的信号（`uiSeq` 与条数一并记录） |
| `sound-skipped` | 冷却窗口内，未重复发信号（正常行为） |

> 服务端只负责**发信号**（推进 `uiSeq` 并记一行），真正的发声在页面里，
> 由 `seq` 变化触发。这条分工带来的好处是：宿主侧不再 spawn 任何进程，
> "配了却不响"也因此不再可能由 spawn 的 spec 不合法引起。
>
> 关掉它：`notifyLog: null`。

## 审计面：只审计"工具调用"（默认）

这是实现里最重要的一个设计决定。

**危险操作只能通过工具真正执行。** 对话里说一万遍 `cordis_define` 也不会有任何代码被注入；
真正注入必须**调用** `cordis_define` 工具。所以审计面 = **工具调用的名字 + 参数**：

```
"type":"tool/call","name":"pwsh"  args:{"command":"whoami"}
```

由此天然免疫三类噪声：

| 噪声 | 为什么免疫 |
|---|---|
| 自我触发 | 插件不会把"你我在对话里**讨论**敏感词"当成敏感操作 |
| 结果回显 | `tool/result` 会列出 `cordis_define` 之类的工具名，但那是输出不是操作 |
| 任务提示/系统上下文 | 里面的 `danger-full-access` 等字样只是描述，不是调用 |

实测（`node test/real-log-compare.mjs`，对 7 份真实会话日志全量扫描）：
`tool-calls` 模式下约 **930 条**工具调用进入审计面，真调用的检测能力没有丢。

### 代价（必须知道的取舍）

只审计工具调用意味着：**以文本形态出现在非工具事件里的迹象不再告警**，例如
审批决策记录、沙箱模式变更记录。**纯文本日志（非 JSONL）始终按文本审计**，不受影响。

想恢复旧的"全文本扫描"：`audit: 'all-text'`。

### 为什么始终忽略自身会话

实测过"审计**本次对话自己**"：**仍然吵**。

原因不是消息文本，而是——当这次对话本身在开发/调试这个插件时，
`write` / `edit` / `subagent` / `workflow` 的**参数里**带着对话摘录和规则定义，
里面到处是 `cordis_define`、`danger-full-access`。

这一点必须说清：**那是真实的工具调用，告警是对的**（参数里确实出现了这些串）。
但"整轮都在处理敏感词相关文本"的会话会因此自我触发、吵个不停，所以本插件
**始终忽略自身会话**（不再提供关闭开关），只监控其它会话。

### 自身识别怎么做到"启动即生效"

识别自身会话有三条通道，缺一不可：

| 通道 | 时机 | 可靠性 |
|---|---|---|
| `process.env.DSH_SESSION_ID` | 立即 | 视环境而定 —— 它是 harness 注入给 bash/pwsh **子进程**的变量，**Host 主进程里没有**，但**工具子进程里有** |
| `ignoredStateFile` 持久化 | **启动瞬间** | 高 —— 同一会话跨重启 id 不变，上次记下的这次直接读回 |
| `session/event` 事件 | 首个事件到达时 | 高 —— 作为前两者的兜底与校正 |

> `DSH_SESSION_ID` 这条通道**没有配置开关**。因此在工具子进程里跑脚本时，自身会话会被它静默跳过 ——
> 若要做"故意连自身一起审计"的对比，需要像 `test/real-log-compare.mjs` 那样临时
> `delete process.env.DSH_SESSION_ID`。

**为什么需要持久化那条**：只靠环境变量 + 事件会留下一个**启动空窗** ——
插件刚启动、首个事件还没来之前，自身会话仍会被扫描，表现就是"重启后头几轮自己报自己"。
把已识别的自身会话写进 `ignoredStateFile`，重启后立刻读回，空窗即消失。

```
$DSH_HOME/log-guard/ignored-sessions.json
{ "updatedAt": "…", "sessionIds": ["session-…"] }
```

文件读失败或损坏一律当作空，不影响启动；不想落盘就设 `ignoredStateFile: null`
（代价是每次重启重现启动空窗）。

## 拦截与阻断（blocker / jammer）

默认关闭。开启后插件从"检测器"升级为"策略执行器"，改变宿主的实际行为。

| 角色 | 挂载点 | 作用 | 默认 |
|---|---|---|---|
| **blocker** | `tools/pre-execute` waterfall | 命中时返回 `ask` → 宿主弹审批，**用户批准才执行** | 开（`ask`） |
| **jammer** | `tools/post-execute` waterfall | 命中时返回 `block` + feedback → **模型只看到"已阻断"，看不到真实输出** | 开（`block`） |

### 为什么用 `ask` 而不是 `ctx.tools.guard()`

`ctx.tools.guard()` 是**同步**的：它只能返回一个字符串来拒绝，无法等待用户，而且**单调不可覆盖**
（任何 guard 都能拒，没人能强制放行）。而"询问用户后放行"必须能 await —— 只有
`tools/pre-execute` 返回 `{ kind: 'ask' }` 才做得到。

> ⚠️ 宿主在没有审批支持时会把 `ask` **转成拒绝**（fail-closed）。这是预期行为：
> 无人值守场景下宁可拒绝，也不静默放行。

### 为什么默认只按「工具名」匹配

`enforce.enforceArguments` 默认 `false`：只拿**工具名**去匹配规则。

- critical 规则本身就是工具名（`cordis_define` / `cordis_run`），按名字匹配**零误报**；
- 若默认扫参数，**编辑本插件源码**（`write` 的 content 里就写着 `cordis_define` 这些字面量）
  会被自己拦住，等于自锁。

需要更严格时显式打开，并接受"写文件内容含敏感词也会被拦"的噪声。

### 为什么不能改写参数

`tools/execute` 的契约写明：**调用身份不可变**，包装器只能替换 `exec.signal`。
所以"jammer = 消毒命令参数"这条路不成立 —— 可行的只有"执行后把结果封存"。
这也是本插件选择 `block` + feedback 的原因。

### 一次完整交互长什么样

```
模型要调用 cordis_define
  → blocker 返回 ask
  → 宿主弹出审批：「dsh-log-guard：该调用命中敏感规则 cordis-define，批准后才会执行。」
  → 用户批准 → 调用执行
  → jammer 在 post-execute 返回 block
  → 模型收到：
      【dsh-log-guard 已阻断本次调用的结果】
      工具：cordis_define
      命中规则：cordis-define(critical)
      该调用可能已经实际执行，但它的输出被策略封存，不会进入你的上下文。
```

同时这次拦截会**进入告警通道**（横幅、`alerts.jsonl`、提示音），来源标记为 `tool:cordis_define`。

### 开启方式

```yaml
- id: dsh-log-guard
  disabled: false
  config:
    enforce:
      enabled: true
      blocker: ask        # 想硬拦就改 deny（不可放行）
      jammer: block
```

改完**需要重启宿主**（宿主 ESM 缓存，见「生效方式」）。

## 实现要点

- **多帧 zstd**：会话日志是**多帧拼接**的 zstd（实测一份 306KB 的日志有 136 个帧）。
  Node 内置的 `zstdDecompressSync` **只解第一帧**，直接用它只能读到 248 字节的会话头。
  本插件自行按魔数 `28 B5 2F FD` 切帧后逐帧解压，2273/2273 帧全部成功。
- **增量 tail**：每个文件维护"已解码文本 + 扫描游标"，只把新增部分送进规则引擎。
- **游标只进不退**：半截的 zstd 帧**不抛错，只贡献 0 个字符**，于是解码文本会比上一轮**变短**。
  早期实现在这里把游标重置为 0，导致下一轮**整份历史重扫** —— 症状是同一批历史告警
  每隔一分钟重复注入一次。现在游标单调前进，本轮少解出的等下一轮补全。
- **整行边界**：只扫描**已完结的行**。半截帧会解出"没有换行的半行 JSON"，
  若游标越过它，等帧补全后新增的那段就落在行中间、解析失败 → **告警被静默丢掉**。
- **会话日志发现必须递归**：真实布局是 `<sessionDir>/<workspace-slug>/<session-id>/<file>`
  —— **三层**。早期实现按 `<sessionDir>/<dir>/<file>` 拼路径，拼出来的全是不存在的路径，
  `consume()` 逐个 stat 失败后静默返回：插件"在运行"却一条都不报。现在按文件名有界递归，
  并且**启动时自检**：一个文件都没发现就打醒目 warn。
- **告警横幅走 `webserver/index-inject`**：学 `dsh-whale-widget` 的桌面端唯一注入通道
  —— 往 index.html 推一行内联 script，吞掉 onerror，路由在就加载、不在就静默失败，
  宿主永远不会因为横幅起不来。
- **告警由页面轮询拉取，且常驻到确认**：页面 banner 每秒 fetch
  `/dsh-log-guard/alerts.json`，取的是**未确认队列**（服务端持有并持久化）。
  旧实现是"取走即清"（`drainAlerts()`），导致告警一闪而过、刷新页面就消失；
  现在只有用户点「已确认」（`POST /dsh-log-guard/ack`）才会收起。
- **声音与界面同源**：提示音由页面用 Web Audio 合成，服务端只推进 `seq` 发信号。
  宿主侧不 spawn、不弹窗 —— 既避免了模态弹框按住界面，也消除了
  "spawn spec 不合法导致静默不响"整类问题。
- **零依赖**：只用 `node:fs` / `node:zlib` / `node:path` / `node:os`。
- **不写对象级 `inject`**：`webServer` 等一律用 `ctx.get(...)` 可选读取 ——
  一旦写进 `inject`，缺服务时整个插件会**完全不 apply**，告警就此静默失效。
- **不依赖 Cordis 定时器**：用 `globalThis.setInterval`。`ctx.setInterval` 是 `timer`
  服务上的属性访问，实测会抛 `cannot get property "timer" without inject` 让插件
  activate 失败；而加对象级 `inject` 又会让缺服务时插件完全不 apply。
- **自我识别靠文件头**：自身会话识别最初读 `process.env.DSH_SESSION_ID`，但那是 harness
  注入给 bash/pwsh **子进程**的变量，Host 主进程里没有 → 静默失效。改为读会话日志
  第一帧的 `{"type":"session",...,"id":...}`，并订阅 `session/event` 做自我修复。
- **绝不因配置炸掉**：所有配置字段都有默认值与类型校验，非法值回落默认值。

## 自测

```powershell
node test/run-tests.mjs         # 73 项主测试
node test/enforce-verify.mjs    # 拦截验收：打印 blocker/jammer 的真实决策形态
node test/routes-verify.mjs     # 路由层验收：直接调 handler 验 /alerts.json、/ack、/history、banner.js
node test/demo.mjs              # 示例验证：造样本日志，打印四条通道的实际输出
node test/beep-live.mjs         # 音效验证：假 DOM+假 AudioContext 跑 banner 脚本，断言三声
node test/final-check.mjs       # 用真实默认配置端到端核验
node test/live-alert-verify.mjs # 真告警验证：忽略自身、但仍报他人的真实操作
node test/real-log-compare.mjs  # 对真实日志对比两种审计面的噪声与检出
```

> 所有验收脚本都通过 `test/_isolation.mjs` 把状态文件重定向到临时目录 ——
> 否则它们会往你真实的 `~/.dsh/log-guard/` 里写（实测报过 EPERM）。

73 项主测试覆盖：规则匹配、审计面语义、误报回归（结果回显 / 对话文本）、告警渲染、
多帧 zstd 解码（拿真实日志当样本）、tail 增量、半行边界、去重、配置回落、
嵌套目录发现、横幅路由与注入行、生命周期补装与卸载、提示音信号与常驻队列、
blocker/jammer 的决策形态与委托纪律，以及针对真实事故的回归：

| 回归 | 盯死的事故 |
|---|---|
| UI 横幅经 `index-inject` 注入 | 旧实现走 `systemPrompt.context` 注入，聊天流默认不渲染 → 用户看不见 |
| 会话日志发现必须支持三层嵌套 | 插件"在运行"却一个文件都没监控 |
| zstd 半截帧不得重扫历史 | 同一批历史告警反复注入 |
| 纯文本截断不得重扫 | 同上（纯文本路径的同类问题） |
| 靠日志文件头识别自身会话 | 自身识别读了一个 Host 里不存在的环境变量，静默失效 |
| 启动即忽略已知自身会话 | 只靠事件识别 → 重启后首个事件之前"自己报自己" |
| 把对话内容当参数传给工具仍告警 | 明确"残留限制是正确行为"，避免以后被误当 bug 修掉 |
| 审计计数不得滞后一轮 | 计数在 `scanText` 里递增，却在扫描之前被取走 → tick#1 报 0 |
| 告警摘录必须以命中串为中心 | 只取"命中前 80 字符"会把命中串挤出可见范围，告警看不出报了什么 |
| **宿主侧不再 spawn 任何子进程** | 声音曾被 powershell 承担，且 spawn spec 不合法 → 日志"已启动"却没响 |
| **告警常驻展示直到确认** | 旧 `drainAlerts()` 取走即清 → 告警一闪而过、刷新即消失 |
| **未确认告警跨重启保留** | 状态只在内存里 → 重启后用户还没看到的告警就没了 |
| 未确认队列有上限 | 无限增长 → 横幅越堆越长 |
| **默认不启用执行策略** | 检测器擅自变成拦截器会改变宿主行为，必须显式开启 |
| **只按工具名匹配** | 扫参数会让"编辑本插件源码"被自己拦住（自锁） |
| **未命中必须委托 `next()`** | 不拥有决策的 waterfall 监听器若吞掉调用，会废掉所有其它工具 |

## 已知边界

- **默认是检测器，不是拦截器。** 未启用 `enforce` 时命中只告警，不阻止操作；
  轮询间隔内操作可能已执行完。启用 blocker/jammer 后才会真正干预（见「拦截与阻断」）。
- **`ask` 依赖宿主审批支持。** 没有审批能力时宿主会把 `ask` 转成拒绝（fail-closed）；
  无人值守场景下这意味着"直接不执行"，而不是"静默放行"。
- **jammer 不能回滚副作用。** 它只在 `post-execute` 封存结果，调用本身**已经执行过**；
  文件已写、命令已跑、进程已起都收不回来。要真正阻止必须靠 blocker。
- **不能改写参数。** `tools/execute` 的契约规定调用身份不可变（只能换 `exec.signal`），
  所以无法做"命令消毒"。
- **规则是字面匹配。** 换个写法、拼接字符串、base64 一下就绕过。它挡的是"顺手的危险操作"，
  不是有意的规避。
- **`scanExisting: false` 是默认值**，即不追诉历史。想审计已有日志就打开它。
- **zstd 会话日志是整文件解的**：帧边界无法从任意字节偏移切入，所以每次轮询都会重新解压
  整个文件（再靠游标只扫描新增部分）。活跃会话日志到 MB 级时有可感知开销，
  此时可把 `scanIntervalMs` 调大。纯文本日志是按字节增量读的，不受此影响。
- **纯二进制日志**（非 JSONL、非 zstd）会被按 UTF-8 尽力解码，通常匹配不到东西。
- **只有 `webServer` 是可选依赖**：取不到时告警仍会写文件与 stderr，
  只是弹不出横幅（并会打一条 warn 说明）。
- **改 `audit` 需要重启**才能切换（宿主 ESM 缓存，见上文「生效方式」）。

## 参考

实现所依据的 DSH 插件契约、日志格式与官方文档出处，见 [REFERENCE.md](./REFERENCE.md)。
