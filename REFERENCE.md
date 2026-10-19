# REFERENCE —— 实现依据与出处

这份文件记录 `dsh-log-guard` 每一处实现所依据的**已验证事实**，以及参考的开源项目。
目的：让别人（或未来的自己）能复核"为什么这么写"，而不是靠猜。

所有"验证方式"栏里的命令都可以直接复跑。

---

## 1. 参考的开源项目

### dsh-whale-widget（DSH 插件契约的权威参考实现）

- 仓库：<https://github.com/MeteorNOX/DeepSeek-Balance-Whale-Widget>
- npm：<https://www.npmjs.com/package/dsh-whale-widget>（已发布到 0.4.2，MIT）
- 本地已安装副本（本机 profile 里就有）：
  `%USERPROFILE%\.dsh\profiles\desktop\node_modules\dsh-whale-widget\`

它虽然是个余额挂件，但**它是最完整的公开 DSH 插件范本**，本插件从它这里确认了：

| 确认的事实 | 出处 |
|---|---|
| 插件包的 `package.json` 形态：`type: module`、`main: lib/index.js`、`dsh.bundle.patch` 指向 patch 文件 | `package.json` L12-L33 |
| `cordis.patch.yml` 的写法：顶层数组 + `- insert: [{id, name}]` | `cordis.patch.yml` |
| Host 插件入口形态：`export default { name, apply(root) {...} }`，`apply` 收到的是 **root 上下文** | `lib/index.js` L649-L657 |
| **对象级 `inject` 的陷阱**：写进 `inject` 会把整个 `apply()` 推迟到服务就绪之后；服务缺失时插件**完全不 apply**（作者为此专门写了注释说明 issue #154/#136 的教训） | `lib/index.js` L651-L675、L1064-L1065 |
| 局部等待的正确写法：`root.inject(['svc'], (ctx) => {...})`、可选服务用 `ctx.get('svc')` | `lib/index.js` L675、L1064 |
| 资源清理写法：`root.effect(() => () => {...})` | `lib/index.js` L659 |
| **桌面端 profile 的特殊约束**：`dsh plugin --profile desktop` 会被拒绝，报 `profile "desktop" is managed exclusively by the Electron application`；桌面端必须用宿主内置 `plugin_manager` | npm README 安装章节 |
| `link:` / `file:` / `github:` 安装语义，以及"link 后不能移动目录" | npm README 安装章节 |

> 上表引用的 README 内容来自 npm registry（`https://registry.npmjs.org/dsh-whale-widget`）。
> 它同时揭示了本插件同样的安装约束，所以本插件 README 的桌面端安装步骤照此修正。

---

## 2. Host 插件契约（本地实测）

### 2.1 Inspect Provider 目录

本机 Host 提供 4 个只读 Inspect Provider：`Service` / `Event` / `Config` / `Tool`。
工具自述里明确写了："Call this Tool before writing or configuring a plugin，
then select the provider and method for `cordis_inspect_query`。"

### 2.2 `systemPrompt` 服务（⚠️ 已弃用：注入的是隐藏上下文，用户看不见）

> **弃用原因**：`context()` 注册的是"动态运行时上下文"，宿主渲染成
> `Current runtime context…` 快照喂给模型，**聊天流默认不渲染**。唯一让它显性的
> 是模型"自觉复述"，不可靠 —— 用户实测"命中后界面啥都没有"。现已改用
> UI 告警横幅（`webserver/index-inject` 注入脚本 + `webServer.register` 路由，见 2.5）。
> 下面保留其契约作为历史记录。

用 `cordis_inspect_query(platform: "host", provider: "Service", method: "listService",
input: {service: "systemPrompt"})` 取到的精确契约：

```
method:   context(context: PromptContext): () => void
描述:     Register ordered dynamic context in the calling context's scope.
          Scoped entries shadow global entries with the same name.
returns:  the exact Cordis effect disposer.

PromptContext = {
  readonly name: string
  readonly order: number
  readonly text: string | ((context: AssembleContext) => string)
}

AssembleContext = { scope?: ScopeKey; signal?: AbortSignal }
PromptAssembly  = { sections, contexts, tools, variables }
```

由此确定：

- 用 `context()` 而**不是** `section()` —— 告警是动态运行时上下文，不是静态提示段。
- `text` 可以是**函数**，所以告警实现了"只提示一次"：但 `text` 的契约是
  `string | (ctx) => string`，**必须返回字符串**。宿主 `interpolate()` 会对返回值直接调
  `text.indexOf("{{")`，返回 `undefined` 会抛
  `Cannot read properties of undefined (reading 'indexOf')` 让整轮失败。
  无告警时应返回**空字符串 `''`**，宿主在 `filter(text.length > 0)` 处丢弃它。
  （"返回 undefined = 不进入上下文"这个行为只对 `variable()` 的 provider 成立，
  对 `context().text` 不成立 —— 这是本插件早前踩过的坑。）
- 返回的是 **effect disposer**，所以必须放进 `ctx.effect(...)` 里，随插件卸载自动撤销。

访问方式由服务契约自己给出：

```
optional:        ctx.get("systemPrompt")   （requiresUndefinedCheck: true）
hardDependency:  inject: ["systemPrompt"]  →  ctx.systemPrompt
```

本插件选 `ctx.get(...)`：`inject` 会让缺服务时插件完全不 apply，告警静默失效。

### 2.3 Host 事件（竞态兜底）

用 `cordis_inspect_query(platform: "host", provider: "Event", method: "listEvents")` 确认存在：

| 事件 | 模式 | 签名 |
|---|---|---|
| `app-boot/config-reload` | emit | `(): void` —— "Profile patches were reconciled into the running Loader tree" |
| `agent/created` | serial | `(this: Scoped<Agent>, payload: {agent, source, signal?})` |
| `session/created` | emit | `(this: Scoped<Session>, session: Session)` |

这三个事件**都不属于任何业务服务**，因此拿它们做"`webServer` 晚就绪时补装"是安全的：
不会因为某个服务缺失而永远等不到。

### 2.4 其他被引用的服务

| 服务 | 用法 | 契约 |
|---|---|---|
| `subprocess` | 可选，仅用于 `notifySound` 蜂鸣 | `spawn(spec: SubprocessSpawnSpec): SubprocessHandle` |
| `webServer` | 可选，UI 横幅路由 | `register({path, handler}): disposer`、`tapIndex((html) => html): disposer`（依据 dsh-whale-widget 实测） |
| `timer` | Cordis 注入的定时器 helper | `interval(callback, delay): () => void` → 插件里用 `ctx.setInterval` |

### 2.5 UI 告警横幅的注入通道（依据 dsh-whale-widget 实测）

桌面端与 web 形态的注入通道不同，都已在 `dsh-whale-widget` 上跑通：

| 通道 | 形态 | 写法 | 说明 |
|---|---|---|---|
| `webserver/index-inject` | 桌面端唯一 | `ctx.on('webserver/index-inject', (table) => table.push({kind:'script', placement:'body', text}))` | 桌面壳 index.html 从静态 dist 直出，`tapIndex` 过不去；宿主启动时**只收集一次**注入表 |
| `webServer.tapIndex` | web 形态 | `ctx.webServer.tapIndex((html) => html.replace('</body>', tag + '</body>'))` | 函数变换 index.html |

`webServer.register({ path, handler })` 注册 HTTP 路由（handler 为 `async (req, res)`，
用 `res.writeHead(200, headers)` + `res.end(body)` 响应），返回 disposer。banner.js 由
`/dsh-log-guard/banner.js` 路由提供，页面脚本轮询 `/dsh-log-guard/alerts.json` 拿告警。

### 2.6 拦截与阻断用的工具管线事件（本地实测）

blocker/jammer 依赖三条 `tools/*` waterfall，契约由 `cordis_inspect_query(provider: "Event")` 读出：

```ts
// 拦截：可返回 allow / deny / cancel / ask
'tools/pre-execute'(
  this: Scoped<ToolRuntime>,
  exec: ToolExecution,
  next: () => Promise<PreToolDecision>,
): Promise<PreToolDecision>

type PreToolDecision =
  | { kind: 'allow' }
  | { kind: 'deny'; reason: string; info?: ToolErrorInfo }
  | { kind: 'cancel' }
  | { kind: 'ask'; reason?: string; displayReason?: { en: string; [locale: string]: string } }
```

```ts
// 执行：包装器**只能替换 exec.signal**，调用身份（名字/参数）不可变
'tools/execute'(this, exec: ToolDispatchExecution, next): Promise<ToolExecutionResult>
```

```ts
// 结果处置：accept / replace / enrich / block
'tools/post-execute'(
  this, exec: ToolExecution, result: Readonly<ToolExecutionResult>, next,
): Promise<PostToolDecision>

type PostToolDecision =
  | { kind: 'accept'; content?: ContentBlock[]; additionalContexts?: UserMessage[] }
  | { kind: 'accept'; value: JsonValue; additionalContexts?: UserMessage[] }
  | { kind: 'block'; feedback: ContentBlock[]; additionalContexts?: UserMessage[] }
```

配套的 `tools` Service：

```
guard(guard: ToolGuard): () => void          // 同步、单调；返回字符串即拒
restrict(filter: ToolRestriction): () => void // 只能隐藏工具
get(name, scope?): ToolDefinition | undefined
```

**由此确定的三条设计约束**：

1. **"询问后放行"只能用 `ask`**。`ctx.tools.guard()` 是同步的，无法等待用户；
   `deny` 又不可覆盖。事件说明还明确：*missing approval support turns `ask` into denial*（fail-closed）。
2. **参数不可改写**。`tools/execute` 的说明写明 *wrappers may change only `exec.signal`,
   while call identity remains immutable*，所以"命令消毒"不可行；jammer 只能封存结果。
3. **未命中必须 `return next()`**。不拥有决策的 waterfall 监听器若吞掉调用，会废掉所有其它工具。

另外 `references/practices.md`（技能自带）给出的选择顺序是：
`restrict` < `guard` < waterfall。本插件按用户选择落在 waterfall 这一档。

---

## 3. 日志格式（本地实测）

### 3.1 会话日志位置与命名

```
%DSH_HOME%/sessions/<workspace-slug>/session-<uuid>/session.v4.jsonl.zstd
```

本机实测（`Get-ChildItem -Recurse -File`）：7 个会话目录，文件名统一为
`session.v4.jsonl.zstd`。

### 3.2 **多帧拼接**的 zstd（本插件最关键的技术点）

实测：一份 306,187 字节的日志里含 **136 个 zstd 帧魔数**（`28 B5 2F FD`）。

```
$ node -e "const z=require('node:zlib'),fs=require('fs');
  const b=fs.readFileSync('<某会话日志>');
  z.zstdDecompressSync(b).length"   // → 248 字节（只有会话头！）
```

**Node 内置的 `zstdDecompressSync` 只解第一帧。** 直接用它只能读到 248 字节的
`{"type":"session",...}` 头，225 条真实事件全部看不见。

按魔数切帧后逐帧解压的实测结果（`node test/run-tests.mjs` 与本机全量扫描）：

| 日志 | 压缩字节 | 帧数 | 解压失败 | 解压文本字节 |
|---|---|---|---|---|
| session-2ead8726… | 364 | 2 | 0 | 503 |
| session-3281cfd1… | 306,187 | 136 | 0 | 1,011,008 |
| session-bea2c2b0… | 407,687 | 255 | 0 | 1,414,150 |
| session-927966c1… | 208,506 | 105 | 0 | 760,290 |
| 78bac2bd… | 225,287 | 162 | 0 | 795,014 |
| session-8f583993… | 1,778,955 | 1,610 | 0 | 6,099,417 |
| session-a4cdee8e… | 390 | 3 | 0 | 527 |
| **合计** | **2,927,376** | **2,273** | **0** | **10,080,909** |

→ 2,273 帧全部解压成功，零失败。

### 3.3 事件行的真实形状

解压后是 JSONL。实测出现过的 `type`（取自 `session-3281cfd1…`，225 行）：

```
session, permission/preset, sandbox/mode, approval/policy, model/selection,
agent/inbox/spliced, turn/start, step/start, system/message, user/message,
request/header, request/context, session/title, session/title-llm-request,
session-log-deepseek/delivery-accepted, assistant/message, tool/call,
tool/result, step/end, turn/end, session/end-seed
```

工具调用事件的精确形状（本节结论的原始样本）：

```json
{"type":"tool/call","seq":20,"time":1791719272718,
 "data":{"turn":1,"step":1,"callId":"call_00_…","name":"pwsh",
         "arguments":"{\"command\": \"Get-ChildItem env: …\", \"description\": \"…\"}"}}
```

工具结果事件的形状：

```json
{"type":"tool/result","seq":21,"time":1791719273553,
 "data":{"turn":1,"step":1,"message":{"role":"tool", …},
         "toolCallId":"call_00_…","content":[{"type":"text","text":"…"}]}}
```

### 3.4 由此推出的"只审计调用"设计

`tool/result` 的 `content[].text` 里装着**工具输出**。`cordis_inspect_list` 的返回体
会列出 `cordis_define` / `cordis_run` 等工具名，`listTools` 的返回体会带出 `subprocess`
之类的字样（本文档第 2 节就是活生生的例子）。

若对日志做无差别全文搜索，**每读一次工具清单就误报一片**。实测对比：

| 扫描方式 | 命中条数（对 1,778,955 字节日志做全量扫描） |
|---|---|
| 无差别全文搜索 | 7 |
| 排除 `tool/result` / `request/header` 后 | 6（且全部为真实调用） |

因此扫描器按行解析，`tool/result` 与 `request/header` 整行跳过；工具名规则只在
真正的 `tool/call` 事件上生效。回归测试见 `test/run-tests.mjs` 的 `[1b]` 组。

---

## 4. `cordis_*` 为什么值得告警（官方文档原文）

在 `app.asar` 里检索 `cordis_define|cordis_run` 命中 20 处，其中
`@deepseek-ai/dsh-cordis-host-runner` 的 README（中英双语，随包分发）明确写了：

> **信任立场**：沙箱隔离全局变量，但不是安全边界：Node 全局变量不存在，或重定向到
> Cordis 服务（`ctx.fs`、`ctx.web`、`ctx.bash` 与定时器 helper），host 半收到的是不含
> 框架内部机制的 façade，但它声明的服务仍会触达存活运行时。**对待动态包要像对待 bash
> 访问一样**。

> `run` 会做什么：程序调用方使用 `define`、`run`、`stop` 和 `undefine`……纯 host 包在
> 沙箱中求值并立即提交。

> **`vmTimeoutMs` 只约束同步求值** —— async 的 host 半函数体会逃出该上限，这与工具集
> 基于协作的信任立场一致。

> 定义按会话隔离且仅在进程内存在：其他会话无法读取，重启会清空。**历史日志保留工具参数
> 和回执**，但不会恢复注册表。

最后一句正是本插件成立的前提：**这些操作会在日志里留下痕迹**，所以可以事后/准实时检测。

同一 README 还说明 `dsh-cordis-host-runner` 的源码结构（`src/sandbox.ts` 用 `node:vm` 求值、
`src/guard.ts` 是注册边界、`src/lifecycle.ts` 在 `cordis-dynamic` fiber 组下启动 host 半）。

> 复核方式：这些字符串在 DSH 安装目录的 `resources/app.asar` 内（偏移约 47,310,000 附近）。
> 可用本插件的 zstd/文本扫描思路反向验证，或直接对 asar 做二进制检索。

---

## 5. 环境事实（本机实测）

> 下表是**本机实测值**；安装根因机器而异，故用占位符代替绝对路径。

| 事实 | 值 | 验证方式 |
|---|---|---|
| DSH 安装根 | `<DSH 安装根>`（Electron 应用目录） | 看宿主进程的可执行文件路径 |
| 应用资源 | `<DSH 安装根>\resources\app.asar`（本机约 121 MB） | `Test-Path` |
| 解包目录 | `<DSH 安装根>\resources\app.asar.unpacked\dsh\node_modules` | 目录列举 |
| `DSH_HOME` | `%USERPROFILE%\.dsh` | `Get-ChildItem env:DSH*` |
| `DSH_PROFILE` | `desktop` | 同上 |
| `DSH_PROFILE_DIR` | `%USERPROFILE%\.dsh\profiles\desktop` | 同上 |
| Node 运行时 | v22.22.2，`node:zlib` 提供 `zstdDecompressSync` | `node -e "…"` |
| 插件包管理器日志 | `%DSH_PROFILE_DIR%\.plugin-manager\logs\pnpm.log` | 目录列举 |

`DSH_PROFILE=desktop` 这一条直接决定了安装方式：见第 1 节表格最后两行。

---

## 6. 复核清单

```powershell
# 1) 契约：服务与事件签名
#    用 cordis_inspect_list → cordis_inspect_query(service: "systemPrompt")
#    用 cordis_inspect_query(provider: "Event", method: "listEvents")

# 2) 解码：多帧 zstd（应输出 248 与 1,011,008 这样的对比）
node -e "const z=require('node:zlib'),fs=require('fs');const b=fs.readFileSync(process.argv[1]);console.log('one-shot',z.zstdDecompressSync(b).length)" "<某会话日志>"

# 3) 全量自测（32 项）
cd <本插件目录>; node test/run-tests.mjs

# 4) 本机全量解码统计（应得 2,273 帧 / 0 失败）
#    见第 3.2 节脚本
```
