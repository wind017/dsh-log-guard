/**
 * blocker / jammer 验收：装配真实监听器，跑一遍决策并打印实际返回值。
 *
 * 验证三件事：
 *   1. 默认关闭（不擅自改变宿主行为）
 *   2. 命中 critical 时的**决策形态**符合 PreToolDecision / PostToolDecision 契约
 *   3. 不命中时正确委托 `next()`（否则会吞掉所有其它工具调用）
 *
 * 运行： node test/enforce-verify.mjs
 */
import { pathToFileURL } from 'node:url'
import { join } from 'node:path'
import { isolate } from './_isolation.mjs'

const m = await import(pathToFileURL(join(import.meta.dirname, '..', 'index.mjs')).href)
const { LogGuard, normalizeConfig, installEnforcement } = m

let pass = true
const check = (name, ok, extra = '') => {
  if (!ok) pass = false
  console.log(`  ${ok ? '✓' : '✗'} ${name}${extra ? '  ' + extra : ''}`)
}

/** 造一个只记录订阅的假上下文。 */
function makeCtx() {
  const listeners = new Map()
  return {
    listeners,
    ctx: {
      effect: (f) => {
        f()
        return () => {}
      },
      on(event, fn) {
        listeners.set(event, fn)
        return () => {}
      },
      // 真机里 tools 服务是存在的；这里给个桩，避免触发"未取到 tools 服务"自检警告。
      get: (name) => (name === 'tools' ? {} : undefined),
    },
  }
}

const cfg = (enforce) =>
  normalizeConfig({ ...isolate(), printToHostConsole: false, notifySound: false, enforce })

const call = (name, args = {}, callId = 'c1') => ({ name, arguments: args, callId })

console.log('=== 1. 默认关闭 ===')
{
  const fake = makeCtx()
  const guard = new LogGuard(fake.ctx, cfg({}))
  const installed = installEnforcement(fake.ctx, guard, guard.config)
  check('未启用时挂 0 个监听器', installed === 0, `实际 ${installed}`)
  check('未启用时无 pre-execute', !fake.listeners.has('tools/pre-execute'))
  check('未启用时无 post-execute', !fake.listeners.has('tools/post-execute'))
}

console.log('\n=== 2. blocker=ask（用户选择）===')
{
  const fake = makeCtx()
  const guard = new LogGuard(fake.ctx, cfg({ enabled: true, blocker: 'ask' }))
  const installed = installEnforcement(fake.ctx, guard, guard.config)
  check('挂了 blocker + jammer 两个', installed === 2, `实际 ${installed}`)

  const pre = fake.listeners.get('tools/pre-execute')
  let nextCalls = 0
  const next = async () => {
    nextCalls++
    return { kind: 'allow' }
  }

  console.log('  演示：模型要调用 cordis_define')
  const denied = await pre(call('cordis_define', { code: 'ctx.log(1)' }, 'c-ask'), next)
  console.log('    决策 =', JSON.stringify(denied))
  check('返回 ask', denied.kind === 'ask')
  check('reason 点名规则', String(denied.reason).includes('cordis-define'))
  check('displayReason 有 en', typeof denied.displayReason?.en === 'string')
  check('displayReason 有 zh', typeof denied.displayReason?.zh === 'string')
  check('命中时不委托 next()', nextCalls === 0)

  console.log('  演示：模型要调用 read（不该被拦）')
  const allowed = await pre(call('read', { file_path: 'a.txt' }, 'c-read'), next)
  console.log('    决策 =', JSON.stringify(allowed))
  check('未命中委托 next()', nextCalls === 1)
  check('未命中不拦截', allowed.kind === 'allow')
}

console.log('\n=== 3. jammer=block（阻断结果）===')
{
  const fake = makeCtx()
  const guard = new LogGuard(fake.ctx, cfg({ enabled: true, jammer: 'block' }))
  installEnforcement(fake.ctx, guard, guard.config)

  const post = fake.listeners.get('tools/post-execute')
  let delegated = 0
  const next = async () => {
    delegated++
    return { kind: 'accept' }
  }

  console.log('  演示：cordis_run 已执行完，结果要封存')
  const blocked = await post(
    call('cordis_run', {}, 'c-jam'),
    { isError: false, value: { leaked: 'SECRET-OUTPUT' }, content: [{ type: 'text', text: 'SECRET-OUTPUT' }] },
    next,
  )
  console.log('    决策 =', JSON.stringify(blocked).slice(0, 200))
  check('返回 block', blocked.kind === 'block')
  check('feedback 是非空数组', Array.isArray(blocked.feedback) && blocked.feedback.length > 0)
  check('feedback 是 text 块', blocked.feedback[0]?.type === 'text')
  check('反馈含"已阻断"', String(blocked.feedback[0]?.text).includes('已阻断'))
  check('反馈不泄漏真实结果', !JSON.stringify(blocked).includes('SECRET-OUTPUT'))
  check('命中时不委托 next()', delegated === 0)

  const accepted = await post(call('read'), { isError: false, value: 1, content: [] }, next)
  check('未命中委托 next()', delegated === 1 && accepted.kind === 'accept')
}

console.log('\n=== 4. 误报防护：编辑本插件源码不应被拦 ===')
{
  const fake = makeCtx()
  const guard = new LogGuard(fake.ctx, cfg({ enabled: true }))
  installEnforcement(fake.ctx, guard, guard.config)
  const pre = fake.listeners.get('tools/pre-execute')
  let delegated = 0
  const decision = await pre(
    call('write', { file_path: 'index.mjs', content: "const TIP = 'cordis_define 与 cordis_run'" }, 'c-write'),
    async () => {
      delegated++
      return { kind: 'allow' }
    },
  )
  check('write 内容含敏感词但不拦（只匹配工具名）', delegated === 1 && decision.kind === 'allow')
}

console.log('\n=== 5. 拦截事件进入告警队列 ===')
{
  const fake = makeCtx()
  const guard = new LogGuard(fake.ctx, cfg({ enabled: true, blocker: 'deny' }))
  installEnforcement(fake.ctx, guard, guard.config)
  const before = guard.unackedList().alerts.length
  await fake.listeners.get('tools/pre-execute')(call('cordis_define', {}, 'c-alert'), async () => ({
    kind: 'allow',
  }))
  const after = guard.unackedList().alerts
  check('告警队列增加', after.length > before, `${before} → ${after.length}`)
  const hit = after.find((a) => a.ruleId === 'cordis-define')
  check('告警描述标明拦截', Boolean(hit && hit.description.includes('拦截')), hit ? hit.description : '(无)')
  check('来源标出工具名', Boolean(hit && hit.sources.join() === 'tool:cordis_define'))
}

console.log(`\n结论：${pass ? '通过' : '失败'}`)
process.exit(pass ? 0 : 1)
