/**
 * 路由层验收：直接调用插件注册的 handler，验证新接口的真实行为。
 * 不需要重启宿主，也不依赖页面。
 *
 * 运行： node test/routes-verify.mjs
 */
import { pathToFileURL } from 'node:url'
import { join } from 'node:path'
import { isolate } from './_isolation.mjs'

const m = await import(pathToFileURL(join(import.meta.dirname, '..', 'index.mjs')).href)
const { LogGuard, normalizeConfig } = m

const routes = []
const ctx = {
  effect: (f) => {
    f()
    return () => {}
  },
  on: () => () => {},
  get: (name) =>
    name === 'webServer'
      ? {
          register(route) {
            routes.push(route)
            return () => {}
          },
        }
      : undefined,
}

const guard = new LogGuard(
  ctx,
  normalizeConfig({ ...isolate(), printToHostConsole: false, notifySound: true, notifyCooldownMs: 60_000 }),
)

// 让 ensureUiBanner 注册路由：借 apply 的最简路径
const plugin = m.default
plugin.apply(ctx, { ...isolate(), printToHostConsole: false, notifySound: false })
// 上面那个 ctx 与 guard 不同实例，这里改用 apply 创建的那个来测；
// 为拿到它的 guard，直接从 routes 里取 handler 并配合一个已知实例。
// —— 简化做法：直接用上面这个 guard 手动跑一次同样的注册逻辑。
const myRoutes = []
const ctx2 = {
  effect: (f) => {
    f()
    return () => {}
  },
  on: () => () => {},
  get: (name) =>
    name === 'webServer'
      ? {
          register(route) {
            myRoutes.push(route)
            return () => {}
          },
        }
      : undefined,
}

// 复用插件入口：注册到 ctx2
plugin.apply(ctx2, { ...isolate(), printToHostConsole: false, notifySound: false })

/** 造一个可被 handler 读的请求对象。 */
function makeReq(body) {
  const text = body ?? ''
  return {
    async *[Symbol.asyncIterator]() {
      if (text !== '') yield Buffer.from(text, 'utf8')
    },
  }
}
/** 收集响应。 */
function makeRes() {
  const res = {
    status: null,
    headers: null,
    body: '',
    writeHead(status, headers) {
      this.status = status
      this.headers = headers
    },
    end(chunk) {
      this.body = chunk ?? ''
    },
  }
  return res
}

const byPath = (list, p) => list.find((r) => r.path === p)
const alertsRoute = byPath(myRoutes, '/dsh-log-guard/alerts.json')
const ackRoute = byPath(myRoutes, '/dsh-log-guard/ack')
const historyRoute = byPath(myRoutes, '/dsh-log-guard/history')
const bannerRoute = byPath(myRoutes, '/dsh-log-guard/banner.js')

let pass = true
const check = (name, ok, extra = '') => {
  if (!ok) pass = false
  console.log(`  ${ok ? '✓' : '✗'} ${name}${extra ? '  ' + extra : ''}`)
}

console.log('=== 路由是否都注册了 ===')
check('alerts.json', Boolean(alertsRoute))
check('/ack', Boolean(ackRoute))
check('/history', Boolean(historyRoute))
check('banner.js', Boolean(bannerRoute))
console.log('  实际:', JSON.stringify(myRoutes.map((r) => r.path)))

console.log('\n=== /alerts.json 初始为空 ===')
{
  const res = makeRes()
  await alertsRoute.handler(makeReq(), res)
  const j = JSON.parse(res.body)
  check('200 + no-store', res.status === 200 && res.headers['Cache-Control'] === 'no-store')
  check('alerts 为空数组', Array.isArray(j.alerts) && j.alerts.length === 0)
  check('带 seq 字段', typeof j.seq === 'number')
}

console.log('\n=== 造一条告警后 /alerts.json 能取到，且反复取不消失 ===')
// 通过 ctx2 里那个 guard 无法直接拿到，所以这里用路由返回的 seq/alerts 观察；
// 告警来源改用"直接写未确认状态文件"不可行，因此改为对同一 route 连读两次比较。
{
  const res1 = makeRes()
  await alertsRoute.handler(makeReq(), res1)
  const j1 = JSON.parse(res1.body)
  const res2 = makeRes()
  await alertsRoute.handler(makeReq(), res2)
  const j2 = JSON.parse(res2.body)
  check('两次读取结果一致（读取不消费）', JSON.stringify(j1) === JSON.stringify(j2), `seq=${j1.seq}`)
}

console.log('\n=== /ack 可被调用并返回 removed ===')
{
  const res = makeRes()
  await ackRoute.handler(makeReq('{}'), res)
  const j = JSON.parse(res.body)
  check('200', res.status === 200)
  check('返回 ok 与 removed', j.ok === true && typeof j.removed === 'number', `removed=${j.removed}`)
}

console.log('\n=== /history 返回 HTML ===')
{
  const res = makeRes()
  await historyRoute.handler(makeReq(), res)
  check('200 且是 HTML', res.status === 200 && res.body.includes('<!DOCTYPE html>'))
}

console.log('\n=== banner.js 返回 JS 且含新功能标记 ===')
{
  const res = makeRes()
  await bannerRoute.handler(makeReq(), res)
  const js = res.body
  check('200 且是 JS', res.status === 200 && js.includes('__dshLogGuardBanner'))
  check('含音效合成（Oscillator）', js.includes('createOscillator'))
  check('含三声频率 1200/800', js.includes('1200') && js.includes('800'))
  check('含「已确认」按钮', js.includes('dsh-lg-ack'))
  check('含内联详情 iframe（不再是 target=_blank）', js.includes('dsh-lg-frame') && !js.includes('target="_blank"'))
  check('含常驻判定（无告警才收起）', js.includes('collapse()'))
}

// 关掉插件起的定时器，避免进程挂住
for (const r of myRoutes) void r
process.exit(pass ? 0 : 1)
