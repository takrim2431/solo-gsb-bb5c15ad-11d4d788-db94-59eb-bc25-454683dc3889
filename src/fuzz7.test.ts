/**
 * 模糊对照测试：审计快照对比。
 * 在缩小报文空间（10.1.0.0/24 × 端口 0..63 × TCP/UDP）上随机生成两个规则集
 * （含随机停用规则；一半轮次由基准集变异得到对比集），逐报文暴力计算两侧
 * 首命中动作并分类，与 diffSnapshots 的分桶（报文空间大小）、区域行合计、
 * 区域行落点分类与代表报文对照。
 */
import assert from 'node:assert'
import { validateRules } from './audit/engine'
import { createSnapshot, diffSnapshots } from './audit/snapshot'
import { ipv4ToInt, parseCidrStrict } from './audit/iputil'
import type { NormalizedRule, RuleInput } from './audit/types'

function rand(n: number) {
  return Math.floor(Math.random() * n)
}

/**
 * 把随机块表示成规范 CIDR（限定 10.1.0.0/24 内）。
 * extra = 超出 /24 的额外前缀位数（0=整 /24，1..4=/25../28），
 * 块大小（IP 数）= 2^(8-extra)，块起始为其整数倍。
 */
function randomCidr(): string {
  const extra = rand(5)
  const prefix = 24 + extra
  const size = 2 ** (8 - extra)
  const base = rand(256 / size) * size
  return `10.1.0.${base}/${prefix}`
}

const PROTOS = ['TCP', 'UDP', 'ANY']
const ACTIONS = ['allow', 'deny', 'drop']

function makeRules(n: number): RuleInput[] {
  return Array.from({ length: n }, (_, i) => {
    const start = rand(64)
    return {
      id: `f${i}`,
      name: `R${i}`,
      cidr: randomCidr(),
      portStart: String(start),
      portEnd: String(Math.min(63, start + rand(64))),
      protocol: PROTOS[rand(3)],
      action: ACTIONS[rand(3)],
      enabled: rand(10) > 0, // 约 1/10 概率停用
    }
  })
}

/** 由基准集变异得到对比集：随机改动作 / 删规则 / 加规则 */
function mutate(rules: RuleInput[]): RuleInput[] {
  const copy = rules.map((r) => ({ ...r }))
  for (const r of copy) {
    if (rand(3) === 0) r.action = ACTIONS[rand(3)]
    if (rand(8) === 0) r.enabled = !r.enabled
  }
  const kept = copy.filter(() => rand(4) > 0)
  return [...kept, ...makeRules(rand(3))]
}

function activeNorm(rules: RuleInput[]): NormalizedRule[] {
  return validateRules(rules).valid.filter((r) => r.enabled)
}

/** 暴力首命中动作（基于规范化后的合法且启用规则）：null = 未命中 */
function bruteAction(
  active: NormalizedRule[],
  ip: number,
  port: number,
  proto: number,
): string | null {
  const pName = proto === 0 ? 'TCP' : 'UDP'
  for (const r of active) {
    if (
      ip >= r.ipStart &&
      ip <= r.ipEnd &&
      port >= r.portStart &&
      port <= r.portEnd &&
      (r.protocol === 'ANY' || r.protocol === pName)
    ) {
      return r.action
    }
  }
  return null
}

function classify(before: string | null, after: string | null): string {
  if (before === null && after === null) return 'both-miss'
  if (before !== null && after !== null) {
    return before === after ? 'same-action' : 'action-changed'
  }
  return before !== null ? 'hit-to-miss' : 'miss-to-hit'
}

const ROUNDS = 300
const NOW = new Date('2026-09-26T00:00:00Z')
const FULL_SPACE = 2 ** 32 * 65536 * 2

for (let round = 0; round < ROUNDS; round++) {
  const rulesA = makeRules(1 + rand(6))
  const rulesB = rand(2) === 0 ? makeRules(1 + rand(6)) : mutate(rulesA)
  const activeA = activeNorm(rulesA)
  const activeB = activeNorm(rulesB)

  const report = diffSnapshots(
    createSnapshot('A', rulesA, NOW),
    createSnapshot('B', rulesB, NOW),
    NOW,
  )

  // ---- 逐报文暴力分类（缩小空间内全部 256 × 64 × 2 个报文） ----
  // 缩小空间之外没有任何规则覆盖，必为双未命中，无需逐点核对
  const bruteCounts = new Map<string, number>() // 分桶 key -> 报文数
  for (let ip = 0; ip < 256; ip++) {
    const ipNum = ipv4ToInt(`10.1.0.${ip}`)
    for (let port = 0; port < 64; port++) {
      for (let proto = 0; proto < 2; proto++) {
        const before = bruteAction(activeA, ipNum, port, proto)
        const after = bruteAction(activeB, ipNum, port, proto)
        const kind = classify(before, after)
        if (kind === 'both-miss') continue
        const key = `${kind}|${before ?? ''}|${after ?? ''}`
        bruteCounts.set(key, (bruteCounts.get(key) ?? 0) + 1)
      }
    }
  }

  // ---- 引擎分桶 ↔ 暴力计数（双向） ----
  // 缩小空间内每个报文的大小为 1，故分桶 size 即缩小空间内的报文数
  let classifiedSize = 0
  let classifiedCells = 0
  const engineKeys = new Set<string>()
  for (const bucket of report.buckets) {
    const key = `${bucket.kind}|${bucket.beforeAction ?? ''}|${bucket.afterAction ?? ''}`
    engineKeys.add(key)
    const brute = bruteCounts.get(key)
    assert.ok(brute !== undefined, `第 ${round} 轮：引擎出现暴力中不存在的分桶 ${key}`)
    assert.equal(
      bucket.size,
      brute,
      `第 ${round} 轮：分桶 ${key} 报文空间大小不符（引擎 ${bucket.size} / 暴力 ${brute}）`,
    )
    classifiedSize += bucket.size
    classifiedCells += bucket.cells

    // 区域行合计与单元级统计一致
    const regionSize = bucket.regions.reduce((s, g) => s + g.size, 0)
    assert.equal(regionSize, bucket.size, `第 ${round} 轮：分桶 ${key} 区域合计不符`)

    // 每个区域行的落点（行首报文）暴力分类必须落在该分桶
    for (const group of bucket.regions) {
      const proto = group.protocol === 'TCP' ? 0 : 1
      for (const row of group.rows) {
        const cidr = parseCidrStrict(row.cidrs[0])
        const before = bruteAction(activeA, cidr.start, row.portStart, proto)
        const after = bruteAction(activeB, cidr.start, row.portStart, proto)
        assert.equal(classify(before, after), bucket.kind, `第 ${round} 轮：区域行落点分类不符`)
        assert.equal(before, bucket.beforeAction)
        assert.equal(after, bucket.afterAction)
      }
    }

    // 代表报文可复现：两侧暴力首命中动作与分桶声明一致
    for (const ex of bucket.examples) {
      const proto = ex.packet.protocol === 'TCP' ? 0 : 1
      const before = bruteAction(activeA, ipv4ToInt(ex.packet.srcIp), ex.packet.srcPort, proto)
      const after = bruteAction(activeB, ipv4ToInt(ex.packet.srcIp), ex.packet.srcPort, proto)
      assert.equal(before, bucket.beforeAction, `第 ${round} 轮：代表报文基准侧动作不符`)
      assert.equal(after, bucket.afterAction, `第 ${round} 轮：代表报文对比侧动作不符`)
    }
  }
  for (const key of bruteCounts.keys()) {
    assert.ok(engineKeys.has(key), `第 ${round} 轮：暴力分桶 ${key} 在引擎结果中缺失`)
  }

  // ---- 汇总一致性：四类 + 双未命中 = 全量空间 / 全部单元 ----
  assert.equal(
    report.sameActionSize +
      report.actionChangedSize +
      report.hitToMissSize +
      report.missToHitSize,
    classifiedSize,
  )
  assert.equal(
    report.sameActionCells +
      report.actionChangedCells +
      report.hitToMissCells +
      report.missToHitCells,
    classifiedCells,
  )
  assert.equal(classifiedSize + report.bothMissSize, FULL_SPACE)
  assert.equal(report.totalSize, FULL_SPACE)
  assert.equal(classifiedCells + report.bothMissCells, report.totalCells)
  assert.equal(
    report.hasDifference,
    report.actionChangedCells + report.hitToMissCells + report.missToHitCells > 0,
  )
}

console.log(`  ✓ 快照对比模糊对照 ${ROUNDS} 轮全部一致`)
