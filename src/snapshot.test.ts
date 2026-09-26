/**
 * 审计快照对比自检：快照深拷贝、合并原子空间逐单元分类（动作未变 /
 * 动作改变 / 命中→未命中 / 未命中→命中）、非法与停用规则排除、
 * ANY 双协议维、区域合计与单元统计一致、代表报文可复现、分桶排序。
 */
import assert from 'node:assert'
import { createSnapshot, diffSnapshots } from './audit/snapshot'
import { validateRules } from './audit/engine'
import { ipv4ToInt } from './audit/iputil'
import type { RuleInput } from './audit/types'

let passed = 0
function test(name: string, fn: () => void) {
  fn()
  passed++
  console.log(`  ✓ ${name}`)
}

let seq = 0
function rule(partial: Partial<RuleInput>): RuleInput {
  return {
    id: partial.id ?? `s${seq++}`,
    name: partial.name ?? `S${seq}`,
    cidr: partial.cidr ?? '0.0.0.0/0',
    portStart: partial.portStart ?? '0',
    portEnd: partial.portEnd ?? '65535',
    protocol: partial.protocol ?? 'ANY',
    action: partial.action ?? 'allow',
    enabled: partial.enabled ?? true,
  }
}

const NOW = new Date('2026-09-26T00:00:00Z')
const snap = (name: string, rules: RuleInput[]) => createSnapshot(name, rules, NOW)

/** 暴力首命中动作：null = 未命中任何合法且启用的规则 */
function bruteAction(
  rules: RuleInput[],
  pkt: { srcIp: string; srcPort: number; protocol: string },
): string | null {
  const { valid } = validateRules(rules)
  const ip = ipv4ToInt(pkt.srcIp)
  const hit = valid
    .filter((r) => r.enabled)
    .find(
      (r) =>
        ip >= r.ipStart &&
        ip <= r.ipEnd &&
        pkt.srcPort >= r.portStart &&
        pkt.srcPort <= r.portEnd &&
        (r.protocol === 'ANY' || r.protocol === pkt.protocol),
    )
  return hit ? hit.action : null
}

/** 全量报文空间：整个 IPv4 × 全部端口 × TCP/UDP */
const FULL_SPACE = 2 ** 32 * 65536 * 2

test('快照保存时深拷贝：之后的编辑 / 增删不影响快照内容', () => {
  const rules = [rule({ name: 'a', action: 'allow', cidr: '10.0.0.0/8' })]
  const s = snap('基线', rules)
  rules[0].action = 'deny'
  rules[0].cidr = '192.168.0.0/16'
  rules.push(rule({ name: 'b' }))
  assert.equal(s.rules.length, 1)
  assert.equal(s.rules[0].action, 'allow')
  assert.equal(s.rules[0].cidr, '10.0.0.0/8')
  assert.equal(s.name, '基线')
  assert.ok(s.id)
  assert.equal(s.createdAt, NOW.toISOString())
})

test('完全相同的规则集：无差异，全部单元动作未变或双未命中', () => {
  const rules = [
    rule({ name: 'web', cidr: '10.0.0.0/8', portStart: '80', portEnd: '80', protocol: 'TCP', action: 'allow' }),
  ]
  const report = diffSnapshots(snap('A', rules), snap('B', rules.map((r) => ({ ...r }))))
  assert.equal(report.hasDifference, false)
  assert.equal(report.actionChangedCells, 0)
  assert.equal(report.hitToMissCells, 0)
  assert.equal(report.missToHitCells, 0)
  assert.equal(report.sameActionCells + report.bothMissCells, report.totalCells)
  assert.equal(report.sameActionSize + report.bothMissSize, report.totalSize)
  assert.equal(report.totalSize, FULL_SPACE)
  assert.equal(report.buckets.length, 1)
  const bucket = report.buckets[0]
  assert.equal(bucket.kind, 'same-action')
  assert.equal(bucket.beforeAction, 'allow')
  assert.equal(bucket.afterAction, 'allow')
  // 命中区域：10.0.0.0/8 × 端口 80 × TCP
  assert.equal(bucket.size, 2 ** 24)
  assert.equal(report.sameActionSize, 2 ** 24)
})

test('动作改变：同区域不同动作，分桶记录前后动作与精确大小', () => {
  const a = [rule({ name: 'r', cidr: '10.0.0.0/8', action: 'allow' })]
  const b = [rule({ name: 'r', cidr: '10.0.0.0/8', action: 'deny' })]
  const report = diffSnapshots(snap('旧', a), snap('新', b))
  assert.equal(report.hasDifference, true)
  assert.equal(report.buckets.length, 1)
  const bucket = report.buckets[0]
  assert.equal(bucket.kind, 'action-changed')
  assert.equal(bucket.beforeAction, 'allow')
  assert.equal(bucket.afterAction, 'deny')
  // 10.0.0.0/8 × 全部端口 × TCP+UDP
  assert.equal(bucket.size, 2 ** 24 * 65536 * 2)
  assert.equal(report.actionChangedSize, bucket.size)
  // TCP / UDP 各一个代表报文，且可复现两侧动作
  assert.equal(bucket.examples.length, 2)
  for (const ex of bucket.examples) {
    assert.equal(bruteAction(a, ex.packet), 'allow')
    assert.equal(bruteAction(b, ex.packet), 'deny')
    assert.equal(ex.beforeRuleName, 'r')
    assert.equal(ex.afterRuleName, 'r')
  }
})

test('命中 → 未命中：对比快照删空规则集', () => {
  const a = [
    rule({ name: 'ssh', cidr: '192.168.0.0/16', portStart: '22', portEnd: '22', protocol: 'TCP', action: 'deny' }),
  ]
  const report = diffSnapshots(snap('旧', a), snap('新', []))
  assert.equal(report.hasDifference, true)
  assert.equal(report.buckets.length, 1)
  const bucket = report.buckets[0]
  assert.equal(bucket.kind, 'hit-to-miss')
  assert.equal(bucket.beforeAction, 'deny')
  assert.equal(bucket.afterAction, null)
  assert.equal(bucket.size, 2 ** 16) // /16 × 端口 22 × TCP
  assert.equal(report.hitToMissSize, bucket.size)
  assert.equal(report.missToHitCells, 0)
  assert.equal(bucket.examples.length, 1)
  const ex = bucket.examples[0]
  assert.equal(bruteAction(a, ex.packet), 'deny')
  assert.equal(bruteAction([], ex.packet), null)
  assert.equal(ex.beforeRuleName, 'ssh')
  assert.equal(ex.afterRuleIndex, null)
  assert.equal(ex.afterRuleName, null)
})

test('未命中 → 命中：基准快照为空规则集', () => {
  const b = [
    rule({ name: 'dns', cidr: '10.0.0.0/8', portStart: '53', portEnd: '53', protocol: 'UDP', action: 'allow' }),
  ]
  const report = diffSnapshots(snap('旧', []), snap('新', b))
  assert.equal(report.hasDifference, true)
  assert.equal(report.buckets.length, 1)
  const bucket = report.buckets[0]
  assert.equal(bucket.kind, 'miss-to-hit')
  assert.equal(bucket.beforeAction, null)
  assert.equal(bucket.afterAction, 'allow')
  assert.equal(bucket.size, 2 ** 24) // /8 × 端口 53 × UDP
  assert.equal(report.missToHitSize, bucket.size)
  const ex = bucket.examples[0]
  assert.equal(bruteAction([], ex.packet), null)
  assert.equal(bruteAction(b, ex.packet), 'allow')
  assert.equal(ex.beforeRuleIndex, null)
  assert.equal(ex.afterRuleName, 'dns')
})

test('合并原子空间精确切分：嵌套 CIDR 边界被切开，区域行精确', () => {
  const a = [
    rule({ name: 'wide', cidr: '10.0.0.0/8', portStart: '80', portEnd: '80', protocol: 'TCP', action: 'allow' }),
  ]
  const b = [
    rule({ name: 'narrow', cidr: '10.0.0.0/16', portStart: '80', portEnd: '80', protocol: 'TCP', action: 'deny' }),
  ]
  const report = diffSnapshots(snap('旧', a), snap('新', b))
  assert.equal(report.buckets.length, 2)
  const changed = report.buckets.find((x) => x.kind === 'action-changed')!
  const gone = report.buckets.find((x) => x.kind === 'hit-to-miss')!
  // 10.0.0.0/16 动作改变；/8 其余部分变为未命中
  assert.equal(changed.size, 2 ** 16)
  assert.equal(gone.size, 2 ** 24 - 2 ** 16)
  // 动作改变区域精确为一行：TCP 端口 80 × 10.0.0.0/16
  const changedRows = changed.regions.find((g) => g.protocol === 'TCP')!.rows
  assert.equal(changedRows.length, 1)
  assert.deepEqual([changedRows[0].portStart, changedRows[0].portEnd], [80, 80])
  assert.deepEqual(changedRows[0].cidrs, ['10.0.0.0/16'])
  // 命中→未命中区域合并回规范 CIDR，合计与单元级统计一致
  const goneRegionSize = gone.regions.reduce((s, g) => s + g.size, 0)
  assert.equal(goneRegionSize, gone.size)
  const goneRows = gone.regions.find((g) => g.protocol === 'TCP')!.rows
  // 同一端口段（80）合并为一行；/8 挖去 /16 后不是单个 CIDR，而是多个规范 CIDR
  assert.equal(goneRows.length, 1)
  assert.deepEqual([goneRows[0].portStart, goneRows[0].portEnd], [80, 80])
  assert.ok(goneRows[0].cidrs.length > 1)
  assert.deepEqual(goneRows[0].cidrs[0], '10.1.0.0/16')
  assert.deepEqual(goneRows[0].cidrs[goneRows[0].cidrs.length - 1], '10.128.0.0/9')
})

test('非法与停用规则被排除并计数，不参与首命中重放', () => {
  const a = [
    rule({ name: 'ok', cidr: '10.0.0.0/8', action: 'allow' }),
    rule({ name: 'bad', cidr: '10.0.0.5/24', action: 'deny' }), // 非法 CIDR
    rule({ name: 'off', cidr: '172.16.0.0/12', action: 'deny', enabled: false }),
  ]
  const b = [rule({ name: 'ok', cidr: '10.0.0.0/8', action: 'allow' })]
  const report = diffSnapshots(snap('旧', a), snap('新', b))
  assert.equal(report.hasDifference, false)
  assert.equal(report.baseActiveRules, 1)
  assert.equal(report.baseInvalidExcluded, 1)
  assert.equal(report.baseDisabledExcluded, 1)
  assert.equal(report.compareActiveRules, 1)
  assert.equal(report.compareInvalidExcluded, 0)
  assert.equal(report.compareDisabledExcluded, 0)
})

test('ANY 规则按 TCP / UDP 两维分别分类', () => {
  const a = [
    rule({ name: 'any', cidr: '10.0.0.0/8', portStart: '53', portEnd: '53', protocol: 'ANY', action: 'allow' }),
  ]
  const b = [
    rule({ name: 'tcp-only', cidr: '10.0.0.0/8', portStart: '53', portEnd: '53', protocol: 'TCP', action: 'deny' }),
  ]
  const report = diffSnapshots(snap('旧', a), snap('新', b))
  const changed = report.buckets.find((x) => x.kind === 'action-changed')!
  const gone = report.buckets.find((x) => x.kind === 'hit-to-miss')!
  assert.equal(changed.size, 2 ** 24) // TCP 维：allow → deny
  assert.equal(gone.size, 2 ** 24) // UDP 维：allow → 未命中
  assert.deepEqual(changed.regions.map((g) => g.protocol), ['TCP'])
  assert.deepEqual(gone.regions.map((g) => g.protocol), ['UDP'])
  assert.equal(changed.examples.length, 1)
  assert.equal(changed.examples[0].packet.protocol, 'TCP')
  assert.equal(gone.examples[0].packet.protocol, 'UDP')
})

test('混合场景：四类同时出现，区域合计与单元统计精确一致，代表报文可复现', () => {
  const a = [
    rule({ name: 'r1', cidr: '10.0.0.0/8', portStart: '0', portEnd: '1024', protocol: 'TCP', action: 'allow' }),
    rule({ name: 'r2', cidr: '172.16.0.0/12', portStart: '80', portEnd: '8080', protocol: 'ANY', action: 'deny' }),
    rule({ name: 'r3', cidr: '192.168.0.0/16', portStart: '22', portEnd: '25', protocol: 'UDP', action: 'allow' }),
  ]
  const b = [
    rule({ name: 's1', cidr: '10.0.0.0/8', portStart: '0', portEnd: '1024', protocol: 'TCP', action: 'allow' }), // 不变
    rule({ name: 's2', cidr: '172.16.0.0/12', portStart: '80', portEnd: '8080', protocol: 'ANY', action: 'drop' }), // 动作改变
    // r3 被删除 → 命中 → 未命中
    rule({ name: 's4', cidr: '203.0.113.0/24', portStart: '443', portEnd: '443', protocol: 'TCP', action: 'allow' }), // 新增 → 未命中 → 命中
  ]
  const report = diffSnapshots(snap('旧', a), snap('新', b))
  for (const kind of ['same-action', 'action-changed', 'hit-to-miss', 'miss-to-hit'] as const) {
    assert.ok(report.buckets.some((x) => x.kind === kind), `缺少分类 ${kind}`)
  }
  // 每个分桶：区域合计 === 报文空间大小，且每行大小自洽
  for (const bucket of report.buckets) {
    const regionSize = bucket.regions.reduce((s, g) => s + g.size, 0)
    assert.equal(regionSize, bucket.size, `${bucket.kind} 区域合计与单元统计不一致`)
    assert.ok(bucket.cells > 0)
    assert.ok(bucket.examples.length > 0)
  }
  // 四类 + 双未命中 = 全量报文空间 / 全部单元
  const classifiedSize =
    report.sameActionSize + report.actionChangedSize + report.hitToMissSize + report.missToHitSize
  assert.equal(classifiedSize + report.bothMissSize, FULL_SPACE)
  assert.equal(report.totalSize, FULL_SPACE)
  const classifiedCells =
    report.sameActionCells + report.actionChangedCells + report.hitToMissCells + report.missToHitCells
  assert.equal(classifiedCells + report.bothMissCells, report.totalCells)
  // 分类合计与各分桶之和一致
  const bucketSizeSum = report.buckets.reduce((s, x) => s + x.size, 0)
  assert.equal(bucketSizeSum, classifiedSize)
  // 每个代表报文：两侧暴力首命中动作与分桶声明一致
  for (const bucket of report.buckets) {
    for (const ex of bucket.examples) {
      assert.equal(bruteAction(a, ex.packet), bucket.beforeAction)
      assert.equal(bruteAction(b, ex.packet), bucket.afterAction)
    }
  }
})

test('首命中规则易主但动作相同仍属动作未变', () => {
  const ra = [
    rule({ id: 'x', name: 'specific', cidr: '10.1.0.0/16', action: 'allow' }),
    rule({ id: 'y', name: 'wide', cidr: '10.0.0.0/8', action: 'allow' }),
  ]
  const rb = [
    rule({ id: 'y', name: 'wide', cidr: '10.0.0.0/8', action: 'allow' }),
    rule({ id: 'x', name: 'specific', cidr: '10.1.0.0/16', action: 'allow' }),
  ]
  const report = diffSnapshots(snap('旧', ra), snap('新', rb))
  assert.equal(report.hasDifference, false)
  assert.equal(report.actionChangedCells, 0)
  assert.equal(report.hitToMissCells, 0)
  assert.equal(report.missToHitCells, 0)
  assert.ok(report.sameActionCells > 0)
})

test('分桶排序：动作改变 → 命中→未命中 → 未命中→命中 → 动作未变', () => {
  const a = [
    rule({ name: 'r1', cidr: '10.0.0.0/8', portStart: '1', portEnd: '1', protocol: 'TCP', action: 'allow' }),
    rule({ name: 'r2', cidr: '10.1.0.0/16', portStart: '2', portEnd: '2', protocol: 'TCP', action: 'deny' }),
    rule({ name: 'r3', cidr: '10.2.0.0/16', portStart: '3', portEnd: '3', protocol: 'TCP', action: 'allow' }),
  ]
  const b = [
    rule({ name: 's1', cidr: '10.0.0.0/8', portStart: '1', portEnd: '1', protocol: 'TCP', action: 'deny' }), // 动作改变
    // r2 删除 → 命中→未命中
    rule({ name: 's3', cidr: '10.2.0.0/16', portStart: '3', portEnd: '3', protocol: 'TCP', action: 'allow' }), // 不变
    rule({ name: 's4', cidr: '10.3.0.0/16', portStart: '4', portEnd: '4', protocol: 'TCP', action: 'allow' }), // 新增
  ]
  const report = diffSnapshots(snap('旧', a), snap('新', b))
  assert.deepEqual(
    report.buckets.map((x) => x.kind),
    ['action-changed', 'hit-to-miss', 'miss-to-hit', 'same-action'],
  )
})

test('空快照对比空快照：全部双未命中，无分桶', () => {
  const report = diffSnapshots(snap('空A', []), snap('空B', []))
  assert.equal(report.hasDifference, false)
  assert.equal(report.buckets.length, 0)
  assert.equal(report.bothMissCells, report.totalCells)
  assert.equal(report.bothMissSize, FULL_SPACE)
  // 无规则时原子空间退化为 1 IP 块 × 1 端口段 × 2 协议
  assert.equal(report.totalCells, 2)
  assert.equal(report.baseActiveRules, 0)
  assert.equal(report.compareActiveRules, 0)
})

console.log(`\n  快照对比自检通过：${passed} 项`)
