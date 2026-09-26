/**
 * 审计快照对比（只读）。
 *
 * 用户可为当前规则集保存带名称的快照：保存时对规则做深拷贝，之后的
 * 编辑 / 调序 / 启停 / 删除都不影响已保存的快照。
 *
 * 对比两个快照时，把**两个快照的合法且启用规则合并**构建同一套
 * IPv4 原子块 × 端口原子段 × {TCP, UDP} 离散单元空间（合并切分保证
 * 任一快照声明的 CIDR / 端口边界都被精确切开），随后在该空间上
 * **逐单元分别重放两个快照的首命中**，按最终动作把每个单元精确分类：
 *
 *   - same-action    两侧均命中且动作相同（动作未变；首命中规则可能易主，
 *                    但只要最终动作一致即归入此类）
 *   - action-changed 两侧均命中但动作不同
 *   - hit-to-miss    基准快照命中、对比快照未命中任何规则
 *   - miss-to-hit    基准快照未命中、对比快照命中（反向变化）
 *
 * 两侧均未命中的单元不属于上述任何一类，仅计入统计（不展开区域）。
 * 每个（分类 × 前动作 × 后动作）分桶给出精确区域
 * （协议 → 连续端口段 × 规范 CIDR 行，与审计共用同一套构建）与
 * 确定性的可复制代表报文（每个具体协议取字典序最小单元）。
 *
 * 非法 / 停用规则与审计一致地被排除（不参与首命中计算）；
 * 对比为纯函数，不修改任何规则，也不改动当前规则集。
 */
import {
  atomCellSize,
  buildExactRegions,
  buildIpAtoms,
  buildOwnerMap,
  buildPortAtoms,
  packetFromKey,
  validateRules,
} from './engine'
import type { ExactRegionGroup, Protocol, RuleInput } from './types'

/** 一份命名快照：保存时刻规则集的深拷贝，之后不可变 */
export interface RuleSnapshot {
  id: string
  name: string
  createdAt: string
  rules: RuleInput[]
}

/** 单元分类：动作未变 / 动作改变 / 命中→未命中 / 未命中→命中 */
export type SnapshotDiffKind =
  | 'same-action'
  | 'action-changed'
  | 'hit-to-miss'
  | 'miss-to-hit'

/** 可复制的代表报文 */
export interface SnapshotDiffPacket {
  srcIp: string
  srcPort: number
  protocol: Extract<Protocol, 'TCP' | 'UDP'>
}

/** 一个代表报文两侧的首命中规则（null = 该侧未命中任何规则） */
export interface SnapshotDiffExample {
  packet: SnapshotDiffPacket
  beforeRuleIndex: number | null
  beforeRuleName: string | null
  afterRuleIndex: number | null
  afterRuleName: string | null
}

/** 一个（分类 × 前动作 × 后动作）分桶：精确区域 + 代表报文 */
export interface SnapshotDiffBucket {
  kind: SnapshotDiffKind
  /** 基准快照侧动作（miss-to-hit 时恒为 null） */
  beforeAction: string | null
  /** 对比快照侧动作（hit-to-miss 时恒为 null） */
  afterAction: string | null
  /** 该桶覆盖的报文空间大小（IP 数 × 端口数，协议按单元计） */
  size: number
  /** 该桶合并的原子单元数 */
  cells: number
  /** 精确区域：协议 → 连续端口段 × 规范 CIDR 行（互斥且完备，合计 = size） */
  regions: ExactRegionGroup[]
  /** 每个具体协议一个确定性代表报文（TCP / UDP 至多各一） */
  examples: SnapshotDiffExample[]
}

export interface SnapshotDiffReport {
  generatedAt: string
  baseSnapshotId: string
  compareSnapshotId: string
  baseName: string
  compareName: string
  /** 参与首命中重放的合法且启用规则数 */
  baseActiveRules: number
  compareActiveRules: number
  /** 被排除的非法 / 停用规则数 */
  baseInvalidExcluded: number
  compareInvalidExcluded: number
  baseDisabledExcluded: number
  compareDisabledExcluded: number
  /** 合并原子空间的单元总数与全量报文空间（含两侧均未命中部分） */
  totalCells: number
  totalSize: number
  sameActionCells: number
  sameActionSize: number
  actionChangedCells: number
  actionChangedSize: number
  hitToMissCells: number
  hitToMissSize: number
  missToHitCells: number
  missToHitSize: number
  /** 两侧均未命中的单元（不属于四类，不展开区域） */
  bothMissCells: number
  bothMissSize: number
  /** 分桶明细：动作改变 → 命中→未命中 → 未命中→命中 → 动作未变 */
  buckets: SnapshotDiffBucket[]
  /** 是否存在任何动作层面的差异（动作改变 / 命中↔未命中） */
  hasDifference: boolean
}

/**
 * 保存当前规则集为一份命名快照。规则逐项浅拷贝（RuleInput 为扁平结构，
 * 等价深拷贝），之后的任何编辑不影响快照内容。
 */
export function createSnapshot(
  name: string,
  rules: RuleInput[],
  now: Date = new Date(),
): RuleSnapshot {
  return {
    id: Math.random().toString(36).slice(2, 10),
    name: name.trim(),
    createdAt: now.toISOString(),
    rules: rules.map((r) => ({ ...r })),
  }
}

const KIND_ORDER: Record<SnapshotDiffKind, number> = {
  'action-changed': 0,
  'hit-to-miss': 1,
  'miss-to-hit': 2,
  'same-action': 3,
}

/**
 * 对比两个快照：在合并的原子空间上逐单元重放两侧首命中并分类。
 * 纯函数，不修改传入快照；同一对快照多次对比结果完全一致。
 */
export function diffSnapshots(
  base: RuleSnapshot,
  compare: RuleSnapshot,
  now: Date = new Date(),
): SnapshotDiffReport {
  // 非法 / 停用规则与审计一致地被排除，不参与首命中重放
  const baseV = validateRules(base.rules)
  const compareV = validateRules(compare.rules)
  const baseActive = baseV.valid.filter((r) => r.enabled)
  const compareActive = compareV.valid.filter((r) => r.enabled)

  // 合并两个快照的边界构建同一套原子空间：任一快照的规则边界都被精确切开，
  // 单元 key 在两侧完全对齐，可逐单元比较首命中结果。
  const ipAtoms = buildIpAtoms([...baseActive, ...compareActive])
  const portAtoms = buildPortAtoms([...baseActive, ...compareActive])
  const baseOwner = buildOwnerMap(baseActive, ipAtoms, portAtoms)
  const compareOwner = buildOwnerMap(compareActive, ipAtoms, portAtoms)

  interface BucketAcc {
    kind: SnapshotDiffKind
    before: string | null
    after: string | null
    keys: Set<string>
    size: number
    /** 每个具体协议记录字典序最小单元（与引擎代表报文选点规则一致） */
    first: [string | null, string | null]
  }
  const acc = new Map<string, BucketAcc>()

  let totalCells = 0
  let totalSize = 0
  let bothMissCells = 0
  let bothMissSize = 0

  for (let ip = 0; ip < ipAtoms.length; ip++) {
    for (let port = 0; port < portAtoms.length; port++) {
      const size = atomCellSize(ipAtoms[ip], portAtoms[port])
      for (let proto = 0; proto < 2; proto++) {
        totalCells++
        totalSize += size
        const key = `${ip}.${port}.${proto}`
        const bPos = baseOwner.get(key)
        const cPos = compareOwner.get(key)
        const before = bPos === undefined ? null : baseActive[bPos].action
        const after = cPos === undefined ? null : compareActive[cPos].action

        if (before === null && after === null) {
          bothMissCells++
          bothMissSize += size
          continue
        }
        const kind: SnapshotDiffKind =
          before !== null && after !== null
            ? before === after
              ? 'same-action'
              : 'action-changed'
            : before !== null
              ? 'hit-to-miss'
              : 'miss-to-hit'
        const bk = `${kind}|${before ?? ''}|${after ?? ''}`
        let bucket = acc.get(bk)
        if (!bucket) {
          bucket = { kind, before, after, keys: new Set(), size: 0, first: [null, null] }
          acc.set(bk, bucket)
        }
        bucket.keys.add(key)
        bucket.size += size
        const cur = bucket.first[proto]
        if (cur === null || key < cur) bucket.first[proto] = key
      }
    }
  }

  const buckets: SnapshotDiffBucket[] = [...acc.values()].map((b) => {
    const examples: SnapshotDiffExample[] = []
    for (const proto of [0, 1]) {
      const key = b.first[proto]
      if (key === null) continue
      const bPos = baseOwner.get(key)
      const cPos = compareOwner.get(key)
      examples.push({
        packet: packetFromKey(key, ipAtoms, portAtoms),
        beforeRuleIndex: bPos === undefined ? null : baseActive[bPos].index,
        beforeRuleName: bPos === undefined ? null : baseActive[bPos].name,
        afterRuleIndex: cPos === undefined ? null : compareActive[cPos].index,
        afterRuleName: cPos === undefined ? null : compareActive[cPos].name,
      })
    }
    return {
      kind: b.kind,
      beforeAction: b.before,
      afterAction: b.after,
      size: b.size,
      cells: b.keys.size,
      regions: buildExactRegions(b.keys, ipAtoms, portAtoms),
      examples,
    }
  })

  // 展示顺序：动作改变 → 命中→未命中 → 未命中→命中 → 动作未变；
  // 同类按报文空间降序，再按动作名升序，保证确定性
  const cmpStr = (x: string, y: string) => (x < y ? -1 : x > y ? 1 : 0)
  buckets.sort(
    (a, b) =>
      KIND_ORDER[a.kind] - KIND_ORDER[b.kind] ||
      b.size - a.size ||
      cmpStr(a.beforeAction ?? '', b.beforeAction ?? '') ||
      cmpStr(a.afterAction ?? '', b.afterAction ?? ''),
  )

  const sumOf = (kind: SnapshotDiffKind, field: 'cells' | 'size') =>
    buckets.filter((b) => b.kind === kind).reduce((s, b) => s + b[field], 0)

  const actionChangedCells = sumOf('action-changed', 'cells')
  const hitToMissCells = sumOf('hit-to-miss', 'cells')
  const missToHitCells = sumOf('miss-to-hit', 'cells')

  return {
    generatedAt: now.toISOString(),
    baseSnapshotId: base.id,
    compareSnapshotId: compare.id,
    baseName: base.name,
    compareName: compare.name,
    baseActiveRules: baseActive.length,
    compareActiveRules: compareActive.length,
    baseInvalidExcluded: baseV.invalid.length,
    compareInvalidExcluded: compareV.invalid.length,
    baseDisabledExcluded: baseV.valid.length - baseActive.length,
    compareDisabledExcluded: compareV.valid.length - compareActive.length,
    totalCells,
    totalSize,
    sameActionCells: sumOf('same-action', 'cells'),
    sameActionSize: sumOf('same-action', 'size'),
    actionChangedCells,
    actionChangedSize: sumOf('action-changed', 'size'),
    hitToMissCells,
    hitToMissSize: sumOf('hit-to-miss', 'size'),
    missToHitCells,
    missToHitSize: sumOf('miss-to-hit', 'size'),
    bothMissCells,
    bothMissSize,
    buckets,
    hasDifference: actionChangedCells + hitToMissCells + missToHitCells > 0,
  }
}
