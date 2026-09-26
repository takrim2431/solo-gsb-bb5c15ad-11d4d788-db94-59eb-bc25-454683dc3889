import { useMemo, useState } from 'react'
import { diffSnapshots } from './audit/snapshot'
import type {
  RuleSnapshot,
  SnapshotDiffBucket,
  SnapshotDiffKind,
  SnapshotDiffReport,
} from './audit/snapshot'
import { validateRules } from './audit/engine'
import type { ExactRegionGroup, RuleInput } from './audit/types'
import { formatPacket, formatPortRange, formatSize } from './format'

interface Props {
  rules: RuleInput[]
  snapshots: RuleSnapshot[]
  onSaveSnapshot: (name: string) => void
  onDeleteSnapshot: (id: string) => void
}

const KIND_META: Record<
  SnapshotDiffKind,
  { text: string; tagClass: string; cardClass: string }
> = {
  'action-changed': { text: '动作改变', tagClass: 'diff-changed', cardClass: 'traffic-action-changed' },
  'hit-to-miss': { text: '命中 → 未命中', tagClass: 'diff-miss', cardClass: 'diff-hit-to-miss' },
  'miss-to-hit': { text: '未命中 → 命中', tagClass: 'diff-hit', cardClass: 'diff-miss-to-hit' },
  'same-action': { text: '动作未变', tagClass: 'diff-same', cardClass: 'diff-same-action' },
}

function CopyButton({ text, label = '复制' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      className="copy-mini"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text)
          setCopied(true)
          setTimeout(() => setCopied(false), 1200)
        } catch {
          setCopied(false)
        }
      }}
    >
      {copied ? '已复制' : label}
    </button>
  )
}

/** 精确区域：协议 → 连续端口段 × 规范 CIDR 列表（行式，互斥且完备） */
function RegionView({ regions }: { regions: ExactRegionGroup[] }) {
  return (
    <div className="code-list">
      {regions.map((reg) => (
        <div key={reg.protocol} className="line">
          <strong>{reg.protocol}</strong>
          <span className="muted-text">（{formatSize(reg.size)} 条报文空间）</span>
          {reg.rows.map((row, i) => (
            <div key={i} className="muted-text" style={{ paddingLeft: 12 }}>
              端口 {formatPortRange(row.portStart, row.portEnd)} × {row.cidrs.join(', ')}
              <span className="muted-text">（{formatSize(row.size)}）</span>
            </div>
          ))}
        </div>
      ))}
    </div>
  )
}

function formatSnapshotTime(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString('zh-CN', { hour12: false })
}

/** 动作侧展示：动作名 pill 或「未命中」 */
function ActionSide({ action }: { action: string | null }) {
  if (action === null) return <span className="traffic-side diff-miss-side">未命中</span>
  return (
    <span className="traffic-side">
      <span className="action-pill">{action}</span>
    </span>
  )
}

function BucketCard({
  bucket,
  baseName,
  compareName,
}: {
  bucket: SnapshotDiffBucket
  baseName: string
  compareName: string
}) {
  const meta = KIND_META[bucket.kind]
  return (
    <div className={`traffic-card ${meta.cardClass}`}>
      <div className="traffic-flow">
        <span className={`tag ${meta.tagClass}`}>{meta.text}</span>
        <ActionSide action={bucket.beforeAction} />
        <span className="reorder-arrow">→</span>
        <ActionSide action={bucket.afterAction} />
        <span className="spacer" />
        <span className="muted-text">
          {formatSize(bucket.size)} 条报文空间 · {formatSize(bucket.cells)} 个原子单元
        </span>
      </div>
      <div className="goal-block-title">代表报文（可复制复现）</div>
      {bucket.examples.map((ex, i) => (
        <div className="packet-box" key={i}>
          <span className={`tag ${meta.tagClass}`}>代表报文</span>
          <span>{formatPacket(ex.packet)}</span>
          <span className="arrow-note">
            {baseName}：
            {ex.beforeRuleIndex === null
              ? '未命中'
              : `#${ex.beforeRuleIndex + 1} ${ex.beforeRuleName}`}
            {' → '}
            {compareName}：
            {ex.afterRuleIndex === null
              ? '未命中'
              : `#${ex.afterRuleIndex + 1} ${ex.afterRuleName}`}
          </span>
          <CopyButton text={formatPacket(ex.packet)} />
        </div>
      ))}
      <div className="goal-block-title">精确区域（协议 → 连续端口段 × 规范 CIDR）</div>
      <RegionView regions={bucket.regions} />
    </div>
  )
}

function DiffReportView({
  report,
  baseMissing,
  compareMissing,
}: {
  report: SnapshotDiffReport
  baseMissing: boolean
  compareMissing: boolean
}) {
  return (
    <div className="snapshot-report">
      {(baseMissing || compareMissing) && (
        <div className="notice warn">
          ⚠ 报告引用的{baseMissing ? `基准快照「${report.baseName}」` : ''}
          {baseMissing && compareMissing ? '与' : ''}
          {compareMissing ? `对比快照「${report.compareName}」` : ''}
          已被删除；以下为删除前生成的历史对比结果（只读），快照内容在生成时刻已固定。
        </div>
      )}

      <div className="legend" style={{ marginTop: 0, marginBottom: 10 }}>
        基准（旧）「{report.baseName}」→ 对比（新）「{report.compareName}」 · 生成于{' '}
        {formatSnapshotTime(report.generatedAt)} · 合并原子空间{' '}
        {formatSize(report.totalCells)} 个单元；基准 {report.baseActiveRules} 条、
        对比 {report.compareActiveRules} 条合法且启用规则参与重放
        {report.baseInvalidExcluded + report.compareInvalidExcluded > 0 &&
          `（排除非法规则 ${report.baseInvalidExcluded} + ${report.compareInvalidExcluded} 条）`}
        {report.baseDisabledExcluded + report.compareDisabledExcluded > 0 &&
          `（排除停用规则 ${report.baseDisabledExcluded} + ${report.compareDisabledExcluded} 条）`}
        。
      </div>

      {!report.hasDifference ? (
        <div className="notice ok">
          ✓ 两个快照的首命中动作完全一致：合并空间中每个报文单元的最终动作都相同
          （首命中规则可能易主，但动作不变）。
        </div>
      ) : (
        <div className="notice error">
          ✗ 两个快照存在动作层面差异：动作改变 {formatSize(report.actionChangedSize)}、
          命中 → 未命中 {formatSize(report.hitToMissSize)}、 未命中 → 命中{' '}
          {formatSize(report.missToHitSize)}（条报文空间）。明细见下方分桶。
        </div>
      )}

      <div className="stats">
        <div className="stat-card ok">
          <div className="label">动作未变</div>
          <div className="value" style={{ fontSize: 16 }}>
            {formatSize(report.sameActionSize)}
          </div>
          <div className="label">{formatSize(report.sameActionCells)} 个单元</div>
        </div>
        <div className="stat-card danger">
          <div className="label">动作改变</div>
          <div className="value" style={{ fontSize: 16 }}>
            {formatSize(report.actionChangedSize)}
          </div>
          <div className="label">{formatSize(report.actionChangedCells)} 个单元</div>
        </div>
        <div className="stat-card warn">
          <div className="label">命中 → 未命中</div>
          <div className="value" style={{ fontSize: 16 }}>
            {formatSize(report.hitToMissSize)}
          </div>
          <div className="label">{formatSize(report.hitToMissCells)} 个单元</div>
        </div>
        <div className="stat-card">
          <div className="label">未命中 → 命中</div>
          <div className="value" style={{ fontSize: 16 }}>
            {formatSize(report.missToHitSize)}
          </div>
          <div className="label">{formatSize(report.missToHitCells)} 个单元</div>
        </div>
        <div className="stat-card">
          <div className="label">两侧均未命中（不展开）</div>
          <div className="value muted-text" style={{ fontSize: 16 }}>
            {formatSize(report.bothMissSize)}
          </div>
          <div className="label">{formatSize(report.bothMissCells)} 个单元</div>
        </div>
      </div>

      {report.buckets.length > 0 && (
        <h3 className="reorder-section-title">
          分桶明细（{report.buckets.length} 组，按 动作改变 → 命中↔未命中 → 动作未变 排列）
        </h3>
      )}
      {report.buckets.map((bucket, i) => (
        <BucketCard
          key={`${bucket.kind}|${bucket.beforeAction ?? ''}|${bucket.afterAction ?? ''}|${i}`}
          bucket={bucket}
          baseName={report.baseName}
          compareName={report.compareName}
        />
      ))}
    </div>
  )
}

export function SnapshotPanel({ rules, snapshots, onSaveSnapshot, onDeleteSnapshot }: Props) {
  const [nameInput, setNameInput] = useState('')
  const [nameError, setNameError] = useState<string | null>(null)
  const [baseId, setBaseId] = useState('')
  const [compareId, setCompareId] = useState('')
  const [compareError, setCompareError] = useState<string | null>(null)
  const [report, setReport] = useState<SnapshotDiffReport | null>(null)

  // 建议名：留空保存时自动使用，保证不重名
  const suggestedName = useMemo(() => {
    let n = snapshots.length + 1
    let candidate = `快照 ${n}`
    while (snapshots.some((s) => s.name === candidate)) {
      n++
      candidate = `快照 ${n}`
    }
    return candidate
  }, [snapshots])

  // 每份快照的规则构成（保存后内容固定，统计只随列表变化重算）
  const statsById = useMemo(() => {
    const map = new Map<
      string,
      { total: number; active: number; invalid: number; disabled: number }
    >()
    for (const s of snapshots) {
      const { valid, invalid } = validateRules(s.rules)
      const active = valid.filter((r) => r.enabled).length
      map.set(s.id, {
        total: s.rules.length,
        active,
        invalid: invalid.length,
        disabled: valid.length - active,
      })
    }
    return map
  }, [snapshots])

  // 快照被删除后，对应选择自动回落为未选
  const baseSel = snapshots.some((s) => s.id === baseId) ? baseId : ''
  const compareSel = snapshots.some((s) => s.id === compareId) ? compareId : ''

  const save = () => {
    const name = nameInput.trim() || suggestedName
    if (snapshots.some((s) => s.name === name)) {
      setNameError(`已存在同名快照「${name}」，请换一个名称`)
      return
    }
    onSaveSnapshot(name)
    setNameInput('')
    setNameError(null)
  }

  const generate = () => {
    const base = snapshots.find((s) => s.id === baseSel)
    const compare = snapshots.find((s) => s.id === compareSel)
    if (!base || !compare) {
      setCompareError('请先在上方列表两侧分别选择基准（旧）与对比（新）快照')
      return
    }
    if (base.id === compare.id) {
      setCompareError('基准与对比不能是同一份快照，请选择两个不同的快照')
      return
    }
    // 只读对比：结果由两份快照内容唯一确定，不触碰当前规则
    setReport(diffSnapshots(base, compare))
    setCompareError(null)
  }

  const swap = () => {
    setBaseId(compareSel)
    setCompareId(baseSel)
  }

  const selectionMismatch =
    report !== null &&
    (report.baseSnapshotId !== baseSel || report.compareSnapshotId !== compareSel)

  return (
    <div className="panel snapshot-panel">
      <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0 }}>审计快照对比（只读）</h2>
        <span className="legend" style={{ marginLeft: 12 }}>
          为当前规则集保存带名称的快照；任选两份快照，在合并的 IPv4 原子块 × 端口原子段 ×
          TCP/UDP 单元上逐单元重放首命中，精确对比动作变化；对比不改动当前规则
        </span>
      </div>

      <div className="snapshot-save-row">
        <input
          value={nameInput}
          onChange={(e) => {
            setNameInput(e.target.value)
            setNameError(null)
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter') save()
          }}
          placeholder={`快照名称（留空使用「${suggestedName}」）`}
          spellCheck={false}
        />
        <button className="primary" onClick={save}>
          保存当前规则为快照（{rules.length} 条）
        </button>
      </div>
      {nameError && <div className="notice error">{nameError}</div>}

      {snapshots.length === 0 ? (
        <div className="notice info" style={{ marginBottom: 0 }}>
          还没有快照。输入名称（或留空使用建议名）后点击「保存当前规则为快照」，
          保存两份后即可生成对比报告。快照保存的是保存时刻的规则副本，之后的编辑不影响它。
        </div>
      ) : (
        <>
          <div className="snapshot-list">
            {snapshots.map((s) => {
              const st = statsById.get(s.id)!
              return (
                <div className="snapshot-row" key={s.id}>
                  <span className="snapshot-name">{s.name}</span>
                  <span className="muted-text">
                    {formatSnapshotTime(s.createdAt)} · {st.total} 条规则（{st.active} 条参与分析
                    {st.invalid > 0 && ` · ${st.invalid} 条非法`}
                    {st.disabled > 0 && ` · ${st.disabled} 条停用`}）
                  </span>
                  <span className="spacer" />
                  <button onClick={() => onDeleteSnapshot(s.id)}>删除</button>
                </div>
              )
            })}
          </div>

          <div className="snapshot-compare-row">
            <label>
              <span>基准快照（旧）</span>
              <select value={baseSel} onChange={(e) => setBaseId(e.target.value)}>
                <option value="">（请选择）</option>
                {snapshots.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}（{s.rules.length} 条规则）
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span>对比快照（新）</span>
              <select value={compareSel} onChange={(e) => setCompareId(e.target.value)}>
                <option value="">（请选择）</option>
                {snapshots.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}（{s.rules.length} 条规则）
                  </option>
                ))}
              </select>
            </label>
            <button onClick={swap} disabled={!baseSel && !compareSel}>
              ⇄ 交换
            </button>
            <button className="primary" onClick={generate} disabled={snapshots.length < 2}>
              生成对比报告
            </button>
          </div>
          {compareError && <div className="notice error">{compareError}</div>}
          {snapshots.length < 2 && (
            <div className="notice info" style={{ marginBottom: 0 }}>
              再保存 {2 - snapshots.length} 份快照后即可生成对比报告。
            </div>
          )}
        </>
      )}

      {report && selectionMismatch && (
        <div className="notice info">
          当前选择的快照与下方报告不一致；点击「生成对比报告」按新选择重新生成。
        </div>
      )}

      {report && (
        <DiffReportView
          report={report}
          baseMissing={!snapshots.some((s) => s.id === report.baseSnapshotId)}
          compareMissing={!snapshots.some((s) => s.id === report.compareSnapshotId)}
        />
      )}
    </div>
  )
}
