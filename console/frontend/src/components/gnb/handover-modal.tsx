import { useEffect, useMemo, useState } from 'react'
import Modal from '../modal/modal'
import styles from '../modal/modal.module.css'
import { useGnb } from '../../context/gnbContext'
import type { GnbWithConnection } from '../../context/gnbContext'

type GnbEntry = GnbWithConnection

interface HandoverModalProps {
  isOpen: boolean
  onClose: () => void
  sourceGnb: GnbEntry
  imsi: string
  submitting: boolean
  onSubmit: (target: GnbEntry) => void
}

export function handoverTargetIssue(source: GnbEntry, target: GnbEntry): string | null {
  const sourceXn = source.gnbInfo?.xnInterface
  const targetXn = target.gnbInfo?.xnInterface
  if (target.status !== 'online') return 'offline'
  if (!sourceXn?.enable) return 'Xn disabled on this gNB'
  if (!targetXn?.enable) return 'Xn disabled'
  if (sourceXn.dialIp !== targetXn.listenIp || sourceXn.dialPort !== targetXn.listenPort) {
    return 'not the Xn peer of this gNB'
  }
  return null
}

export default function HandoverModal({ isOpen, onClose, sourceGnb, imsi, submitting, onSubmit }: HandoverModalProps) {
  const { gnbList } = useGnb()

  const candidates = useMemo(() => gnbList
    .filter(gnb => gnb.gnbInfo?.gnbId !== sourceGnb.gnbInfo?.gnbId)
    .map(gnb => ({ gnb, issue: handoverTargetIssue(sourceGnb, gnb) })), [gnbList, sourceGnb])

  const [targetId, setTargetId] = useState('')

  useEffect(() => {
    if (!isOpen) return
    const firstValid = candidates.find(candidate => candidate.issue === null)
    setTargetId(firstValid?.gnb.gnbInfo?.gnbId || '')
  }, [isOpen, candidates])

  const target = candidates.find(candidate => candidate.gnb.gnbInfo?.gnbId === targetId && candidate.issue === null)?.gnb

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Xn Handover"
      onSubmit={() => target && onSubmit(target)}
      submitLabel={submitting ? 'Handing over...' : 'Handover'}
      submitDisabled={!target || submitting}
    >
      <div className={styles.formGroup}>
        <label className={styles.label}>UE</label>
        <div className={styles.value}>{imsi}</div>
      </div>
      <div className={styles.formGroup}>
        <label className={styles.label}>Source gNB</label>
        <div className={styles.value}>
          {sourceGnb.gnbInfo?.gnbName} ({sourceGnb.gnbInfo?.gnbId})
        </div>
      </div>
      <div className={styles.formGroup}>
        <label className={styles.label} htmlFor="handover-target">Target gNB</label>
        {candidates.length === 0 ? (
          <div className={styles.hint}>No other gNB has been added to the console.</div>
        ) : (
          <select
            id="handover-target"
            className={styles.select}
            value={targetId}
            onChange={e => setTargetId(e.target.value)}
            disabled={submitting}
          >
            {!target && <option value="">Select a target gNB</option>}
            {candidates.map(({ gnb, issue }) => (
              <option key={gnb.gnbInfo?.gnbId} value={gnb.gnbInfo?.gnbId} disabled={issue !== null}>
                {gnb.gnbInfo?.gnbName} ({gnb.gnbInfo?.gnbId}) - {gnb.connection?.ip}:{gnb.connection?.port}
                {issue ? ` [${issue}]` : ''}
              </option>
            ))}
          </select>
        )}
        <div className={styles.hint}>
          Only the Xn peer of the source gNB can be selected. The UE must be in single connection.
        </div>
      </div>
    </Modal>
  )
}
