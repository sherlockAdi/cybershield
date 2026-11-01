'use client';

import { useEffect, useRef, useState, type FormEvent } from 'react';
import { RefreshCw, ShieldCheck } from 'lucide-react';
import { api } from '../lib/api';

type Rollout = { id: string; mode: string; state: string; target_checksum: string; policy_name: string; version: number; approval_state: string; stage_deadline_at: string | null; last_reconciled_at: string | null };
type Target = { id: string; server_id: string; hostname: string; state: string; is_canary: boolean; error_code: string | null; watchdog_deadline_at: string | null; confirmed_at: string | null; simulation_online: boolean; simulation_failure: string; verification_evidence: unknown };
type Detail = { deployment: Rollout; approval: { state: string; requester_id: string; approver_id: string | null; expires_at: string; reason: string }; targets: Target[]; jobs: { id: string; target_id: string; operation: string; state: string; idempotency_key: string; expires_at: string }[]; history: { id: string; action: string; actor_name: string | null; created_at: string; metadata: unknown }[] };
type Page = { items: Rollout[]; nextCursor: string | null };
const date = (value: string | null) => value ? new Date(value).toLocaleString() : '—';

export function RolloutRequest({ organizationId, versionId, checksum, serverIds, onError }: { organizationId: string; versionId: string; checksum: string; serverIds: string[]; onError: (error: unknown) => void }) {
  const [busy, setBusy] = useState(false); const [notice, setNotice] = useState('');
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = new FormData(event.currentTarget); setBusy(true); setNotice('');
    try {
      await api(`/organizations/${organizationId}/rollouts`, 'POST', { mode: 'SIMULATION', versionId, expectedChecksum: checksum, canaryServerIds: form.getAll('canary'), batchSize: Number(form.get('batchSize')), canaryTimeoutSeconds: Number(form.get('timeout')), reason: form.get('reason') });
      setNotice('Approval requested. Open Approvals & rollouts; a different administrator from the requester and policy author must decide.');
    } catch (error) { onError(error); } finally { setBusy(false); }
  }
  return <form className="firewall-rule" onSubmit={submit}><h3>Request a simulation rollout</h3><p className="muted">Only sandbox database state changes. No native agent jobs are delivered and no host firewall is modified.</p><div className="group-checkboxes">{serverIds.map(id => <label key={id}><input type="checkbox" name="canary" value={id} />Canary {id}</label>)}</div><small>Select 1–3 canaries from the sealed target snapshot.</small><div className="firewall-fields"><label className="field"><span>Batch size</span><input type="number" name="batchSize" min={1} max={10} defaultValue={2} required /></label><label className="field"><span>Canary/rollout stage timeout (seconds)</span><input type="number" name="timeout" min={30} max={600} defaultValue={300} required /></label></div><label className="field"><span>Request reason</span><input name="reason" minLength={3} maxLength={1000} required /></label><button className="button secondary" disabled={busy}>{busy ? 'Requesting…' : 'Request approval · simulation only'}</button>{notice && <p role="status" className="success-text">{notice}</p>}</form>;
}

function Scenario({ target, base, disabled, changed }: { target: Target; base: string; disabled: boolean; changed: (task: () => Promise<void>) => void }) {
  const [online, setOnline] = useState(target.simulation_online); const [failure, setFailure] = useState(target.simulation_failure);
  useEffect(() => { setOnline(target.simulation_online); setFailure(target.simulation_failure); }, [target.simulation_online, target.simulation_failure]);
  return <form className="rollout-scenario" onSubmit={event => { event.preventDefault(); const form = new FormData(event.currentTarget); changed(async () => { await api(`${base}/targets/${target.id}/scenario`, 'PATCH', { online, failureMode: failure, reason: form.get('reason') }); }); }}><label><input type="checkbox" checked={online} onChange={event => setOnline(event.target.checked)} /> Sandbox connected</label><select aria-label={`Failure scenario for ${target.hostname}`} value={failure} onChange={event => setFailure(event.target.value)}><option value="NONE">No simulated failure</option><option value="APPLY">Apply failure</option><option value="VERIFY">Verification failure</option><option value="ROLLBACK">Rollback failure</option></select><input name="reason" placeholder="Scenario change reason" aria-label="Scenario change reason" minLength={3} maxLength={1000} required /><button className="button secondary compact" disabled={disabled}>Set scenario</button></form>;
}

export default function Rollouts({ organizationId, canManage, userId, onError }: { organizationId: string; canManage: boolean; userId: string; onError: (error: unknown) => void }) {
  const [items, setItems] = useState<Rollout[]>([]); const [cursor, setCursor] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null); const [detail, setDetail] = useState<Detail | null>(null);
  const [busy, setBusy] = useState(false); const [error, setError] = useState(''); const [reason, setReason] = useState('');
  const alive = useRef(true); const request = useRef(0); const pages = useRef(false); const current = useRef(selected); current.current = selected;
  const callback = useRef(onError); callback.current = onError;
  const base = `/organizations/${organizationId}/rollouts`;
  function failure(error: unknown) { if (alive.current) { setError(error instanceof Error ? error.message : 'Rollout request failed'); callback.current(error); } }
  async function load(append = false) {
    const sequence = ++request.current; const id = current.current;
    const [page, nextDetail] = await Promise.all([!pages.current || append ? api<Page>(`${base}${append && cursor ? `?cursor=${cursor}` : ''}`) : Promise.resolve(null), id ? api<Detail>(`${base}/${id}`) : Promise.resolve(null)]);
    if (!alive.current || sequence !== request.current || id !== current.current) return;
    if (page) { setItems(previous => append ? [...previous, ...page.items] : page.items); setCursor(page.nextCursor); if (append) pages.current = true; }
    setDetail(nextDetail);
  }
  useEffect(() => {
    alive.current = true; void load().catch(failure);
    const timer = setInterval(() => { if (!document.hidden) void load().catch(failure); }, 5000);
    return () => { alive.current = false; request.current++; clearInterval(timer); };
  }, [organizationId, selected]);
  async function work(task: () => Promise<void>) {
    setBusy(true); setError(''); try { await task(); if (alive.current) await load(); } catch (error) { failure(error); } finally { if (alive.current) setBusy(false); }
  }
  async function action(action: string) {
    if (reason.trim().length < 3) { setError('Enter an action reason (at least three characters).'); return; }
    if (action === 'ROLLBACK' && !confirm('Restore retained sandbox state? This is simulation-only and does not modify native firewall rules.')) return;
    await work(async () => { await api(`${base}/${selected}/actions`, 'POST', { action, reason }); });
  }
  const state = detail?.deployment.state;
  return <>
    <div className="message simulation-banner"><ShieldCheck size={23} /><div><strong>SIMULATION ONLY · LIVE ENFORCEMENT DISABLED</strong><p>Approvals are real authorization decisions. Canary jobs, reachability evidence and rollback modify a database sandbox, not Linux/Windows firewalls. Native watchdog and independent offline execution remain unimplemented.</p></div></div>
    {error && <div className="message error" role="alert">{error}</div>}
    <section className="panel"><div className="panel-heading"><div><h2>Approvals & rollouts</h2><p>Distinct approver · frozen target set · explicit canary promotion</p></div><button className="button secondary compact" disabled={busy} onClick={() => work(async () => { pages.current = false; await load(); })}><RefreshCw size={15} />Refresh</button></div><div className="table-wrap"><table><thead><tr><th>Policy / deployment</th><th>State</th><th>Approval</th><th>Mode</th></tr></thead><tbody>{items.map(item => <tr key={item.id}><td><button className="text-button" disabled={busy} onClick={() => { setDetail(null); setSelected(item.id); setReason(''); }}>{item.policy_name} · v{item.version}</button><div className="muted">{item.id}</div></td><td><span className={`badge ${item.state === 'SUCCEEDED' || item.state === 'ROLLED_BACK' ? 'green' : item.state === 'FAILED' ? 'red' : 'amber'}`}>{item.state.replaceAll('_', ' ')}</span></td><td>{item.approval_state}</td><td>{item.mode}</td></tr>)}</tbody></table></div>{!items.length && <div className="empty"><p>No rollout requests. Seal a policy version, then request a simulation rollout from Firewall policies.</p></div>}{cursor && <div className="pagination-bar"><button className="button secondary" disabled={busy} onClick={() => work(() => load(true))}>Load more</button></div>}</section>
    {detail && <><section className="panel section-gap"><div className="panel-heading"><div><h2>Deployment · {state?.replaceAll('_', ' ')}</h2><p>Approval expires {date(detail.approval.expires_at)} · Last reconciled {date(detail.deployment.last_reconciled_at)}</p></div><span className="badge amber">SANDBOX</span></div><div className="firewall-editor"><code className="secret">{detail.deployment.id}<br />SHA-256 {detail.deployment.target_checksum}</code><p className="muted">Stage deadline: {date(detail.deployment.stage_deadline_at)} · Approval reason: {detail.approval.reason}</p>{canManage && <><label className="field"><span>Reason for approval/control action</span><input value={reason} minLength={3} maxLength={1000} onChange={event => setReason(event.target.value)} /></label><div className="button-row rollout-controls">{detail.approval.state === 'PENDING' && detail.approval.requester_id !== userId && ['APPROVE', 'REJECT'].map(decision => <button key={decision} className={`button ${decision === 'APPROVE' ? 'primary' : 'secondary'}`} disabled={busy || reason.trim().length < 3} onClick={() => work(async () => { await api(`${base}/${selected}/decision`, 'POST', { decision, expectedChecksum: detail.deployment.target_checksum, reason }); })}>{decision === 'APPROVE' ? 'Approve sandbox rollout' : 'Reject request'}</button>)}{['QUEUED', 'CANARY', 'ROLLING_OUT'].includes(state!) && <button className="button secondary" disabled={busy} onClick={() => action('PAUSE')}>Pause</button>}{state === 'PAUSED' && <button className="button secondary" disabled={busy} onClick={() => action('RESUME')}>Resume</button>}{state === 'CANARY' && <button className="button primary" disabled={busy || !detail.targets.filter(target => target.is_canary).every(target => target.state === 'VERIFIED')} onClick={() => action('PROMOTE')}>Promote verified canaries</button>}{['CANARY', 'ROLLING_OUT', 'PAUSED', 'SUCCEEDED', 'FAILED'].includes(state!) && <button className="button secondary" disabled={busy} onClick={() => action('ROLLBACK')}>Rollback sandbox state</button>}{['PENDING_APPROVAL', 'QUEUED', 'CANARY', 'PAUSED', 'ROLLING_OUT'].includes(state!) && <button className="button secondary" disabled={busy} onClick={() => action('CANCEL')}>Cancel undispatched work</button>}</div>{detail.approval.requester_id === userId && detail.approval.state === 'PENDING' && <p className="list-note">You cannot approve your own request. Invite another administrator. The policy author also cannot approve.</p>}</>}</div></section>
      <section className="panel section-gap"><div className="panel-heading"><div><h2>Targets & simulated verification</h2><p>Watchdog deadlines are persisted before simulated mutation and never reset by retries.</p></div></div>{detail.targets.map(target => <div className="rollout-target" key={target.id}><div className="panel-heading"><div><h3>{target.hostname} {target.is_canary && <span className="badge">CANARY</span>}</h3><p>{target.state} · {target.simulation_online ? 'Sandbox connected' : 'Sandbox disconnected'} · {target.error_code || 'No error'}</p></div></div><div className="firewall-editor"><p className="muted">Watchdog: {date(target.watchdog_deadline_at)} · Confirmed: {date(target.confirmed_at)}</p>{target.verification_evidence != null && <details><summary>Simulation evidence (not host attestation)</summary><pre className="native-preview">{JSON.stringify(target.verification_evidence, null, 2)}</pre></details>}{canManage && <Scenario target={target} base={`${base}/${selected}`} disabled={busy} changed={task => void work(task)} />}</div></div>)}</section>
      <section className="panel section-gap"><div className="panel-heading"><h2>Durable sandbox jobs</h2></div><div className="table-wrap"><table><thead><tr><th>Operation</th><th>State</th><th>Idempotency key</th><th>Expires</th></tr></thead><tbody>{detail.jobs.map(job => <tr key={job.id}><td>{job.operation}</td><td>{job.state}</td><td><code>{job.idempotency_key}</code></td><td>{date(job.expires_at)}</td></tr>)}</tbody></table></div></section>
      <section className="panel section-gap"><div className="panel-heading"><div><h2>Rollout audit history</h2><p>Latest 100 append-only entries</p></div></div><div className="table-wrap"><table><thead><tr><th>Action</th><th>Actor</th><th>Time</th><th>Evidence</th></tr></thead><tbody>{detail.history.map(event => <tr key={event.id}><td>{event.action}</td><td>{event.actor_name || 'Reconciler'}</td><td>{date(event.created_at)}</td><td><details><summary>Details</summary><pre className="native-preview">{JSON.stringify(event.metadata, null, 2)}</pre></details></td></tr>)}</tbody></table></div></section>
    </>}
  </>;
}
