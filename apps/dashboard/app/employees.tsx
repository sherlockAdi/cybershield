'use client';

import { useEffect, useState, type FormEvent } from 'react';
import { api } from '../lib/api';

type Employee = { id: string; name: string; email: string; aadhaar_reviewed_at: string | null; pan_reviewed_at: string | null; login_status: string; last_sign_in: string | null };

export default function Employees({ organizationId, openVault }: { organizationId: string; openVault: () => void }) {
  const endpoint = '/organizations/' + organizationId + '/employees';
  const [rows, setRows] = useState<Employee[] | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [invitation, setInvitation] = useState<{email: string; token: string} | null>(null);

  useEffect(() => {
    let active = true;
    void api<Employee[]>(endpoint).then(value => { if (active) setRows(value); })
      .catch(e => { if (active) setError(String(e.message)); });
    return () => { active = false; };
  }, [endpoint]);

  async function update(action: () => Promise<void>) {
    setBusy(true);
    setError('');
    try {
      await action();
      setRows(await api<Employee[]>(endpoint));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to save employee details');
    } finally {
      setBusy(false);
    }
  }

  function register(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const values = new FormData(form);
    void update(async () => {
      const result = await api<{ created: boolean }>(endpoint, 'POST', { name: values.get('name'), email: values.get('email') });
      if (!result.created) throw new Error('This email is already registered.');
      form.reset();
    });
  }

  return <section className="panel settings-panel">
    <h2>Employee registration</h2>
    <form onSubmit={register}>
      <label className="field"><span>Full name</span><input name="name" required maxLength={120} /></label>
      <label className="field"><span>Work email</span><input name="email" type="email" required maxLength={254} /></label>
      <button className="button primary" disabled={busy}>Register employee</button>
    </form>
    <h2>Document verification</h2>
    <p>Use the official services with employee consent. Record the review after completing it. For Aadhaar, use UIDAI’s secure QR workflow and keep only permitted, masked evidence.</p>
    <div className="button-row">
      <a className="button secondary" href="https://uidai.gov.in/pa/ovse" target="_blank" rel="noreferrer">UIDAI Aadhaar verification</a>
      <a className="button secondary" href="https://www.incometax.gov.in/iec/foportal/help/all-topics/e-filing-services/verify-your-pan" target="_blank" rel="noreferrer">Income Tax Verify PAN</a>
      <button className="button secondary" onClick={openVault}>Open encrypted document vault</button>
    </div>
    {error && <p role="alert" className="message error">{error}</p>}
    {rows === null ? <p>Loading employees…</p> : rows.length === 0 ? <p>No employees registered.</p> :
      <div className="table-wrap"><table><thead><tr><th>Employee</th><th>Workspace sign-in</th><th>Aadhaar review</th><th>PAN review</th></tr></thead>
        <tbody>{rows.map(row => <tr key={row.id}><td>{row.name}<br />{row.email}</td>
          <td>{row.login_status}<br />Last sign-in: {row.last_sign_in ? new Date(row.last_sign_in).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }) + ' IST' : 'No record'}
            {row.login_status === 'No workspace access' && <><br /><button className="button secondary" disabled={busy || Boolean(invitation)} onClick={() => {
              void update(async () => {
                const { token } = await api<{ token: string }>('/organizations/' + organizationId + '/invitations', 'POST', { email: row.email, role: 'VIEWER' });
                setInvitation({ email: row.email, token });
              });
            }}>Create sign-in invitation</button></>}
          </td>
          {(['aadhaar', 'pan'] as const).map(document => <td key={document}>
            {(document === 'aadhaar' ? row.aadhaar_reviewed_at : row.pan_reviewed_at) ? 'External review recorded' : <button className="button secondary" disabled={busy} onClick={() => {
              if (confirm('Record that you completed the external ' + document.toUpperCase() + ' review?')) {
                void update(async () => { await api(endpoint + '/' + row.id + '/review', 'PATCH', { document }); });
              }
            }}>Record completed review</button>}
          </td>)}
        </tr>)}</tbody></table></div>}
    {invitation && <div className="message"><p>Share this single-use invitation privately with {invitation.email}.</p><code className="secret">{invitation.token}</code><button className="button secondary" onClick={() => setInvitation(null)}>Dismiss</button></div>}
  </section>;
}
