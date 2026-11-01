'use client';

import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { ShieldCheck, LayoutDashboard, Users, Building2, ScrollText, LockKeyhole, LogOut, ArrowUpRight, ChevronRight, Server, SlidersHorizontal, Activity, Plus, Check, X, Copy, Terminal, KeyRound, ArrowRight, Shield, Menu, RefreshCw } from 'lucide-react';
import { api, ApiError } from '../lib/api';
import Alerts from './alerts'; import Rollouts from './rollouts'; import Firewall from './firewall'; import Servers from './servers'; import { Events } from './telemetry';

type Role = 'OWNER' | 'ADMIN' | 'OPERATOR' | 'VIEWER';
type Organization = { id: string; name: string; role: Role };
type Me = { user: { id: string; name: string; email: string; mfaEnabled: boolean; mfaVerified: boolean }; organizations: Organization[]; databaseMode: string };
type Member = { id: string; name: string; email: string; role: Role; mfa_enabled: boolean; created_at: string };
type Invitation = { id: string; email: string; role: Role; expires_at: string; accepted_at: string | null; revoked_at: string | null };
type Audit = { id: string; action: string; actor_name: string | null; resource_id: string; created_at: string };
type Overview = { members: number; servers: number; policies: number; incidents: number; audit_entries: number; activity: Audit[] };
type Session = { id: string; created_at: string; expires_at: string; current: boolean; mfa_verified: boolean };
type Page = 'alerts' | 'rollouts' | 'firewall' | 'events' | 'overview' | 'servers' | 'members' | 'organizations' | 'audit' | 'security';
const navigation = [
  { id: 'overview' as Page, label: 'Overview', icon: LayoutDashboard },
  { id: 'servers' as Page, label: 'Servers & agents', icon: Server }, { id: 'events' as Page, label: 'Security events', icon: Activity }, { id: 'firewall' as Page, label: 'Firewall policies', icon: Shield }, { id: 'rollouts' as Page, label: 'Approvals & rollouts', icon: ShieldCheck }, { id: 'alerts' as Page, label: 'Alerts & notifications', icon: Activity },
  { id: 'members' as Page, label: 'Team & access', icon: Users },
  { id: 'organizations' as Page, label: 'Organizations', icon: Building2 },
  { id: 'audit' as Page, label: 'Audit trail', icon: ScrollText },
  { id: 'security' as Page, label: 'Account security', icon: LockKeyhole },
];
const date = (value: string) => new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const initials = (value: string) => value.split(' ').map(part => part[0]).slice(0, 2).join('').toUpperCase();

function Brand() { return <div className="brand"><span className="brand-icon"><ShieldCheck size={23} /></span><span>ServerGuard<span className="brand-ai">AI</span></span></div>; }
function Field({ label, children }: { label: string; children: ReactNode }) { return <label className="field"><span>{label}</span>{children}</label>; }
function Badge({ children, tone = '' }: { children: ReactNode; tone?: string }) { return <span className={`badge ${tone}`}>{children}</span>; }

export default function Home() {
  const [me, setMe] = useState<Me | null>(null);
  const [booting, setBooting] = useState(true);
  const [mode, setMode] = useState<'login' | 'register'>('register');
  const [challenge, setChallenge] = useState(false);
  const [page, setPage] = useState<Page>('overview');
  const [organizationId, setOrganizationId] = useState('');
  const [overview, setOverview] = useState<Overview | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [invitations, setInvitations] = useState<Invitation[]>([]);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [mobile, setMobile] = useState(false);
  const [modal, setModal] = useState<'create' | 'invite' | 'join' | null>(null);
  const [inviteToken, setInviteToken] = useState('');
  const [setup, setSetup] = useState<{ secret: string; qr: string } | null>(null);
  const [recovery, setRecovery] = useState<string[]>([]);
  const [savedCodes, setSavedCodes] = useState(false);
  const sequence = useRef(0);
  const activeOrganization = useRef(organizationId);
  activeOrganization.current = organizationId;
  const organization = me?.organizations.find(item => item.id === organizationId);
  const canManage = organization?.role === 'OWNER' || organization?.role === 'ADMIN';

  async function loadMe() {
    const data = await api<Me>('/auth/me');
    setMe(data);
    setOrganizationId(previous => data.organizations.some(item => item.id === previous) ? previous : data.organizations[0]?.id || '');
    return data;
  }
  useEffect(() => { loadMe().catch(failure => { if (!(failure instanceof ApiError && failure.status === 401)) setError(failure.message); }).finally(() => setBooting(false)); }, []);

  async function loadOrganization(id = organizationId, context = me) {
    if (!id || id !== activeOrganization.current || !context?.user.mfaEnabled || !context.user.mfaVerified) return;
    const current = ++sequence.current;
    setLoading(true);
    setOverview(null);
    setMembers([]);
    setInvitations([]);
    try {
      const role = context.organizations.find(item => item.id === id)?.role;
      if (!role) return;
      const [nextOverview, nextMembers, nextInvitations, nextSessions] = await Promise.all([
        api<Overview>(`/organizations/${id}/overview`), api<Member[]>(`/organizations/${id}/members`),
        role === 'OWNER' || role === 'ADMIN' ? api<Invitation[]>(`/organizations/${id}/invitations`) : Promise.resolve([]), api<Session[]>('/auth/sessions'),
      ]);
      if (sequence.current !== current || id !== activeOrganization.current) return;
      setOverview(nextOverview); setMembers(nextMembers); setInvitations(nextInvitations); setSessions(nextSessions);
    } catch (failure) { if (sequence.current === current) handleError(failure); }
    finally { if (sequence.current === current) setLoading(false); }
  }
  useEffect(() => { void loadOrganization(); return () => { sequence.current++; }; }, [organizationId, me?.user.mfaEnabled, me?.user.mfaVerified]);

  function handleError(failure: unknown) {
    setError(failure instanceof Error ? failure.message : 'Something went wrong');
    if (failure instanceof ApiError && failure.status === 401) { setMe(null); setMode('login'); }
  }
  async function refreshWorkspace() {
    const data = await loadMe();
    const selectedId = activeOrganization.current;
    const id = data.organizations.some(item => item.id === selectedId) ? selectedId : data.organizations[0]?.id || '';
    await loadOrganization(id, data);
  }
  async function refreshInventoryCounts() {
    const id = activeOrganization.current;
    try {
      const data = await api<Overview>(`/organizations/${id}/overview`);
      if (activeOrganization.current === id) setOverview(data);
    } catch (failure) { if (activeOrganization.current === id) handleError(failure); }
  }
  async function action(work: () => Promise<void>) {
    setBusy(true); setError(''); setNotice('');
    try { await work(); } catch (failure) { handleError(failure); } finally { setBusy(false); }
  }
  async function authSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = new FormData(event.currentTarget);
    await action(async () => {
      const result = await api<{ ok?: boolean; challenge?: boolean }>(`/auth/${mode}`, 'POST', mode === 'register'
        ? { name: form.get('name'), email: form.get('email'), password: form.get('password'), organization: form.get('organization') }
        : { email: form.get('email'), password: form.get('password'), ...(form.get('code') ? { code: form.get('code') } : {}) });
      if (result.challenge) { setChallenge(true); return; }
      setChallenge(false); await loadMe();
    });
  }
  async function logout() { await action(async () => { await api('/auth/logout', 'POST', {}); setMe(null); setSetup(null); setRecovery([]); setMode('login'); setOrganizationId(''); setOverview(null); }); }

  if (booting) return <main className="boot"><Brand /><span className="spinner" /><p>Connecting to your control plane…</p></main>;

  if (!me) return <main className="auth-shell">
    <section className="auth-story"><Brand /><div className="auth-copy"><span className="eyebrow">YOUR INFRASTRUCTURE. UNDER CONTROL.</span><h1>Strong security<br />starts with<br /><em>trusted access.</em></h1><p>A single control plane for your people, policies, and servers. Built to make every security decision accountable.</p><div className="auth-benefits"><span><ShieldCheck size={18} /> Multi-factor protection</span><span><Users size={18} /> Organization-scoped roles</span><span><ScrollText size={18} /> An auditable foundation</span></div></div><div className="auth-footer"><span className="status-dot" /> ServerGuard AI · Development workspace</div><div className="orbit orbit-one" /><div className="orbit orbit-two" /></section>
    <section className="auth-form-area"><div className="auth-card"><Badge tone="green">WEEKS 01—02 · FOUNDATION</Badge><h2>{mode === 'register' ? 'Create your workspace' : 'Welcome back'}</h2><p className="muted">{mode === 'register' ? 'Set up your account, then secure it with two-factor authentication.' : 'Sign in to your security control plane.'}</p>
      <div className="tabs"><button type="button" className={mode === 'register' ? 'active' : ''} onClick={() => { setMode('register'); setChallenge(false); setError(''); }}>Create account</button><button type="button" className={mode === 'login' ? 'active' : ''} onClick={() => { setMode('login'); setChallenge(false); setError(''); }}>Sign in</button></div>
      {error && <div className="message error" role="alert">{error}</div>}
      <form onSubmit={authSubmit} key={mode}>
        {mode === 'register' && <Field label="Full name"><input name="name" autoComplete="name" placeholder="Alex Morgan" required minLength={2} maxLength={100} /></Field>}
        <Field label="Email address"><input type="email" name="email" autoComplete="email" placeholder="you@company.com" required maxLength={254} /></Field>
        <Field label="Password"><input type="password" name="password" autoComplete={mode === 'register' ? 'new-password' : 'current-password'} placeholder={mode === 'register' ? 'At least 12 characters' : 'Enter your password'} required minLength={mode === 'register' ? 12 : 1} maxLength={128} /></Field>
        {mode === 'register' && <Field label="Organization name"><input name="organization" placeholder="Acme Infrastructure" required minLength={2} maxLength={100} /></Field>}
        {mode === 'login' && <Field label={challenge ? 'Verification code required' : 'Authenticator or recovery code (if enabled)'}><input name="code" autoComplete="one-time-code" placeholder="6-digit code or recovery code" required={challenge} maxLength={100} /></Field>}
        <button className="button primary wide" disabled={busy}>{busy ? 'Please wait…' : mode === 'register' ? 'Create secure workspace' : 'Sign in'}<ArrowRight size={17} /></button>
      </form><p className="auth-note"><LockKeyhole size={14} /> No default credentials. Your account is created securely.</p>
    </div></section>
  </main>;

  if (!me.user.mfaEnabled || !me.user.mfaVerified || recovery.length > 0) return <main className="mfa-shell"><Brand /><section className="mfa-card"><div className="feature-icon"><KeyRound size={25} /></div><span className="eyebrow">SECURE YOUR ACCOUNT</span><h1>{recovery.length ? 'Save your recovery codes' : 'Add a second layer of protection'}</h1><p className="muted">{recovery.length ? 'Each code can be used once if you lose your authenticator. Store them in a password manager. They will not be shown again.' : 'Two-factor authentication is required before accessing organizations. Use any TOTP authenticator app.'}</p>
    {error && <div className="message error" role="alert">{error}</div>}
    {recovery.length ? <><div className="recovery-grid">{recovery.map(code => <code key={code}>{code}</code>)}</div><button className="button secondary" onClick={() => action(async () => { await navigator.clipboard.writeText(recovery.join('\n')); setNotice('Recovery codes copied'); })}><Copy size={15} /> Copy codes</button><label className="check-label"><input type="checkbox" checked={savedCodes} onChange={event => setSavedCodes(event.target.checked)} /> I have stored these codes somewhere safe.</label><button className="button primary wide" disabled={!savedCodes || busy} onClick={() => action(async () => { await loadMe(); setRecovery([]); setSetup(null); })}>Open dashboard<ArrowRight size={17} /></button></>
      : setup ? <><div className="qr-wrap"><img src={setup.qr} width={184} height={184} alt="Scan this QR code with your authenticator" /></div><Field label="Or enter this setup key manually"><code className="secret">{setup.secret}</code></Field><form onSubmit={event => { event.preventDefault(); const form = new FormData(event.currentTarget); void action(async () => { const result = await api<{ recoveryCodes: string[] }>('/auth/mfa/confirm', 'POST', { code: form.get('code') }); setRecovery(result.recoveryCodes); }); }}><Field label="6-digit verification code"><input name="code" autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" placeholder="000000" required minLength={6} maxLength={6} /></Field><button className="button primary wide" disabled={busy}>Verify & enable<ShieldCheck size={17} /></button></form></>
      : <button className="button primary wide" disabled={busy} onClick={() => action(async () => setSetup(await api('/auth/mfa/setup', 'POST', {})))}>Set up authenticator<ArrowRight size={17} /></button>}
    {notice && <p role="status" className="success-text">{notice}</p>}<button className="text-button" disabled={busy} onClick={logout}>Sign out</button>
  </section></main>;

  function activityTable() {
    return overview?.activity.length ? <div className="table-wrap"><table><thead><tr><th>Event</th><th>Performed by</th><th>Time</th><th>Result</th></tr></thead><tbody>{overview.activity.map(item => <tr key={item.id}><td><span className="event-label"><span className="event-dot" />{item.action.replaceAll('.', ' · ').replaceAll('_', ' ')}</span></td><td>{item.actor_name || 'System'}</td><td className="muted">{date(item.created_at)}</td><td><Badge tone="green">Recorded</Badge></td></tr>)}</tbody></table></div> : <div className="empty"><ScrollText size={30} /><h3>No activity yet</h3><p>Administrative changes will appear here.</p></div>;
  }

  return <div className="app-shell">
    <aside className={`sidebar ${mobile ? 'open' : ''}`}><Brand /><div className="workspace-label">WORKSPACE</div><label className="org-selector"><Building2 size={18} /><select aria-label="Active organization" value={organizationId} onChange={event => { setOrganizationId(event.target.value); setError(''); setNotice(''); }}>{me.organizations.map(item => <option value={item.id} key={item.id}>{item.name}</option>)}</select></label>
      <div className="workspace-label nav-label">CONTROL PLANE</div><nav aria-label="Main navigation">{navigation.map(item => <button key={item.id} className={`nav-item ${page === item.id ? 'selected' : ''}`} onClick={() => { setPage(item.id); setMobile(false); setError(''); setNotice(''); }}><item.icon size={19} />{item.label}{page === item.id && <span className="nav-dot" />}</button>)}</nav>
      <div className="sidebar-bottom"><div className="foundation-card"><span className="small-label">BUILDING THE FOUNDATION</span><p>Safe operations start here.</p><div className="progress-track"><span /></div><span>Identity & access · Weeks 1–2</span></div><div className="user-box"><span className="avatar">{initials(me.user.name)}</span><div><strong>{me.user.name}</strong><span>{organization?.role.toLowerCase() || 'Member'}</span></div><button aria-label="Sign out" title="Sign out" onClick={logout} disabled={busy}><LogOut size={18} /></button></div></div>
    </aside>
    {mobile && <button className="backdrop" aria-label="Close navigation" onClick={() => setMobile(false)} />}
    <div className="main-shell"><header className="topbar"><div className="breadcrumb"><button className="mobile-toggle" aria-label="Open navigation" onClick={() => setMobile(true)}><Menu size={20} /></button><span>Workspace</span><ChevronRight size={14} /><strong>{navigation.find(item => item.id === page)?.label}</strong></div><div className="topbar-right"><span className="environment"><span className="status-dot" /> Local development</span><span className="topbar-divider" /><span className="avatar small">{initials(me.user.name)}</span></div></header>
      <main className="content"><div className="page-heading"><div><span className="eyebrow">SERVERGUARD CONTROL PLANE</span><h1>{page === 'overview' ? 'Security overview' : navigation.find(item => item.id === page)?.label}</h1><p className="muted">{page === 'overview' ? `Welcome back, ${me.user.name.split(' ')[0]}. Here’s your workspace at a glance.` : page === 'servers' ? 'Inspect host inventory, resource health and authenticated heartbeats.' : page === 'alerts' ? 'Investigate SSH/RDP and process indicators, review evidence and track in-app delivery.' : page === 'rollouts' ? 'Real approvals with simulation-only canaries, verification, rollback and offline scenarios.' : page === 'firewall' ? 'Validate rules, inspect native plans and preserve a versioned audit trail.' : page === 'events' ? 'Normalized agent events and resource-state transitions. Not a detection verdict.' : page === 'members' ? 'The right people. The right permissions. Every change accounted for.' : page === 'organizations' ? 'Keep teams and infrastructure securely separated.' : page === 'audit' ? 'A clear record of administrative decisions in this organization.' : 'Manage the protection around your personal account.'}</p></div><button className="button secondary compact" disabled={busy || loading} onClick={() => action(async () => { await refreshWorkspace(); })}><RefreshCw size={15} /> Refresh</button></div>
      {error && <div className="message error" role="alert">{error}<button aria-label="Dismiss error" onClick={() => setError('')}><X size={16} /></button></div>}{notice && <div className="message success" role="status">{notice}<button aria-label="Dismiss notification" onClick={() => setNotice('')}><X size={16} /></button></div>}
      {loading ? <div className="loading-panel"><span className="spinner" /> Loading organization…</div> : !organization ? <section className="panel empty"><Building2 size={32} /><h2>Create or join an organization</h2><p>Your account is ready. Choose where you want to work.</p><div className="button-row"><button className="button primary" onClick={() => setModal('create')}>Create organization</button><button className="button secondary" onClick={() => setModal('join')}>Join with a token</button></div></section> : <>
        {page === 'overview' && <><section className="welcome-panel"><div><Badge tone="green"><ShieldCheck size={12} /> IDENTITY & ACCESS READY</Badge><h2>A secure foundation.<br /><span>A clear path forward.</span></h2><p>Your workspace is protected with multi-factor authentication<br className="desktop-break" /> and organization-scoped access controls.</p><button className="button primary" onClick={() => setPage('members')}>Manage team access<ArrowUpRight size={16} /></button></div><div className="shield-visual" aria-hidden="true"><div className="radar-ring ring-a" /><div className="radar-ring ring-b" /><div className="radar-ring ring-c" /><div className="shield-center"><ShieldCheck size={73} strokeWidth={1.2} /></div><span className="radar-point point-a" /><span className="radar-point point-b" /><span className="visual-caption"><span className="status-dot" /> ACCESS PROTECTED</span></div></section>
          <section className="stats-grid" aria-label="Organization statistics">{[{ label: 'Team members', value: overview?.members ?? '—', icon: Users, detail: 'Organization-scoped access', accent: true }, { label: 'Enrolled servers', value: overview?.servers ?? '—', icon: Server, detail: 'Registered Linux and Windows hosts' }, { label: 'Firewall policies', value: overview?.policies ?? '—', icon: SlidersHorizontal, detail: 'Policy management arrives in Week 5' }, { label: 'Open incidents', value: overview?.incidents ?? '—', icon: Activity, detail: 'Detection arrives in Week 8' }].map(stat => <article className="stat-card" key={stat.label}><div><span>{stat.label}</span><stat.icon size={19} className={stat.accent ? 'accent' : ''} /></div><strong>{stat.value}</strong><p>{stat.detail}</p></article>)}</section>
          <div className="overview-grid"><section className="panel"><div className="panel-heading"><div><h2>Recent activity</h2><p>The latest changes to your workspace</p></div><button className="text-button" onClick={() => setPage('audit')}>View audit trail<ArrowUpRight size={15} /></button></div>{activityTable()}</section><section className="panel posture-panel"><div className="panel-heading"><div><h2>Access posture</h2><p>Your account and permissions</p></div><Shield size={18} className="accent" /></div><div className="posture-item"><span className="check-icon"><Check size={14} /></span><div><strong>Two-factor authentication</strong><p>Enabled for your account</p></div></div><div className="posture-item"><span className="check-icon"><Check size={14} /></span><div><strong>Organization isolation</strong><p>Permissions checked on every request</p></div></div><div className="posture-item"><span className="check-icon"><Check size={14} /></span><div><strong>Administrative auditing</strong><p>{overview?.audit_entries ?? 0} recorded events</p></div></div><div className="your-role"><span>Your current role</span><Badge>{organization.role}</Badge></div></section></div>
          <section className="next-step"><span className="feature-icon"><Terminal size={22} /></span><div><span className="small-label">AGENT PROTOTYPES · WEEK 3</span><h3>Connect your first server</h3><p>Register a Linux or Windows host and verify its signed heartbeat.</p></div><button className="button secondary compact" onClick={() => setPage('servers')}>View agents<ArrowUpRight size={15} /></button></section>
        </>}
        {page === 'alerts' && <Alerts key={organizationId} organizationId={organizationId} canManage={canManage} canTriage={canManage || organization.role === 'OPERATOR'} onError={handleError} />}{page === 'rollouts' && <Rollouts key={organizationId} organizationId={organizationId} canManage={canManage} userId={me.user.id} onError={handleError} />}{page === 'firewall' && <Firewall key={organizationId} organizationId={organizationId} canManage={canManage} onError={handleError} />}{page === 'events' && <Events key={organizationId} organizationId={organizationId} onError={handleError} />}{page === 'servers' && <Servers key={organizationId} organizationId={organizationId} canManage={canManage} onChanged={() => void refreshInventoryCounts()} onSessionExpired={() => { setMe(null); setMode('login'); }} />}
        {page === 'members' && <><section className="panel"><div className="panel-heading"><div><h2>Team members <span className="count">{members.length}</span></h2><p>Access to {organization.name}</p></div>{canManage && <button className="button primary compact" onClick={() => { setInviteToken(''); setModal('invite'); }}><Plus size={16} /> Invite member</button>}</div><div className="table-wrap"><table><thead><tr><th>Member</th><th>Role</th><th>Account protection</th><th>Joined</th><th>Actions</th></tr></thead><tbody>{members.map(member => <tr key={member.id}><td><div className="member-cell"><span className="avatar">{initials(member.name)}</span><div><strong>{member.name}{member.id === me.user.id && <small> (you)</small>}</strong><span>{member.email}</span></div></div></td><td>{canManage && (organization.role === 'OWNER' || member.role !== 'OWNER') ? <select aria-label={`Role for ${member.name}`} value={member.role} disabled={busy} onChange={event => { const role = event.target.value; void action(async () => { await api(`/organizations/${organizationId}/members/${member.id}`, 'PATCH', { role }); await refreshWorkspace(); setNotice('Role updated'); }); }}>{(organization.role === 'OWNER' ? ['OWNER', 'ADMIN', 'OPERATOR', 'VIEWER'] : ['ADMIN', 'OPERATOR', 'VIEWER']).map(role => <option key={role}>{role}</option>)}</select> : <Badge>{member.role}</Badge>}</td><td><Badge tone={member.mfa_enabled ? 'green' : 'amber'}>{member.mfa_enabled ? 'MFA enabled' : 'Setup pending'}</Badge></td><td className="muted">{date(member.created_at)}</td><td>{canManage && (organization.role === 'OWNER' || member.role !== 'OWNER') && <button className="text-button danger" disabled={busy} onClick={() => { if (confirm(`Remove ${member.name} from ${organization.name}? Their access will end immediately.`)) void action(async () => { await api(`/organizations/${organizationId}/members/${member.id}`, 'DELETE'); await refreshWorkspace(); setNotice('Member removed'); }); }}>Remove</button>}</td></tr>)}</tbody></table></div></section>
          {canManage && <section className="panel section-gap"><div className="panel-heading"><div><h2>Invitations</h2><p>Single-use tokens expire after 48 hours. Share them privately.</p></div></div>{invitations.length ? <div className="table-wrap"><table><thead><tr><th>Email</th><th>Role</th><th>Status</th><th>Expires</th><th>Actions</th></tr></thead><tbody>{invitations.map(invitation => <tr key={invitation.id}><td>{invitation.email}</td><td><Badge>{invitation.role}</Badge></td><td>{invitation.accepted_at ? 'Accepted' : invitation.revoked_at ? 'Revoked' : new Date(invitation.expires_at).getTime() < Date.now() ? 'Expired' : 'Pending'}</td><td className="muted">{date(invitation.expires_at)}</td><td>{!invitation.accepted_at && !invitation.revoked_at && (organization.role === 'OWNER' || invitation.role !== 'OWNER') && <button className="text-button danger" disabled={busy} onClick={() => action(async () => { await api(`/organizations/${organizationId}/invitations/${invitation.id}`, 'DELETE'); await loadOrganization(); setNotice('Invitation revoked'); })}>Revoke</button>}</td></tr>)}</tbody></table></div> : <div className="empty compact-empty"><Users size={25} /><p>No invitations yet.</p></div>}</section>}
          <section className="role-guide"><h3>Understand your roles</h3><div>{[['OWNER', 'Organization ownership and all administration'], ['ADMIN', 'Manage teams and organization settings'], ['OPERATOR', 'Read access; future policy drafting and submission'], ['VIEWER', 'Read-only access to organization data']].map(([role, detail]) => <p key={role}><Badge>{role}</Badge><span>{detail}</span></p>)}</div></section>
        </>}
        {page === 'organizations' && <><div className="section-toolbar"><p className="muted">You belong to {me.organizations.length} organization{me.organizations.length !== 1 ? 's' : ''}.</p><div className="button-row"><button className="button secondary" onClick={() => setModal('join')}>Join with token</button><button className="button primary" onClick={() => setModal('create')}><Plus size={16} /> New organization</button></div></div><section className="organization-grid">{me.organizations.map(item => <article className={`panel organization-card ${item.id === organizationId ? 'current-org' : ''}`} key={item.id}><span className="feature-icon"><Building2 size={25} /></span><Badge>{item.role}</Badge><h2>{item.name}</h2><p className="muted">Separate membership, policies and audit history.</p><button className={`button ${item.id === organizationId ? 'secondary' : 'primary'} wide`} disabled={item.id === organizationId} onClick={() => setOrganizationId(item.id)}>{item.id === organizationId ? <><Check size={15} /> Current workspace</> : <>Switch workspace<ArrowRight size={15} /></>}</button></article>)}</section>{canManage && <section className="panel settings-panel section-gap"><h2>Organization settings</h2><p className="muted">Update the name of the active organization.</p><form key={organizationId} onSubmit={event => { event.preventDefault(); const form = new FormData(event.currentTarget); void action(async () => { await api(`/organizations/${organizationId}`, 'PATCH', { name: form.get('name') }); await refreshWorkspace(); setNotice('Organization updated'); }); }}><Field label="Organization name"><input name="name" defaultValue={organization.name} minLength={2} maxLength={100} required /></Field><button className="button primary" disabled={busy}>Save changes</button></form></section>}</>}
        {page === 'audit' && <section className="panel"><div className="panel-heading"><div><h2>Administrative activity</h2><p>Latest 12 events · {overview?.audit_entries ?? 0} total · displayed in your local timezone</p></div><Badge tone="green">APPEND-ONLY</Badge></div>{activityTable()}</section>}
        {page === 'security' && <><section className="panel security-summary"><div className="feature-icon"><ShieldCheck size={27} /></div><div><h2>Two-factor authentication is enabled</h2><p className="muted">Authenticator verification protects {me.user.email}. Keep your recovery codes somewhere safe.</p></div><Badge tone="green">PROTECTED</Badge></section><section className="panel section-gap"><div className="panel-heading"><div><h2>Active sessions</h2><p>Revoke a session to end its access and refresh credentials.</p></div></div><div className="table-wrap"><table><thead><tr><th>Session</th><th>Created</th><th>Expires</th><th>Actions</th></tr></thead><tbody>{sessions.map(session => <tr key={session.id}><td><span className="session-label"><Terminal size={17} />{session.current ? 'This session' : `Session ${session.id.slice(0, 8)}`}{session.current && <Badge tone="green">CURRENT</Badge>}</span></td><td className="muted">{date(session.created_at)}</td><td className="muted">{date(session.expires_at)}</td><td><button className="text-button danger" disabled={busy} onClick={() => action(async () => { await api(`/auth/sessions/${session.id}`, 'DELETE'); if (session.current) { setMe(null); setMode('login'); } else { await loadOrganization(); setNotice('Session revoked'); } })}>Revoke</button></td></tr>)}</tbody></table></div></section><div className="info-note"><LockKeyhole size={17} /><p>Passwords use Argon2id. Session tokens are hashed at rest, refresh credentials rotate on use, and MFA secrets are encrypted.</p></div></>}
      </>}
      <footer className="content-footer"><span>ServerGuard AI <span className="muted">/</span> Identity & access foundation</span><span>{me.databaseMode === 'embedded-postgresql' ? 'Embedded PostgreSQL · local data' : 'External PostgreSQL'}</span></footer>
      </main>
    </div>
    {modal && <div className="modal-overlay" onClick={event => { if (event.target === event.currentTarget && !busy) { setModal(null); setInviteToken(''); } }}><section role="dialog" aria-modal="true" aria-labelledby="modal-title" className="modal"><button className="modal-close" aria-label="Close dialog" disabled={busy} onClick={() => { setModal(null); setInviteToken(''); }}><X size={20} /></button><span className="feature-icon">{modal === 'invite' ? <Users size={24} /> : <Building2 size={24} />}</span><h2 id="modal-title">{modal === 'create' ? 'Create an organization' : modal === 'join' ? 'Join an organization' : 'Invite a team member'}</h2><p className="muted">{modal === 'create' ? 'A separate workspace with its own members and audit trail.' : modal === 'join' ? 'Use the token shared by an administrator. Your account email must match the invitation.' : 'Choose the minimum access this person needs.'}</p>{error && <div className="message error" role="alert">{error}</div>}
      {inviteToken ? <><Field label="Single-use invitation token"><code className="secret">{inviteToken}</code></Field><p className="muted">Shown once. Email delivery is not configured; share this token privately with the intended recipient.</p><button className="button primary wide" onClick={() => action(async () => { await navigator.clipboard.writeText(inviteToken); setNotice('Invitation token copied'); })}><Copy size={16} /> Copy token</button></> : <form onSubmit={event => { event.preventDefault(); const form = new FormData(event.currentTarget); void action(async () => { if (modal === 'create') { const result = await api<Organization>('/organizations', 'POST', { name: form.get('name') }); await loadMe(); setOrganizationId(result.id); setModal(null); setNotice('Organization created'); } else if (modal === 'join') { const result = await api<{ organizationId: string }>('/invitations/accept', 'POST', { token: form.get('token') }); await loadMe(); setOrganizationId(result.organizationId); setModal(null); setNotice('You joined the organization'); } else { const result = await api<{ token: string }>(`/organizations/${organizationId}/invitations`, 'POST', { email: form.get('email'), role: form.get('role') }); setInviteToken(result.token); await loadOrganization(); } }); }}>
        {modal === 'create' ? <Field label="Organization name"><input name="name" required minLength={2} maxLength={100} autoFocus placeholder="Acme Infrastructure" /></Field> : modal === 'join' ? <Field label="Invitation token"><input name="token" required minLength={20} maxLength={200} autoFocus autoComplete="off" placeholder="Paste your invitation token" /></Field> : <><Field label="Email address"><input name="email" type="email" required maxLength={254} autoFocus placeholder="teammate@company.com" /></Field><Field label="Organization role"><select name="role" defaultValue="VIEWER">{(organization?.role === 'OWNER' ? ['VIEWER', 'OPERATOR', 'ADMIN', 'OWNER'] : ['VIEWER', 'OPERATOR', 'ADMIN']).map(role => <option key={role}>{role}</option>)}</select></Field></>}
        <button className="button primary wide" disabled={busy}>{busy ? 'Please wait…' : modal === 'create' ? 'Create organization' : modal === 'join' ? 'Accept invitation' : 'Create invitation'}<ArrowRight size={16} /></button>
      </form>}
    </section></div>}
  </div>;
}
