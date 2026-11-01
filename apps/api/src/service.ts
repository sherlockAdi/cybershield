import { Injectable, Inject, BadRequestException, ConflictException, ForbiddenException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { randomUUID, randomBytes } from 'node:crypto';
import type { Request, Response } from 'express';
import QRCode from 'qrcode';
import { z } from 'zod';
import { Database, Queryable, Row } from './database';
import { digest, token, passwordHash, passwordMatches, newTotpSecret, encryptSecret, decryptSecret, validTotpStep } from './security';
import { input, name, email, password, uuid, roles, Role } from './input';
import { production } from './config';

export interface Actor { id: string; session_id: string; family_id: string; name: string; email: string; mfa_enabled: boolean; mfa_verified: boolean }

@Injectable()
export class ControlService {
  constructor(@Inject(Database) readonly db: Database) {}

  async audit(client: Queryable, organizationId: string, actorId: string | null, action: string, resourceId: string, metadata: Row = {}) {
    await client.query('INSERT INTO audit_logs (id,organization_id,actor_id,action,resource_id,request_id,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)', [randomUUID(), organizationId, actorId, action, resourceId, randomUUID(), JSON.stringify(metadata)]);
  }

  async authenticate(request: Request, requireMfa = true): Promise<Actor> {
    const access = request.cookies?.sg_access;
    if (typeof access !== 'string') throw new UnauthorizedException('Sign in to continue');
    const { rows } = await this.db.query(`SELECT u.id,u.name,u.email,u.mfa_enabled,s.id AS session_id,s.family_id,s.mfa_verified,s.csrf_hash
      FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.access_hash=$1 AND s.revoked_at IS NULL AND s.consumed_at IS NULL
      AND s.access_expires_at>now() AND s.expires_at>now() AND u.disabled_at IS NULL`, [digest(access)]);
    if (!rows.length) throw new UnauthorizedException('Session expired. Sign in again.');
    const actor = rows[0] as Actor & { csrf_hash: string };
    if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method)) {
      const csrf = request.headers['x-csrf-token'];
      if (typeof csrf !== 'string' || digest(csrf) !== actor.csrf_hash) throw new ForbiddenException('Invalid CSRF token');
    }
    if (requireMfa && (!actor.mfa_enabled || !actor.mfa_verified)) throw new ForbiddenException('Complete two-factor authentication first');
    return actor;
  }

  async membership(client: Queryable, organizationId: string, actor: Actor, allowed: readonly Role[] = roles) {
    input(uuid, organizationId);
    const { rows } = await client.query('SELECT role FROM memberships WHERE organization_id=$1 AND user_id=$2', [organizationId, actor.id]);
    if (!rows.length) throw new NotFoundException('Organization not found');
    if (!allowed.includes(rows[0].role)) throw new ForbiddenException('Your role does not permit this action');
    return rows[0].role as Role;
  }

  async session(client: Queryable, userId: string, verified: boolean, familyId = randomUUID(), expiresAt = new Date(Date.now() + 7 * 86400000)) {
    const credentials = { access: token(), refresh: token(), csrf: token() };
    await client.query(`INSERT INTO sessions (id,user_id,family_id,access_hash,refresh_hash,csrf_hash,mfa_verified,access_expires_at,expires_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [randomUUID(), userId, familyId, digest(credentials.access), digest(credentials.refresh), digest(credentials.csrf), verified, new Date(Math.min(Date.now() + 15 * 60000, expiresAt.getTime())), expiresAt]);
    return credentials;
  }

  cookies(response: Response, credentials: { access: string; refresh: string; csrf: string }) {
    const options = { secure: production, sameSite: 'strict' as const, path: '/' };
    response.cookie('sg_access', credentials.access, { ...options, httpOnly: true, maxAge: 15 * 60000 });
    response.cookie('sg_refresh', credentials.refresh, { ...options, httpOnly: true, maxAge: 7 * 86400000 });
    response.cookie('sg_csrf', credentials.csrf, { ...options, httpOnly: false, maxAge: 7 * 86400000 });
  }

  async register(body: unknown, response: Response) {
    if (production && process.env.ALLOW_REGISTRATION !== 'true') throw new ForbiddenException('Public registration is disabled');
    const data = input(z.object({ name, email, password, organization: name }).strict(), body);
    const encoded = await passwordHash(data.password);
    const userId = randomUUID();
    const organizationId = randomUUID();
    try {
      const credentials = await this.db.transaction(async client => {
        await client.query('INSERT INTO users (id,name,email,password_hash) VALUES ($1,$2,$3,$4)', [userId, data.name, data.email, encoded]);
        await client.query('INSERT INTO organizations (id,name,updated_at) VALUES ($1,$2,now())', [organizationId, data.organization]);
        await client.query('INSERT INTO memberships (organization_id,user_id,role) VALUES ($1,$2,\'OWNER\')', [organizationId, userId]);
        await this.audit(client, organizationId, userId, 'organization.created', organizationId);
        return this.session(client, userId, false);
      });
      this.cookies(response, credentials);
      return { ok: true, mfaRequired: true };
    } catch (error) {
      if ((error as { code?: string }).code === '23505') throw new ConflictException('Unable to create account with these details');
      throw error;
    }
  }

  async login(body: unknown, response: Response) {
    const data = input(z.object({ email, password: z.string().min(1).max(128), code: z.string().max(100).optional() }).strict(), body);
    const { rows } = await this.db.query('SELECT * FROM users WHERE email=$1', [data.email]);
    const user = rows[0];
    const fallback = '$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRmb3JhdXRoMQ$GPRi0d9xFGJkplD87EGKHdKCW/5K1+gc5ebhgnfGlAg';
    const matches = await passwordMatches(user?.password_hash || fallback, data.password).catch(() => false);
    if (!matches || !user || user.disabled_at) throw new UnauthorizedException('Invalid email, password or verification code');
    if (user.mfa_enabled && !data.code) return { mfaRequired: true, challenge: true };
    const credentials = await this.db.transaction(async client => {
      if (user.mfa_enabled) await this.consumeMfa(client, user.id, data.code || '');
      const result = await this.session(client, user.id, Boolean(user.mfa_enabled));
      const memberships = await client.query('SELECT organization_id FROM memberships WHERE user_id=$1', [user.id]);
      for (const membership of memberships.rows) await this.audit(client, membership.organization_id, user.id, 'auth.login', user.id);
      return result;
    });
    this.cookies(response, credentials);
    return { ok: true, mfaRequired: !user.mfa_enabled };
  }

  async consumeMfa(client: Queryable, userId: string, code: string) {
    const { rows } = await client.query('SELECT * FROM users WHERE id=$1 FOR UPDATE', [userId]);
    const user = rows[0];
    const step = validTotpStep(decryptSecret(user.mfa_secret_encrypted), code, Number(user.mfa_last_step));
    if (step !== null) {
      await client.query('UPDATE users SET mfa_last_step=$2 WHERE id=$1', [userId, step]);
      return;
    }
    const recovered = await client.query('UPDATE mfa_recovery_codes SET used_at=now() WHERE user_id=$1 AND code_hash=$2 AND used_at IS NULL RETURNING id', [userId, digest(code)]);
    if (!recovered.rows.length) throw new UnauthorizedException('Invalid or already used verification code');
  }

  async refresh(request: Request, response: Response) {
    const refresh = request.cookies?.sg_refresh;
    const csrf = request.headers['x-csrf-token'];
    if (typeof refresh !== 'string' || typeof csrf !== 'string') throw new UnauthorizedException('Session expired');
    const result = await this.db.transaction(async client => {
      const { rows } = await client.query('SELECT s.*,u.disabled_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.refresh_hash=$1 FOR UPDATE OF s', [digest(refresh)]);
      const session = rows[0];
      if (!session || session.csrf_hash !== digest(csrf) || session.disabled_at || session.revoked_at || new Date(session.expires_at).getTime() <= Date.now()) return null;
      if (session.consumed_at) {
        await client.query('UPDATE sessions SET revoked_at=now() WHERE family_id=$1', [session.family_id]);
        return null;
      }
      await client.query('UPDATE sessions SET consumed_at=now() WHERE id=$1', [session.id]);
      return this.session(client, session.user_id, session.mfa_verified, session.family_id, new Date(session.expires_at));
    });
    if (!result) throw new UnauthorizedException('Session expired or reused. Sign in again.');
    this.cookies(response, result);
    return { ok: true };
  }

  async logout(request: Request, response: Response) {
    const refresh = request.cookies?.sg_refresh;
    const csrf = request.headers['x-csrf-token'];
    if (typeof refresh === 'string') {
      if (typeof csrf !== 'string') throw new ForbiddenException('Invalid CSRF token');
      await this.db.query('UPDATE sessions SET revoked_at=now() WHERE family_id IN (SELECT family_id FROM sessions WHERE refresh_hash=$1 AND csrf_hash=$2)', [digest(refresh), digest(csrf)]);
    }
    for (const cookie of ['sg_access', 'sg_refresh', 'sg_csrf']) response.clearCookie(cookie, { path: '/', secure: production, sameSite: 'strict' });
    return { ok: true };
  }

  async me(actor: Actor) {
    const { rows } = await this.db.query('SELECT o.id,o.name,m.role FROM organizations o JOIN memberships m ON m.organization_id=o.id WHERE m.user_id=$1 ORDER BY o.created_at,o.id', [actor.id]);
    return { user: { id: actor.id, name: actor.name, email: actor.email, mfaEnabled: actor.mfa_enabled, mfaVerified: actor.mfa_verified }, organizations: rows, databaseMode: this.db.mode };
  }

  async mfaSetup(actor: Actor) {
    if (actor.mfa_enabled) throw new ConflictException('Two-factor authentication is already enabled');
    const secret = newTotpSecret();
    await this.db.query('UPDATE users SET mfa_pending_encrypted=$2 WHERE id=$1 AND mfa_enabled=false', [actor.id, encryptSecret(secret)]);
    const uri = `otpauth://totp/ServerGuard:${encodeURIComponent(actor.email)}?secret=${secret}&issuer=ServerGuard&algorithm=SHA1&digits=6&period=30`;
    return { secret, qr: await QRCode.toDataURL(uri), uri };
  }

  async mfaConfirm(actor: Actor, body: unknown) {
    const data = input(z.object({ code: z.string().regex(/^\d{6}$/) }).strict(), body);
    const recoveryCodes = Array.from({ length: 10 }, () => randomBytes(10).toString('hex'));
    await this.db.transaction(async client => {
      const { rows } = await client.query('SELECT mfa_pending_encrypted,mfa_enabled FROM users WHERE id=$1 FOR UPDATE', [actor.id]);
      const user = rows[0];
      if (!user.mfa_pending_encrypted || user.mfa_enabled) throw new BadRequestException('Start two-factor setup first');
      const step = validTotpStep(decryptSecret(user.mfa_pending_encrypted), data.code);
      if (step === null) throw new BadRequestException('Invalid verification code');
      await client.query('UPDATE users SET mfa_enabled=true,mfa_secret_encrypted=mfa_pending_encrypted,mfa_pending_encrypted=NULL,mfa_last_step=$2 WHERE id=$1', [actor.id, step]);
      await client.query('UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND id<>$2', [actor.id, actor.session_id]);
      await client.query('UPDATE sessions SET mfa_verified=true WHERE id=$1', [actor.session_id]);
      for (const code of recoveryCodes) await client.query('INSERT INTO mfa_recovery_codes (id,user_id,code_hash) VALUES ($1,$2,$3)', [randomUUID(), actor.id, digest(code)]);
      const memberships = await client.query('SELECT organization_id FROM memberships WHERE user_id=$1', [actor.id]);
      for (const membership of memberships.rows) await this.audit(client, membership.organization_id, actor.id, 'auth.mfa_enabled', actor.id);
    });
    return { recoveryCodes };
  }

  async createOrganization(actor: Actor, body: unknown) {
    const data = input(z.object({ name }).strict(), body);
    const organizationId = randomUUID();
    await this.db.transaction(async client => {
      await client.query('INSERT INTO organizations (id,name,updated_at) VALUES ($1,$2,now())', [organizationId, data.name]);
      await client.query('INSERT INTO memberships (organization_id,user_id,role) VALUES ($1,$2,\'OWNER\')', [organizationId, actor.id]);
      await this.audit(client, organizationId, actor.id, 'organization.created', organizationId);
    });
    return { id: organizationId, name: data.name, role: 'OWNER' };
  }

  async overview(actor: Actor, organizationId: string) {
    await this.membership(this.db, organizationId, actor);
    const counts = await this.db.query(`SELECT
      (SELECT count(*)::int FROM memberships WHERE organization_id=$1) AS members,
      (SELECT count(*)::int FROM servers WHERE organization_id=$1 AND decommissioned_at IS NULL) AS servers,
      (SELECT count(*)::int FROM firewall_policies WHERE organization_id=$1) AS policies,
      (SELECT count(*)::int FROM incidents WHERE organization_id=$1 AND state<>'RESOLVED') AS incidents,
      (SELECT count(*)::int FROM audit_logs WHERE organization_id=$1) AS audit_entries`, [organizationId]);
    const activity = await this.db.query('SELECT a.id,a.action,a.resource_id,a.metadata,a.created_at,u.name AS actor_name FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id WHERE a.organization_id=$1 ORDER BY a.created_at DESC,a.id DESC LIMIT 12', [organizationId]);
    return { ...counts.rows[0], activity: activity.rows };
  }

  async members(actor: Actor, organizationId: string) {
    await this.membership(this.db, organizationId, actor);
    const { rows } = await this.db.query('SELECT u.id,u.name,u.email,u.mfa_enabled,m.role,m.created_at FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 ORDER BY m.created_at,u.id', [organizationId]);
    return rows;
  }

  async updateOrganization(actor: Actor, organizationId: string, body: unknown) {
    const data = input(z.object({ name }).strict(), body);
    await this.db.transaction(async client => {
      await client.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [input(uuid, organizationId)]);
      await this.membership(client, organizationId, actor, ['OWNER', 'ADMIN']);
      await client.query('UPDATE organizations SET name=$2,updated_at=now() WHERE id=$1', [organizationId, data.name]);
      await this.audit(client, organizationId, actor.id, 'organization.updated', organizationId, { name: data.name });
    });
    return { ok: true };
  }

  async changeMember(actor: Actor, organizationId: string, userId: string, body: unknown, remove = false) {
    input(uuid, userId);
    const role = remove ? null : input(z.object({ role: z.enum(roles) }).strict(), body).role;
    await this.db.transaction(async client => {
      await client.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [input(uuid, organizationId)]);
      const actorRole = await this.membership(client, organizationId, actor, ['OWNER', 'ADMIN']);
      const existing = await client.query('SELECT role FROM memberships WHERE organization_id=$1 AND user_id=$2', [organizationId, userId]);
      if (!existing.rows.length) throw new NotFoundException('Member not found');
      const oldRole = existing.rows[0].role;
      if ((oldRole === 'OWNER' || role === 'OWNER') && actorRole !== 'OWNER') throw new ForbiddenException('Only an owner can change ownership');
      if (oldRole === 'OWNER' && role !== 'OWNER') {
        const owners = await client.query('SELECT count(*)::int AS count FROM memberships WHERE organization_id=$1 AND role=\'OWNER\'', [organizationId]);
        if (owners.rows[0].count <= 1) throw new ConflictException('An organization must retain at least one owner');
      }
      if (remove) await client.query('DELETE FROM memberships WHERE organization_id=$1 AND user_id=$2', [organizationId, userId]);
      else await client.query('UPDATE memberships SET role=$3 WHERE organization_id=$1 AND user_id=$2', [organizationId, userId, role]);
      await this.audit(client, organizationId, actor.id, remove ? 'member.removed' : 'member.role_changed', userId, { previousRole: oldRole, role });
    });
    return { ok: true };
  }

  async invitations(actor: Actor, organizationId: string) {
    await this.membership(this.db, organizationId, actor, ['OWNER', 'ADMIN']);
    return (await this.db.query('SELECT id,email,role,expires_at,accepted_at,revoked_at FROM invitations WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100', [organizationId])).rows;
  }

  async invite(actor: Actor, organizationId: string, body: unknown) {
    const data = input(z.object({ email, role: z.enum(roles) }).strict(), body);
    const invitationToken = token();
    const id = randomUUID();
    await this.db.transaction(async client => {
      await client.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [input(uuid, organizationId)]);
      const actorRole = await this.membership(client, organizationId, actor, ['OWNER', 'ADMIN']);
      if (data.role === 'OWNER' && actorRole !== 'OWNER') throw new ForbiddenException('Only an owner can invite another owner');
      const existing = await client.query('SELECT m.user_id FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND u.email=$2', [organizationId, data.email]);
      if (existing.rows.length) throw new ConflictException('This person is already a member');
      await client.query('UPDATE invitations SET revoked_at=now() WHERE organization_id=$1 AND email=$2 AND accepted_at IS NULL AND revoked_at IS NULL', [organizationId, data.email]);
      await client.query('INSERT INTO invitations (id,organization_id,email,role,token_hash,invited_by,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)', [id, organizationId, data.email, data.role, digest(invitationToken), actor.id, new Date(Date.now() + 48 * 3600000)]);
      await this.audit(client, organizationId, actor.id, 'invitation.created', id, { role: data.role });
    });
    return { id, token: invitationToken, message: 'Share this single-use token privately. Email delivery is not configured.' };
  }

  async revokeInvite(actor: Actor, organizationId: string, invitationId: string) {
    input(uuid, invitationId);
    await this.db.transaction(async client => {
      await client.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [input(uuid, organizationId)]);
      const actorRole = await this.membership(client, organizationId, actor, ['OWNER', 'ADMIN']);
      const result = await client.query('SELECT role FROM invitations WHERE id=$1 AND organization_id=$2', [invitationId, organizationId]);
      if (!result.rows.length) throw new NotFoundException('Invitation not found');
      if (result.rows[0].role === 'OWNER' && actorRole !== 'OWNER') throw new ForbiddenException('Only owners can revoke owner invitations');
      await client.query('UPDATE invitations SET revoked_at=now() WHERE id=$1 AND organization_id=$2 AND accepted_at IS NULL', [invitationId, organizationId]);
      await this.audit(client, organizationId, actor.id, 'invitation.revoked', invitationId);
    });
    return { ok: true };
  }

  async acceptInvite(actor: Actor, body: unknown) {
    const data = input(z.object({ token: z.string().min(20).max(200) }).strict(), body);
    return this.db.transaction(async client => {
      const preview = await client.query('SELECT organization_id FROM invitations WHERE token_hash=$1', [digest(data.token)]);
      if (!preview.rows.length) throw new NotFoundException('Invitation not found or expired');
      const organizationId = preview.rows[0].organization_id;
      await client.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [organizationId]);
      const { rows } = await client.query(`SELECT * FROM invitations WHERE token_hash=$1 AND email=$2 AND accepted_at IS NULL
        AND revoked_at IS NULL AND expires_at>now() FOR UPDATE`, [digest(data.token), actor.email]);
      if (!rows.length) throw new NotFoundException('Invitation not found or expired');
      const invitation = rows[0];
      const issuer = await client.query('SELECT role FROM memberships WHERE organization_id=$1 AND user_id=$2', [organizationId, invitation.invited_by]);
      if (!issuer.rows.length || !['OWNER', 'ADMIN'].includes(issuer.rows[0].role) || (invitation.role === 'OWNER' && issuer.rows[0].role !== 'OWNER')) throw new ForbiddenException('Invitation issuer no longer has permission');
      const existing = await client.query('SELECT user_id FROM memberships WHERE organization_id=$1 AND user_id=$2', [organizationId, actor.id]);
      if (existing.rows.length) throw new ConflictException('Already a member');
      await client.query('INSERT INTO memberships (organization_id,user_id,role) VALUES ($1,$2,$3)', [organizationId, actor.id, invitation.role]);
      await client.query('UPDATE invitations SET accepted_at=now() WHERE id=$1', [invitation.id]);
      await this.audit(client, organizationId, actor.id, 'invitation.accepted', invitation.id);
      return { ok: true, organizationId };
    });
  }

  async sessions(actor: Actor) {
    return (await this.db.query(`SELECT id,created_at,expires_at,mfa_verified,(id=$2) AS current FROM sessions
      WHERE user_id=$1 AND revoked_at IS NULL AND consumed_at IS NULL AND expires_at>now() ORDER BY created_at DESC LIMIT 100`, [actor.id, actor.session_id])).rows;
  }

  async revokeSession(actor: Actor, sessionId: string) {
    input(uuid, sessionId);
    await this.db.query('UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND family_id IN (SELECT family_id FROM sessions WHERE id=$2 AND user_id=$1)', [actor.id, sessionId]);
    return { ok: true };
  }
}
