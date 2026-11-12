import { BadRequestException, ConflictException, Inject, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { createHash, createPublicKey, KeyObject, randomUUID, verify } from 'node:crypto';
import type { Request } from 'express';
import { z } from 'zod';
import { Database, Row, Queryable } from './database';
import { Actor, ControlService } from './service';
import { input, uuid } from './input';
import { digest, token } from './security';
import { managementSchema, acceptManagement } from './host-management';
import { inventorySchema, metricsSchema, recordMetrics } from './telemetry-model';

const hostname = z.string().trim().min(1).max(253).regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/);
const os = z.enum(['LINUX', 'WINDOWS']);
const version = z.string().min(1).max(100);
const enrollmentSchema = z.object({ schemaVersion: z.literal(1), serverId: uuid, token: z.string().min(32).max(100), publicKey: z.string().max(2048), hostname, os, osVersion: version, agentVersion: version }).strict();
const heartbeatSchema = z.object({ schemaVersion: z.literal(1), serverId: uuid, credentialId: uuid, sequence: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER), hostname, os, osVersion: version, agentVersion: version, uptimeSeconds: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER), inventory: inventorySchema.optional(), metrics: metricsSchema.optional(), management: managementSchema.nullish(), deviceAudit: z.object({ schemaVersion: z.literal(1), collectedAt: z.string().datetime({ offset: true }), mode: z.literal('AUDIT_ONLY'), computerName: z.string().max(253), employeeMapping: z.string().max(100), deviceIdentity: z.string().max(100), sections: z.record(z.string().regex(/^[A-Za-z][A-Za-z0-9]{0,59}$/), z.object({ status: z.enum(['OBSERVED', 'UNKNOWN']), data: z.array(z.unknown()).max(300), error: z.string().max(200).nullable() }).strict()).refine(value => Object.keys(value).length <= 30, 'Too many audit sections'), limitations: z.array(z.string().max(500)).max(20) }).strict().refine(value => Buffer.byteLength(JSON.stringify(value)) <= 100000, 'Device audit exceeds limit').nullish() }).strict();

export type AgentRequest = Request & { rawBody?: Buffer };
export function signingMessage(path: string, timestamp: string, nonce: string, rawBody: Buffer) {
  return Buffer.from(`SG1\nPOST\n${path}\n${timestamp}\n${nonce}\n${createHash('sha256').update(rawBody).digest('hex')}`, 'utf8');
}

function publicKey(pem: string) {
  try {
    if (!/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\s*$/.test(pem)) throw new Error('Expected SPKI PEM');
    const key = createPublicKey(pem);
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw new Error('Unsupported key');
    return key;
  } catch { throw new BadRequestException('A P-256 SPKI public key is required'); }
}

function verifyRequest(request: AgentRequest, key: KeyObject, endpoint: string) {
  const timestamp = request.headers['x-sg-timestamp'];
  const nonce = request.headers['x-sg-nonce'];
  const signature = request.headers['x-sg-signature'];
  if (!request.rawBody || request.originalUrl !== endpoint || typeof timestamp !== 'string' || !/^\d{10}$/.test(timestamp)
    || Math.abs(Date.now() / 1000 - Number(timestamp)) > 90 || typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{22,64}$/.test(nonce)
    || typeof signature !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(signature) || signature.length > 128) throw new UnauthorizedException('Invalid agent signature envelope');
  let valid = false;
  try { valid = verify('sha256', signingMessage(endpoint, timestamp, nonce, request.rawBody), key, Buffer.from(signature, 'base64')); } catch {}
  if (!valid) throw new UnauthorizedException('Invalid agent signature');
}

export function agentStatus(server: Row, now = Date.now()) {
  if (server.decommissioned_at) return 'DECOMMISSIONED';
  if (!server.credential_id) return server.had_credentials ? 'REVOKED_OR_EXPIRED' : 'PENDING_ENROLLMENT';
  if (!server.last_heartbeat_at) return 'AWAITING_HEARTBEAT';
  const age = (now - new Date(server.last_heartbeat_at).getTime()) / 1000;
  return age <= 90 ? 'ONLINE' : age <= 300 ? 'STALE' : 'UNKNOWN';
}

@Injectable()
export class AgentService {
  constructor(@Inject(Database) private readonly db: Database, @Inject(ControlService) private readonly control: ControlService) {}

  async createServer(actor: Actor, organizationId: string, body: unknown) {
    const data = input(z.object({ hostname, os, device: z.boolean().optional() }).strict(), body);
    if (data.device && data.os !== 'WINDOWS') throw new BadRequestException('Device pilot supports Windows only');
    const serverId = randomUUID();
    const enrollmentToken = token();
    const expiresAt = new Date(Date.now() + 10 * 60000);
    await this.db.transaction(async client => {
      await client.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [input(uuid, organizationId)]);
      await this.control.membership(client, organizationId, actor, ['OWNER', 'ADMIN']);
      await client.query('INSERT INTO servers (id,organization_id,hostname,os) VALUES ($1,$2,$3,$4)', [serverId, organizationId, data.hostname, data.os]);
      if (data.device) await client.query('UPDATE servers SET device_config=$2::jsonb WHERE id=$1', [serverId, JSON.stringify({ employeeId: null, notes: '', storage: 'AUDIT', approvedStorageIds: [], bluetooth: 'AUDIT', mtp: 'AUDIT', printers: 'AUDIT', usbNetwork: 'AUDIT', screenLockMinutes: 10, requireFirewall: true, requireAntivirus: true, requireEncryption: true })]);
      await client.query('INSERT INTO enrollment_tokens (id,organization_id,server_id,token_hash,created_by,expires_at) VALUES ($1,$2,$3,$4,$5,$6)', [randomUUID(), organizationId, serverId, digest(enrollmentToken), actor.id, expiresAt]);
      await this.control.audit(client, organizationId, actor.id, 'server.created', serverId, { os: data.os });
    });
    return { serverId, enrollmentToken, expiresAt, heartbeatIntervalSeconds: 30 };
  }

  async issueEnrollment(actor: Actor, organizationId: string, serverId: string) {
    input(uuid, serverId);
    const enrollmentToken = token();
    const expiresAt = new Date(Date.now() + 10 * 60000);
    await this.db.transaction(async client => {
      await client.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [input(uuid, organizationId)]);
      await this.control.membership(client, organizationId, actor, ['OWNER', 'ADMIN']);
      const server = await client.query('SELECT id FROM servers WHERE organization_id=$1 AND id=$2 AND decommissioned_at IS NULL FOR UPDATE', [organizationId, serverId]);
      if (!server.rows.length) throw new NotFoundException('Active server not found');
      await client.query('UPDATE enrollment_tokens SET revoked_at=now() WHERE organization_id=$1 AND server_id=$2 AND revoked_at IS NULL', [organizationId, serverId]);
      await client.query('INSERT INTO enrollment_tokens (id,organization_id,server_id,token_hash,created_by,expires_at) VALUES ($1,$2,$3,$4,$5,$6)', [randomUUID(), organizationId, serverId, digest(enrollmentToken), actor.id, expiresAt]);
      await this.control.audit(client, organizationId, actor.id, 'agent.enrollment_issued', serverId);
    });
    return { serverId, enrollmentToken, expiresAt, heartbeatIntervalSeconds: 30 };
  }

  async servers(actor: Actor, organizationId: string) {
    await this.control.membership(this.db, organizationId, actor);
    const result = await this.db.query(`SELECT servers.id,servers.hostname,servers.os,servers.os_version,servers.agent_version,servers.last_heartbeat_at,
      servers.decommissioned_at,servers.uptime_seconds::text,servers.created_at,active.id AS credential_id,active.expires_at AS credential_expires_at,
      EXISTS(SELECT 1 FROM agent_credentials history WHERE history.organization_id=servers.organization_id AND history.server_id=servers.id) AS had_credentials
      FROM servers LEFT JOIN LATERAL (SELECT id,expires_at FROM agent_credentials WHERE organization_id=servers.organization_id AND server_id=servers.id
      AND revoked_at IS NULL AND expires_at>now() ORDER BY created_at DESC LIMIT 1) active ON true
      WHERE servers.organization_id=$1 ORDER BY servers.created_at DESC,servers.id LIMIT 500`, [organizationId]);
    return result.rows.map(server => ({ ...server, status: agentStatus(server) }));
  }

  async revoke(actor: Actor, organizationId: string, serverId: string, decommission = false) {
    input(uuid, serverId);
    await this.db.transaction(async client => {
      await client.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [input(uuid, organizationId)]);
      await this.control.membership(client, organizationId, actor, ['OWNER', 'ADMIN']);
      const result = await client.query('SELECT id FROM servers WHERE organization_id=$1 AND id=$2 FOR UPDATE', [organizationId, serverId]);
      if (!result.rows.length) throw new NotFoundException('Server not found');
      await client.query('UPDATE agent_credentials SET revoked_at=now() WHERE organization_id=$1 AND server_id=$2 AND revoked_at IS NULL', [organizationId, serverId]);
      await client.query('UPDATE enrollment_tokens SET revoked_at=now() WHERE organization_id=$1 AND server_id=$2 AND revoked_at IS NULL', [organizationId, serverId]);
      if (decommission) await client.query('UPDATE servers SET decommissioned_at=now() WHERE organization_id=$1 AND id=$2', [organizationId, serverId]);
      await this.control.audit(client, organizationId, actor.id, decommission ? 'server.decommissioned' : 'agent.credentials_revoked', serverId);
    });
    return { ok: true };
  }

  async enroll(request: AgentRequest) {
    const data = input(enrollmentSchema, request.body);
    const key = publicKey(data.publicKey);
    verifyRequest(request, key, '/api/agent/v1/enroll');
    const fingerprint = createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');
    return this.db.transaction(async client => {
      const preliminary = await client.query('SELECT organization_id,server_id FROM enrollment_tokens WHERE token_hash=$1 AND server_id=$2', [digest(data.token), data.serverId]);
      if (!preliminary.rows.length) throw new UnauthorizedException('Enrollment token is invalid or expired');
      const organizationId = preliminary.rows[0].organization_id;
      await client.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [organizationId]);
      const server = await client.query('SELECT * FROM servers WHERE organization_id=$1 AND id=$2 FOR UPDATE', [organizationId, data.serverId]);
      const tokens = await client.query('SELECT * FROM enrollment_tokens WHERE token_hash=$1 AND server_id=$2 AND revoked_at IS NULL AND expires_at>now() FOR UPDATE', [digest(data.token), data.serverId]);
      const enrollment = tokens.rows[0];
      if (!enrollment || server.rows[0].decommissioned_at || server.rows[0].os !== data.os) throw new UnauthorizedException('Enrollment token or server binding is invalid');
      const issuer = await client.query('SELECT memberships.role FROM memberships JOIN users ON users.id=memberships.user_id WHERE memberships.organization_id=$1 AND memberships.user_id=$2 AND users.disabled_at IS NULL', [organizationId, enrollment.created_by]);
      if (!issuer.rows.length || !['OWNER', 'ADMIN'].includes(issuer.rows[0].role)) throw new UnauthorizedException('Enrollment issuer no longer has permission');
      if (enrollment.consumed_at) {
        const previous = await client.query('SELECT id,expires_at,key_fingerprint FROM agent_credentials WHERE id=$1 AND organization_id=$2 AND server_id=$3 AND revoked_at IS NULL AND expires_at>now()', [enrollment.credential_id, organizationId, data.serverId]);
        if (!previous.rows.length || previous.rows[0].key_fingerprint !== fingerprint) throw new UnauthorizedException('Enrollment token has already been used');
        return { credentialId: previous.rows[0].id, serverId: data.serverId, expiresAt: previous.rows[0].expires_at, heartbeatIntervalSeconds: 30 };
      }
      const duplicate = await client.query('SELECT id FROM agent_credentials WHERE key_fingerprint=$1', [fingerprint]);
      if (duplicate.rows.length) throw new ConflictException('Generate a fresh key for a new enrollment');
      const credentialId = randomUUID();
      const expiresAt = new Date(Date.now() + 30 * 86400000);
      await client.query('UPDATE agent_credentials SET revoked_at=now() WHERE organization_id=$1 AND server_id=$2 AND revoked_at IS NULL', [organizationId, data.serverId]);
      await client.query('INSERT INTO agent_credentials (id,organization_id,server_id,public_key_pem,key_fingerprint,expires_at) VALUES ($1,$2,$3,$4,$5,$6)', [credentialId, organizationId, data.serverId, key.export({ format: 'pem', type: 'spki' }).toString(), fingerprint, expiresAt]);
      await client.query('UPDATE enrollment_tokens SET consumed_at=now(),credential_id=$2 WHERE id=$1', [enrollment.id, credentialId]);
      await client.query('UPDATE servers SET hostname=$3,os_version=$4,agent_version=$5,last_heartbeat_at=NULL,uptime_seconds=NULL,management_snapshot=NULL,management_received_at=NULL,device_snapshot=NULL,device_received_at=NULL,capabilities=$6::jsonb WHERE organization_id=$1 AND id=$2', [organizationId, data.serverId, data.hostname, data.osVersion, data.agentVersion, JSON.stringify({ heartbeat: true, firewall: false, execution: false })]);
      await this.control.audit(client, organizationId, null, 'agent.enrolled', data.serverId, { credentialId, fingerprint });
      return { credentialId, serverId: data.serverId, expiresAt, heartbeatIntervalSeconds: 30 };
    });
  }

  async heartbeat(request: AgentRequest) {
    const data = input(heartbeatSchema, request.body);
    if (data.metrics && (Date.parse(data.metrics.sampledAt) > Date.now() + 90000 || Date.parse(data.metrics.sampledAt) < Date.now() - 10 * 60000)) throw new BadRequestException('Metric sample time must be recent');
    return this.db.transaction(async client => {
      const { server, credential } = await this.authorizeReport(client, request, data, '/api/agent/v1/heartbeat', data.os);
      await client.query('UPDATE agent_credentials SET last_sequence=$2 WHERE id=$1', [data.credentialId, data.sequence]);
      const updated = await client.query('UPDATE servers SET hostname=$3,os_version=$4,agent_version=$5,uptime_seconds=$6,last_heartbeat_at=now() WHERE organization_id=$1 AND id=$2 RETURNING last_heartbeat_at', [server.organization_id, data.serverId, data.hostname, data.osVersion, data.agentVersion, data.uptimeSeconds]);
      if (data.inventory) await client.query('UPDATE servers SET architecture=$3,logical_cpu_count=$4 WHERE organization_id=$1 AND id=$2', [server.organization_id, data.serverId, data.inventory.architecture, data.inventory.logicalCpuCount]);
      if (data.metrics) await recordMetrics(client, server.organization_id, data.serverId, data.credentialId, data.sequence, data.metrics);
      if (data.deviceAudit) {
        if (data.os !== 'WINDOWS') throw new BadRequestException('Windows audit required');
        const stamp = Date.parse(data.deviceAudit.collectedAt);
        if (stamp > Date.now() + 90000 || stamp < Date.now() - 10 * 60000) throw new BadRequestException('Device audit must be recent');
        await client.query('UPDATE servers SET device_snapshot=$3::jsonb,device_received_at=now() WHERE organization_id=$1 AND id=$2 AND device_config IS NOT NULL', [server.organization_id, data.serverId, JSON.stringify(data.deviceAudit)]);
      }
      const command = data.management ? await acceptManagement(client, server.organization_id, data.serverId, data.credentialId, data.management) : null;
      return { command, accepted: true, serverId: data.serverId, acceptedSequence: data.sequence, receivedAt: updated.rows[0].last_heartbeat_at, heartbeatIntervalSeconds: 30, credentialExpiresAt: credential.expires_at };
    });
  }

  async authorizeReport(client: Queryable, request: AgentRequest, identity: { serverId: string; credentialId: string; sequence: number }, endpoint: string, expectedOs?: string) {
    const servers = await client.query('SELECT organization_id,os,decommissioned_at FROM servers WHERE id=$1 FOR UPDATE', [identity.serverId]);
    if (!servers.rows.length || servers.rows[0].decommissioned_at) throw new UnauthorizedException('Agent identity is invalid');
    const server = servers.rows[0];
    const result = await client.query('SELECT * FROM agent_credentials WHERE id=$1 AND organization_id=$2 AND server_id=$3 AND revoked_at IS NULL AND expires_at>now() FOR UPDATE', [identity.credentialId, server.organization_id, identity.serverId]);
    const credential = result.rows[0];
    if (!credential?.public_key_pem || expectedOs !== undefined && server.os !== expectedOs) throw new UnauthorizedException('Agent identity is invalid');
    verifyRequest(request, publicKey(credential.public_key_pem), endpoint);
    if (identity.sequence <= Number(credential.last_sequence)) throw new ConflictException('Report sequence was already accepted or is stale');
    return { server, credential };
  }
}
