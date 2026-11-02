import { ConflictException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { z } from 'zod';
import { Database, Queryable } from './database';
import { Actor, ControlService } from './service';
import { input, uuid } from './input';

const text = z.string().max(500);
export const applicationSchema = z.object({ id: z.string().min(1).max(200), kind: z.enum(['SYSTEMD','DOCKER','WINDOWS_SERVICE','IIS_SITE','IIS_POOL']), name: text, state: text, instance: text, details: text, stoppable: z.boolean() }).strict();
const ip = z.string().refine(value => isIP(value) !== 0, 'Enter a literal IPv4 or IPv6 address');
const rule = z.object({ id: uuid, ip, scope: z.enum(['LOGIN','TCP']), ports: z.array(z.number().int().min(1).max(65535)).max(16) }).strict();
export const managementSchema = z.object({ applications: z.array(applicationSchema).max(200), rules: z.array(rule).max(200), firewall: z.boolean(), errors: z.array(text).max(10), truncated: z.boolean(), results: z.array(z.object({ id: uuid, success: z.boolean(), message: text }).strict()).max(1) }).strict();
const commandSchema = z.discriminatedUnion('operation', [
  z.object({ operation: z.literal('BLOCK_IP'), ip, scope: z.enum(['LOGIN','TCP']), ports: z.array(z.number().int().min(1).max(65535)).max(16) }).strict().refine(value => value.scope !== 'LOGIN' || value.ports.length > 0, 'Login requires the SSH/RDP port(s)'),
  z.object({ operation: z.literal('UNBLOCK_IP'), ruleId: uuid }).strict(),
  z.object({ operation: z.literal('STOP_APPLICATION'), applicationId: z.string().min(1).max(200), instance: text }).strict()
]);

// Called only inside the signed heartbeat transaction, after credential/sequence verification.
export async function acceptManagement(client: Queryable, organizationId: string, serverId: string, credentialId: string, report: z.infer<typeof managementSchema>) {
  await client.query('UPDATE servers SET management_snapshot=$3::jsonb,management_received_at=now() WHERE organization_id=$1 AND id=$2', [organizationId, serverId, JSON.stringify(report)]);
  for (const result of report.results) {
    const done = await client.query("UPDATE host_commands SET state=$4,completed_at=now(),message=$5 WHERE organization_id=$1 AND server_id=$2 AND id=$3 AND credential_id=$6 AND state='DISPATCHED' RETURNING id", [organizationId, serverId, result.id, result.success ? 'SUCCEEDED' : 'FAILED', result.message, credentialId]);
    if (done.rows.length) await client.query("INSERT INTO audit_logs (id,organization_id,actor_id,action,resource_id,request_id,metadata) VALUES ($1,$2,NULL,'host.command_result',$3,$5,$4::jsonb)", [randomUUID(), organizationId, result.id, JSON.stringify(result), randomUUID()]);
  }
  await client.query("UPDATE host_commands SET state='EXPIRED',message='Expired or agent credential changed; inspect host before retrying' WHERE organization_id=$1 AND server_id=$2 AND state IN ('PENDING','DISPATCHED') AND (expires_at<=now() OR credential_id<>$3)", [organizationId, serverId, credentialId]);
  const commands = await client.query("SELECT * FROM host_commands WHERE organization_id=$1 AND server_id=$2 AND credential_id=$3 AND state IN ('PENDING','DISPATCHED') ORDER BY created_at,id LIMIT 1 FOR UPDATE", [organizationId, serverId, credentialId]);
  const command = commands.rows[0];
  if (!command) return null;
  const authorized = await client.query("SELECT m.role FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND m.user_id=$2 AND u.disabled_at IS NULL AND m.role IN ('OWNER','ADMIN')", [organizationId, command.requested_by]);
  if (!authorized.rows.length) { await client.query("UPDATE host_commands SET state='EXPIRED',message='Requester no longer authorized' WHERE id=$1", [command.id]); return null; }
  await client.query("UPDATE host_commands SET state='DISPATCHED' WHERE id=$1", [command.id]);
  return { id: command.id, operation: command.operation, payload: command.payload, expiresAt: command.expires_at };
}

@Injectable()
export class HostManagementService {
  constructor(@Inject(Database) private readonly db: Database, @Inject(ControlService) private readonly control: ControlService) {}
  async read(actor: Actor, organizationId: string, serverId: string) {
    await this.control.membership(this.db, organizationId, actor);
    const server = (await this.db.query('SELECT management_snapshot,management_received_at FROM servers WHERE organization_id=$1 AND id=$2', [organizationId, input(uuid, serverId)])).rows[0];
    if (!server) throw new NotFoundException('Server not found');
    const commands = (await this.db.query("SELECT id,operation,payload,CASE WHEN state IN ('PENDING','DISPATCHED') AND expires_at<=now() THEN 'EXPIRED' ELSE state END AS state,message,created_at FROM host_commands WHERE organization_id=$1 AND server_id=$2 ORDER BY created_at DESC,id DESC LIMIT 100", [organizationId, serverId])).rows;
    return { snapshot: server.management_snapshot, receivedAt: server.management_received_at, stale: !server.management_received_at || Date.now() - new Date(server.management_received_at).getTime() > 120000, commands };
  }
  async command(actor: Actor, organizationId: string, serverId: string, body: unknown) {
    const data = input(commandSchema, body);
    return this.db.transaction(async client => {
      await this.control.membership(client, organizationId, actor, ['OWNER','ADMIN']);
      const server = (await client.query('SELECT * FROM servers WHERE organization_id=$1 AND id=$2 AND decommissioned_at IS NULL FOR UPDATE', [organizationId, input(uuid, serverId)])).rows[0];
      if (!server) throw new NotFoundException('Active server not found');
      const credential = (await client.query('SELECT id FROM agent_credentials WHERE organization_id=$1 AND server_id=$2 AND revoked_at IS NULL AND expires_at>now() ORDER BY created_at DESC LIMIT 1', [organizationId, serverId])).rows[0];
      if (!credential || !server.management_received_at || Date.now() - new Date(server.management_received_at).getTime() > 120000) throw new ConflictException('Management agent is unavailable or stale. Upgrade/configure the host agent first.');
      const snapshot = input(managementSchema, server.management_snapshot);
      let payload: object;
      if (data.operation === 'STOP_APPLICATION') {
        const application = snapshot.applications.find(item => item.id === data.applicationId && item.instance === data.instance && item.stoppable);
        if (!application) throw new ConflictException('Refresh application inventory; target is unavailable or stopping is not permitted on this host');
        payload = { application };
      } else {
        if (!snapshot.firewall) throw new ConflictException('Host firewall management is unavailable');
        if (data.operation === 'UNBLOCK_IP') {
          const existing = snapshot.rules.find(item => item.id === data.ruleId);
          if (!existing) throw new NotFoundException('Managed IP block not found');
          payload = existing;
        } else {
          if (snapshot.rules.length >= 200) throw new ConflictException('Managed rule limit reached');
          payload = { id: randomUUID(), ip: data.ip, scope: data.scope, ports: [...new Set(data.ports)].sort((a,b) => a-b) };
        }
      }
      await client.query("UPDATE host_commands SET state='EXPIRED' WHERE server_id=$1 AND state IN ('PENDING','DISPATCHED') AND (expires_at<=now() OR credential_id<>$2)", [serverId, credential.id]);
      if ((await client.query("SELECT id FROM host_commands WHERE server_id=$1 AND state IN ('PENDING','DISPATCHED')", [serverId])).rows.length) throw new ConflictException('Wait for the previous host action to complete');
      const id = randomUUID();
      await client.query('INSERT INTO host_commands (id,organization_id,server_id,credential_id,requested_by,operation,payload,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8)', [id, organizationId, serverId, credential.id, actor.id, data.operation, JSON.stringify(payload), new Date(Date.now()+120000)]);
      await this.control.audit(client, organizationId, actor.id, 'host.command_requested', serverId, { commandId: id, operation: data.operation, ...payload });
      return { id, state: 'PENDING' };
    });
  }
}
