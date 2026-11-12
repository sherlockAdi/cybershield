import { ConflictException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { z } from 'zod';
import { policyStatus } from './device-policy';
import { Database } from './database';
import { Actor, ControlService } from './service';
import { input, uuid } from './input';
import { agentStatus } from './agents';

export const deviceConfigSchema = z.object({
  employeeId: uuid.nullable(), notes: z.string().trim().max(1000),
  storage: z.enum(['AUDIT', 'BLOCK', 'READ_ONLY', 'ALLOWLIST']),
  approvedStorageIds: z.array(z.string().trim().min(1).max(300)).max(50),
  bluetooth: z.enum(['AUDIT', 'BLOCK']), mtp: z.enum(['AUDIT', 'BLOCK']),
  printers: z.enum(['AUDIT', 'BLOCK']), usbNetwork: z.enum(['AUDIT', 'BLOCK']),
  screenLockMinutes: z.number().int().min(1).max(60),
  requireFirewall: z.boolean(), requireAntivirus: z.boolean(), requireEncryption: z.boolean(),
}).strict().refine(value => value.storage !== 'ALLOWLIST' || value.approvedStorageIds.length > 0, 'Allowlist needs at least one device instance ID');

@Injectable()
export class DeviceService {
  constructor(@Inject(Database) private readonly db: Database, @Inject(ControlService) private readonly control: ControlService) {}
  async list(actor: Actor, org: string, query: unknown) {
    const { page } = input(z.object({ page: z.coerce.number().int().min(1).max(10000).default(1) }).strict(), query);
    await this.control.membership(this.db, org, actor);
    const { rows } = await this.db.query(`SELECT s.id,s.hostname,s.os_version,s.agent_version,s.last_heartbeat_at,s.decommissioned_at,
      s.device_config,s.device_revision,s.device_received_at,s.device_policy_requested,s.device_policy_report,s.device_policy_received_at,s.device_policy_supported,c.id AS credential_id,c.expires_at AS credential_expires_at,
      EXISTS(SELECT 1 FROM agent_credentials h WHERE h.server_id=s.id) AS had_credentials
      FROM servers s LEFT JOIN LATERAL (SELECT id,expires_at FROM agent_credentials WHERE server_id=s.id AND organization_id=s.organization_id AND revoked_at IS NULL AND expires_at>now() ORDER BY created_at DESC LIMIT 1) c ON true
      WHERE s.organization_id=$1 AND s.device_config IS NOT NULL ORDER BY s.created_at DESC,s.id LIMIT 11 OFFSET $2`, [org, (page - 1) * 10]);
    return { items: rows.slice(0, 10).map(row => ({ ...row, status: agentStatus(row), enforcement: policyStatus(row) })), hasNext: rows.length > 10 };
  }
  async read(actor: Actor, org: string, id: string) {
    await this.control.membership(this.db, org, actor);
    const { rows } = await this.db.query('SELECT id,hostname,agent_version,last_heartbeat_at,device_config,device_revision,device_snapshot,device_received_at,device_policy_requested,device_policy_report,device_policy_received_at,device_policy_supported FROM servers WHERE organization_id=$1 AND id=$2 AND device_config IS NOT NULL', [org, input(uuid,id)]);
    if (!rows.length) throw new NotFoundException('Device not found');
    return { ...rows[0], enforcement: policyStatus(rows[0]) };
  }
  async save(actor: Actor, org: string, id: string, body: unknown) {
    const data = input(z.object({ revision: z.number().int().min(0), config: deviceConfigSchema, apply: z.boolean().default(false) }).strict(), body);
    input(uuid,id);
    return this.db.transaction(async client => {
      await client.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [input(uuid,org)]);
      await this.control.membership(client,org,actor,['OWNER','ADMIN']);
      const { rows } = await client.query('SELECT device_revision FROM servers WHERE organization_id=$1 AND id=$2 AND device_config IS NOT NULL AND decommissioned_at IS NULL FOR UPDATE', [org,id]);
      if (!rows.length) throw new NotFoundException('Active device not found');
      if (rows[0].device_revision !== data.revision) throw new ConflictException('Configuration changed; reload before saving');
      if (data.config.employeeId) {
        const member = await client.query('SELECT m.user_id FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND m.user_id=$2 AND u.disabled_at IS NULL', [org,data.config.employeeId]);
        if (!member.rows.length) throw new NotFoundException('Employee must be an active member of this organization');
      }
      await client.query('UPDATE servers SET device_config=$3::jsonb,device_revision=device_revision+1,device_policy_requested=$4,device_policy_actor=$5 WHERE organization_id=$1 AND id=$2', [org,id,JSON.stringify(data.config),data.apply,actor.id]);
      await this.control.audit(client,org,actor.id,'device.configuration_saved',id,{ revision: data.revision+1, enforcement: data.apply ? 'PENDING' : 'NOT_APPLIED', config: data.config });
      return { revision: data.revision+1, enforcement: data.apply ? 'PENDING' : 'NOT_APPLIED' };
    });
  }
}
