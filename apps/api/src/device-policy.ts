import { z } from 'zod';
import { isDeepStrictEqual } from 'node:util';
import { randomUUID } from 'node:crypto';
import { Queryable } from './database';

export const devicePolicyResultSchema = z.object({ revision: z.number().int().min(1), status: z.enum(['APPLIED','PARTIAL','FAILED']), controls: z.array(z.object({ name: z.string().max(50), status: z.enum(['APPLIED','VERIFIED','NOT_MANAGED','UNSUPPORTED','FAILED','PENDING_RESTART']), message: z.string().max(500) }).strict()).max(20) }).strict();
export function policyStatus(row: Record<string, any>) {
  if (!row.device_policy_requested) return 'NOT_APPLIED';
  if (!row.device_policy_supported) return 'AGENT_UPGRADE_REQUIRED';
  if (row.device_policy_report?.revision !== row.device_revision) return 'PENDING';
  if (!row.last_heartbeat_at || Date.now()-new Date(row.last_heartbeat_at).getTime()>90000) return 'STALE';
  return row.device_policy_report.status;
}
export async function devicePolicyHeartbeat(client: Queryable, org: string, id: string, supported: boolean, result?: z.infer<typeof devicePolicyResultSchema> | null) {
  const row=(await client.query('SELECT device_config,device_revision,device_policy_requested,device_policy_actor,device_policy_report FROM servers WHERE organization_id=$1 AND id=$2 AND device_config IS NOT NULL',[org,id])).rows[0];
  if (!row) return null;
  await client.query('UPDATE servers SET device_policy_supported=$3 WHERE organization_id=$1 AND id=$2',[org,id,supported]);
  if (supported && result && row.device_policy_requested && result.revision===row.device_revision) {
    await client.query('UPDATE servers SET device_policy_report=$3::jsonb,device_policy_received_at=now() WHERE organization_id=$1 AND id=$2',[org,id,JSON.stringify(result)]);
    if(!isDeepStrictEqual(row.device_policy_report,result)) await client.query("INSERT INTO audit_logs(id,organization_id,actor_id,action,resource_id,request_id,metadata) VALUES($1,$2,NULL,'device.policy_result',$3,$4,$5::jsonb)",[randomUUID(),org,id,randomUUID(),JSON.stringify(result)]);
  }
  if (!supported || !row.device_policy_requested) return null;
  const authorized=await client.query("SELECT m.user_id FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND m.user_id=$2 AND m.role IN ('OWNER','ADMIN') AND u.disabled_at IS NULL",[org,row.device_policy_actor]);
  if(!authorized.rows.length)return null;
  return { revision:row.device_revision, config:row.device_config };
}
