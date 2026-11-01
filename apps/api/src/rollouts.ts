import { BadRequestException, ConflictException, ForbiddenException, Inject, Injectable, NotFoundException, OnModuleDestroy } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { Database, Queryable, Row } from './database';
import { Actor, ControlService } from './service';
import { input, uuid } from './input';

const hash = z.string().regex(/^[a-f0-9]{64}$/);
const reason = z.string().trim().min(3).max(1000);
const activeStates = ['QUEUED', 'CANARY', 'ROLLING_OUT', 'PAUSED', 'ROLLING_BACK'];

@Injectable()
export class RolloutService implements OnModuleDestroy {
  private timer?: ReturnType<typeof setInterval>;
  private task?: Promise<void>;
  private running = false;
  constructor(@Inject(Database) private readonly db: Database, @Inject(ControlService) private readonly control: ControlService) {}

  start() {
    if (this.timer) return;
    this.timer = setInterval(() => { if (!this.running) this.task = this.tick().catch(() => console.error('Rollout reconciliation failed; durable state retained')); }, 5000);
    this.timer.unref();
    this.task = this.tick().catch(() => console.error('Rollout recovery deferred'));
  }
  async onModuleDestroy() { if (this.timer) clearInterval(this.timer); await this.task; }
  async tick() {
    if (this.running) return;
    this.running = true;
    try {
      const deployments = (await this.db.query("SELECT id,organization_id FROM policy_deployments WHERE state IN ('PENDING_APPROVAL','QUEUED','CANARY','ROLLING_OUT','PAUSED','ROLLING_BACK') ORDER BY last_reconciled_at NULLS FIRST,created_at LIMIT 100")).rows;
      for (const deployment of deployments) {
        try { await this.reconcile(deployment.organization_id, deployment.id); } catch { console.error('Rollout reconciliation deferred:', deployment.id); }
      }
    } finally { this.running = false; }
  }
  private async access(client: Queryable, actor: Actor, organizationId: string, write = false) {
    if (write) await client.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [input(uuid, organizationId)]);
    await this.control.membership(client, organizationId, actor, write ? ['OWNER', 'ADMIN'] : undefined);
  }
  private async load(client: Queryable, organizationId: string, deploymentId: string, lock = false): Promise<Row> {
    const row = (await client.query(`SELECT * FROM policy_deployments WHERE organization_id=$1 AND id=$2${lock ? ' FOR UPDATE' : ''}`, [organizationId, input(uuid, deploymentId)])).rows[0];
    if (!row) throw new NotFoundException('Deployment not found');
    if (row.mode !== 'SIMULATION') throw new ConflictException('Live execution is not supported');
    return row;
  }
  private async authority(client: Queryable, organizationId: string, userId: string) {
    return (await client.query("SELECT memberships.user_id FROM memberships JOIN users ON users.id=memberships.user_id WHERE memberships.organization_id=$1 AND memberships.user_id=$2 AND memberships.role IN ('OWNER','ADMIN') AND users.disabled_at IS NULL AND users.mfa_enabled=true", [organizationId, userId])).rows.length > 0;
  }
  private async event(client: Queryable, deployment: Row, actor: string | null, action: string, metadata: Row = {}) {
    await this.control.audit(client, deployment.organization_id, actor, `rollout.${action}`, deployment.id, { mode: 'SIMULATION', versionId: deployment.policy_version_id, checksum: deployment.target_checksum, ...metadata });
  }
  async request(actor: Actor, organizationId: string, body: unknown) {
    const data = input(z.object({ mode: z.literal('SIMULATION'), versionId: uuid, expectedChecksum: hash, canaryServerIds: z.array(uuid).min(1).max(3).refine(ids => new Set(ids).size === ids.length), batchSize: z.number().int().min(1).max(10).default(2), canaryTimeoutSeconds: z.number().int().min(30).max(600).default(300), reason }).strict(), body);
    return this.db.transaction(async client => {
      await this.access(client, actor, organizationId, true);
      const version = (await client.query('SELECT * FROM policy_versions WHERE organization_id=$1 AND id=$2 FOR UPDATE', [organizationId, data.versionId])).rows[0];
      if (!version) throw new NotFoundException('Policy version not found');
      if (!version.sealed_at || !['PENDING_APPROVAL', 'APPROVED'].includes(version.state) || version.checksum !== data.expectedChecksum) throw new ConflictException('Select an unchanged sealed version');
      const serverIds: string[] = version.target.serverIds || [];
      if (!serverIds.length || serverIds.length > 100 || data.canaryServerIds.some(id => !serverIds.includes(id))) throw new BadRequestException('Canaries must belong to the frozen target snapshot');
      const servers = (await client.query('SELECT id FROM servers WHERE organization_id=$1 AND id=ANY($2::uuid[]) AND decommissioned_at IS NULL', [organizationId, serverIds])).rows;
      if (servers.length !== serverIds.length) throw new ConflictException('Snapshot includes unavailable targets; create a new policy draft');
      if ((await client.query("SELECT id FROM firewall_rules WHERE organization_id=$1 AND policy_version_id=$2 AND expires_at IS NOT NULL AND expires_at<=now()+interval '10 minutes' LIMIT 1", [organizationId, version.id])).rows.length) throw new BadRequestException('Rules need at least ten minutes remaining for this rollout prototype');
      const id = randomUUID();
      await client.query('INSERT INTO policy_deployments (id,organization_id,policy_version_id,target_checksum,requested_by,mode,batch_size,canary_timeout_seconds) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', [id, organizationId, version.id, version.checksum, actor.id, data.mode, data.batchSize, data.canaryTimeoutSeconds]);
      await client.query("INSERT INTO approval_requests (id,organization_id,deployment_id,requester_id,reason,expires_at) VALUES ($1,$2,$3,$4,$5,now()+interval '24 hours')", [randomUUID(), organizationId, id, actor.id, data.reason]);
      for (const serverId of serverIds) await client.query('INSERT INTO deployment_targets (id,organization_id,deployment_id,server_id,is_canary) VALUES ($1,$2,$3,$4,$5)', [randomUUID(), organizationId, id, serverId, data.canaryServerIds.includes(serverId)]);
      const deployment = await this.load(client, organizationId, id);
      await this.event(client, deployment, actor.id, 'requested', { canaryServerIds: data.canaryServerIds, targetCount: serverIds.length, reason: data.reason });
      return { deploymentId: id, mode: 'SIMULATION', state: 'PENDING_APPROVAL', liveExecutionEnabled: false };
    });
  }
  async list(actor: Actor, organizationId: string, query: unknown) {
    const filter = input(z.object({ cursor: uuid.optional(), limit: z.coerce.number().int().min(1).max(100).default(30) }).strict(), query);
    await this.access(this.db, actor, organizationId);
    let anchor: Row | undefined;
    if (filter.cursor) {
      anchor = (await this.db.query('SELECT id,created_at FROM policy_deployments WHERE organization_id=$1 AND id=$2', [organizationId, filter.cursor])).rows[0];
      if (!anchor) throw new BadRequestException('Invalid deployment cursor');
    }
    const rows = (await this.db.query(`SELECT deployments.*,policies.name AS policy_name,versions.version,approval.state AS approval_state,approval.requester_id,approval.approver_id,approval.expires_at AS approval_expires_at FROM policy_deployments deployments JOIN policy_versions versions ON versions.organization_id=deployments.organization_id AND versions.id=deployments.policy_version_id JOIN firewall_policies policies ON policies.organization_id=versions.organization_id AND policies.id=versions.policy_id JOIN approval_requests approval ON approval.organization_id=deployments.organization_id AND approval.deployment_id=deployments.id WHERE deployments.organization_id=$1 AND ($2::timestamptz IS NULL OR (deployments.created_at,deployments.id)<($2::timestamptz,$3::uuid)) ORDER BY deployments.created_at DESC,deployments.id DESC LIMIT $4`, [organizationId, anchor?.created_at || null, anchor?.id || null, filter.limit + 1])).rows;
    return { items: rows.slice(0, filter.limit), nextCursor: rows.length > filter.limit ? rows[filter.limit - 1].id : null, liveExecutionEnabled: false };
  }
  async detail(actor: Actor, organizationId: string, deploymentId: string) {
    await this.access(this.db, actor, organizationId);
    const deployment = await this.load(this.db, organizationId, deploymentId);
    const targets = (await this.db.query('SELECT targets.*,servers.hostname FROM deployment_targets targets JOIN servers ON servers.organization_id=targets.organization_id AND servers.id=targets.server_id WHERE targets.organization_id=$1 AND targets.deployment_id=$2 ORDER BY targets.is_canary DESC,targets.server_id', [organizationId, deploymentId])).rows;
    const approval = (await this.db.query('SELECT * FROM approval_requests WHERE organization_id=$1 AND deployment_id=$2', [organizationId, deploymentId])).rows[0];
    const jobs = (await this.db.query('SELECT jobs.* FROM agent_jobs jobs JOIN deployment_targets targets ON targets.organization_id=jobs.organization_id AND targets.id=jobs.target_id WHERE targets.organization_id=$1 AND targets.deployment_id=$2 ORDER BY jobs.created_at,jobs.id LIMIT 400', [organizationId, deploymentId])).rows;
    const history = (await this.db.query("SELECT audit.id,audit.action,audit.created_at,audit.metadata,users.name AS actor_name FROM audit_logs audit LEFT JOIN users ON users.id=audit.actor_id WHERE audit.organization_id=$1 AND audit.resource_id=$2 AND audit.action LIKE 'rollout.%' ORDER BY audit.created_at DESC,audit.id DESC LIMIT 100", [organizationId, deploymentId])).rows;
    return { deployment, approval, targets, jobs, history, liveExecutionEnabled: false, verificationScope: 'SIMULATION_ONLY_NOT_HOST_ATTESTATION' };
  }
  async decide(actor: Actor, organizationId: string, deploymentId: string, body: unknown) {
    const data = input(z.object({ decision: z.enum(['APPROVE', 'REJECT']), expectedChecksum: hash, reason }).strict(), body);
    return this.db.transaction(async client => {
      await this.access(client, actor, organizationId, true);
      const deployment = await this.load(client, organizationId, deploymentId, true);
      const approval = (await client.query('SELECT * FROM approval_requests WHERE organization_id=$1 AND deployment_id=$2 FOR UPDATE', [organizationId, deploymentId])).rows[0];
      const version = (await client.query('SELECT created_by,state,checksum FROM policy_versions WHERE organization_id=$1 AND id=$2 FOR UPDATE', [organizationId, deployment.policy_version_id])).rows[0];
      if (approval.requester_id === actor.id || version.created_by === actor.id) throw new ForbiddenException('A different administrator from both requester and policy author must decide');
      if (deployment.state !== 'PENDING_APPROVAL' || approval.state !== 'PENDING' || Date.parse(approval.expires_at) <= Date.now()) throw new ConflictException('Approval is no longer pending or has expired');
      if (data.expectedChecksum !== deployment.target_checksum || version.checksum !== data.expectedChecksum || !['PENDING_APPROVAL', 'APPROVED'].includes(version.state)) throw new ConflictException('Approval checksum/state mismatch');
      if (!await this.authority(client, organizationId, approval.requester_id) || !await this.authority(client, organizationId, version.created_by)) throw new ConflictException('Requester/author authority no longer valid');
      await client.query('UPDATE approval_requests SET state=$3,approver_id=$4,decided_at=now(),reason=$5 WHERE organization_id=$1 AND deployment_id=$2', [organizationId, deploymentId, data.decision === 'APPROVE' ? 'APPROVED' : 'REJECTED', actor.id, data.reason]);
      if (data.decision === 'APPROVE') {
        await client.query("UPDATE policy_versions SET state='APPROVED' WHERE organization_id=$1 AND id=$2", [organizationId, deployment.policy_version_id]);
        await client.query("UPDATE policy_deployments SET state='QUEUED' WHERE organization_id=$1 AND id=$2", [organizationId, deploymentId]);
      } else {
        await client.query("UPDATE policy_deployments SET state='CANCELLED',completed_at=now() WHERE organization_id=$1 AND id=$2", [organizationId, deploymentId]);
        await client.query("UPDATE deployment_targets SET state='CANCELLED' WHERE organization_id=$1 AND deployment_id=$2", [organizationId, deploymentId]);
      }
      await this.event(client, deployment, actor.id, data.decision === 'APPROVE' ? 'approved' : 'rejected', { reason: data.reason });
      return { state: data.decision === 'APPROVE' ? 'QUEUED' : 'CANCELLED', mode: 'SIMULATION', liveExecutionEnabled: false };
    });
  }
  async action(actor: Actor, organizationId: string, deploymentId: string, body: unknown) {
    const data = input(z.object({ action: z.enum(['PAUSE', 'RESUME', 'PROMOTE', 'ROLLBACK', 'CANCEL']), reason }).strict(), body);
    return this.db.transaction(async client => {
      await this.access(client, actor, organizationId, true);
      const deployment = await this.load(client, organizationId, deploymentId, true);
      const targets = (await client.query('SELECT * FROM deployment_targets WHERE organization_id=$1 AND deployment_id=$2 ORDER BY server_id FOR UPDATE', [organizationId, deploymentId])).rows;
      let next: string;
      if (data.action === 'PAUSE') {
        if (!['QUEUED', 'CANARY', 'ROLLING_OUT'].includes(deployment.state)) throw new ConflictException('Only active rollouts may be paused');
        next = 'PAUSED';
      } else if (data.action === 'RESUME' || data.action === 'PROMOTE') {
        const approval = (await client.query('SELECT * FROM approval_requests WHERE organization_id=$1 AND deployment_id=$2', [organizationId, deploymentId])).rows[0];
        if (approval.state !== 'APPROVED' || !await this.authority(client, organizationId, deployment.requested_by) || !await this.authority(client, organizationId, approval.approver_id)) throw new ConflictException('Current approval authority is required');
        if (targets.some(target => ['FAILED', 'UNKNOWN', 'ROLLING_BACK', 'ROLLED_BACK', 'ROLLBACK_FAILED'].includes(target.state))) throw new ConflictException('Failed/uncertain targets require rollback, not resume');
        if (data.action === 'RESUME') {
          if (deployment.state !== 'PAUSED') throw new ConflictException('Only paused rollouts may resume');
          next = 'CANARY';
        } else {
          if (deployment.state !== 'CANARY' || !targets.filter(target => target.is_canary).every(target => target.state === 'VERIFIED')) throw new ConflictException('Every canary must be verified before promotion');
          next = 'ROLLING_OUT';
        }
      } else if (data.action === 'CANCEL') {
        if (!['PENDING_APPROVAL', 'QUEUED', 'CANARY', 'PAUSED', 'ROLLING_OUT'].includes(deployment.state) || targets.some(target => target.rollback_state?.applied)) throw new ConflictException('Applied targets require rollback; cancellation cannot undo changes');
        next = 'CANCELLED';
        await client.query("UPDATE deployment_targets SET state='CANCELLED',watchdog_deadline_at=NULL WHERE organization_id=$1 AND deployment_id=$2", [organizationId, deploymentId]);
        await client.query("UPDATE agent_jobs SET state='EXPIRED',result=$3::jsonb WHERE organization_id=$1 AND target_id IN (SELECT id FROM deployment_targets WHERE organization_id=$1 AND deployment_id=$2) AND state IN ('PENDING','LEASED')", [organizationId, deploymentId, JSON.stringify({ mode: 'SIMULATION', error: 'CANCELLED_BEFORE_APPLY' })]);
        await client.query("UPDATE approval_requests SET state='EXPIRED' WHERE organization_id=$1 AND deployment_id=$2 AND state='PENDING'", [organizationId, deploymentId]);
      } else {
        if (!['CANARY', 'ROLLING_OUT', 'PAUSED', 'SUCCEEDED', 'FAILED'].includes(deployment.state)) throw new ConflictException('Deployment cannot enter rollback from this state');
        if ((await client.query("SELECT targets.id FROM deployment_targets targets JOIN policy_deployments deployments ON deployments.organization_id=targets.organization_id AND deployments.id=targets.deployment_id WHERE targets.organization_id=$1 AND targets.server_id=ANY($2::uuid[]) AND deployments.id<>$3 AND deployments.state IN ('CANARY','ROLLING_OUT','PAUSED','ROLLING_BACK') LIMIT 1", [organizationId, targets.map(target => target.server_id), deploymentId])).rows.length) throw new ConflictException('Another active rollout owns a target; resolve it before rollback');
        next = 'ROLLING_BACK';
        for (const target of targets) {
          if (target.state === 'ROLLBACK_FAILED') throw new ConflictException('Rollback failed; manual sandbox reconciliation is required');
          if (target.state === 'ROLLED_BACK' || target.state === 'CANCELLED') continue;
          if (target.rollback_state?.applied) {
            await client.query("UPDATE deployment_targets SET state='ROLLING_BACK' WHERE organization_id=$1 AND id=$2", [organizationId, target.id]);
            await this.job(client, deployment, target, 'ROLLBACK_POLICY', 300);
          } else await client.query("UPDATE deployment_targets SET state='CANCELLED',watchdog_deadline_at=NULL WHERE organization_id=$1 AND id=$2", [organizationId, target.id]);
        }
        await client.query("UPDATE agent_jobs SET state='EXPIRED' WHERE organization_id=$1 AND target_id IN (SELECT id FROM deployment_targets WHERE organization_id=$1 AND deployment_id=$2) AND operation IN ('APPLY_POLICY','INSPECT_POLICY') AND state IN ('PENDING','LEASED')", [organizationId, deploymentId]);
      }
      await client.query('UPDATE policy_deployments SET state=$3::"DeploymentState",stage_deadline_at=CASE WHEN $3::text IN (\'CANARY\',\'ROLLING_OUT\') THEN now()+canary_timeout_seconds*interval \'1 second\' ELSE stage_deadline_at END,completed_at=CASE WHEN $3::text=\'CANCELLED\' THEN now() ELSE NULL END WHERE organization_id=$1 AND id=$2', [organizationId, deploymentId, next]);
      await this.event(client, deployment, actor.id, data.action.toLowerCase(), { reason: data.reason, previousState: deployment.state, state: next });
      return { state: next, mode: 'SIMULATION', liveExecutionEnabled: false };
    });
  }
  async scenario(actor: Actor, organizationId: string, deploymentId: string, targetId: string, body: unknown) {
    const data = input(z.object({ online: z.boolean(), failureMode: z.enum(['NONE', 'APPLY', 'VERIFY', 'ROLLBACK']), reason }).strict(), body);
    return this.db.transaction(async client => {
      await this.access(client, actor, organizationId, true);
      const deployment = await this.load(client, organizationId, deploymentId, true);
      const result = await client.query('UPDATE deployment_targets SET simulation_online=$4,simulation_failure=$5 WHERE organization_id=$1 AND deployment_id=$2 AND id=$3 RETURNING id', [organizationId, deploymentId, input(uuid, targetId), data.online, data.failureMode]);
      if (!result.rows.length) throw new NotFoundException('Target not found');
      await this.event(client, deployment, actor.id, 'scenario_changed', { targetId, ...data });
      return { mode: 'SIMULATION', ...data };
    });
  }
  private async job(client: Queryable, deployment: Row, target: Row, operation: string, timeout: number) {
    const id = randomUUID();
    const payload = { schemaVersion: 1, mode: 'SIMULATION', organizationId: deployment.organization_id, serverId: target.server_id, deploymentId: deployment.id, versionId: deployment.policy_version_id, checksum: deployment.target_checksum };
    await client.query('INSERT INTO agent_jobs (id,organization_id,target_id,idempotency_key,operation,payload,expires_at) VALUES ($1,$2,$3,$4,$5,$6::jsonb,now()+$7*interval \'1 second\') ON CONFLICT(idempotency_key) DO NOTHING', [id, deployment.organization_id, target.id, `simulation:${target.id}:${operation}`, operation, JSON.stringify(payload), timeout]);
  }
  private async finishJob(client: Queryable, organizationId: string, targetId: string, operation: string, state: string, result: Row) {
    await client.query('UPDATE agent_jobs SET state=$4,result=$5::jsonb,attempts=attempts+1,lease_until=NULL WHERE organization_id=$1 AND target_id=$2 AND operation=$3 AND state IN (\'PENDING\',\'LEASED\')', [organizationId, targetId, operation, state, JSON.stringify({ mode: 'SIMULATION', ...result })]);
  }
  private async restore(client: Queryable, deployment: Row, target: Row, watchdog: boolean) {
    const current = (await client.query('SELECT simulation_firewall_state FROM servers WHERE organization_id=$1 AND id=$2 FOR UPDATE', [deployment.organization_id, target.server_id])).rows[0].simulation_firewall_state;
    const previous = target.rollback_state?.previous;
    const matches = current.hash === deployment.target_checksum || current.hash === previous?.hash;
    const success = !!previous && matches && target.simulation_failure !== 'ROLLBACK';
    if (success && current.hash !== previous.hash) await client.query('UPDATE servers SET simulation_firewall_state=$3::jsonb WHERE organization_id=$1 AND id=$2', [deployment.organization_id, target.server_id, JSON.stringify(previous)]);
    const state = success ? 'ROLLED_BACK' : 'ROLLBACK_FAILED';
    await client.query('UPDATE deployment_targets SET state=$3,error_code=$4,watchdog_deadline_at=NULL WHERE organization_id=$1 AND id=$2', [deployment.organization_id, target.id, state, success ? watchdog ? 'WATCHDOG_EXPIRED' : null : 'SIMULATED_ROLLBACK_FAILED_OR_SUPERSEDED']);
    await this.finishJob(client, deployment.organization_id, target.id, 'ROLLBACK_POLICY', success ? 'SUCCEEDED' : 'FAILED', { restored: success, watchdog });
    if (watchdog) await this.finishJob(client, deployment.organization_id, target.id, 'INSPECT_POLICY', 'EXPIRED', { error: 'WATCHDOG_EXPIRED' });
    await this.event(client, deployment, null, watchdog ? 'watchdog_expired' : success ? 'target_rolled_back' : 'rollback_failed', { targetId: target.id, state, restored: success });
    return success;
  }
  async reconcile(organizationId: string, deploymentId: string) {
    return this.db.transaction(async client => {
      await client.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [organizationId]);
      const deployment = await this.load(client, organizationId, deploymentId, true);
      if (!['PENDING_APPROVAL', ...activeStates].includes(deployment.state)) return;
      await client.query('UPDATE policy_deployments SET last_reconciled_at=now() WHERE organization_id=$1 AND id=$2', [organizationId, deploymentId]);
      const approval = (await client.query('SELECT * FROM approval_requests WHERE organization_id=$1 AND deployment_id=$2 FOR UPDATE', [organizationId, deploymentId])).rows[0];
      const version = (await client.query('SELECT * FROM policy_versions WHERE organization_id=$1 AND id=$2', [organizationId, deployment.policy_version_id])).rows[0];
      const targets = (await client.query('SELECT targets.*,servers.decommissioned_at FROM deployment_targets targets JOIN servers ON servers.organization_id=targets.organization_id AND servers.id=targets.server_id WHERE targets.organization_id=$1 AND deployment_id=$2 ORDER BY targets.server_id FOR UPDATE OF targets', [organizationId, deploymentId])).rows;
      const now = Date.now();
      if (deployment.state === 'PENDING_APPROVAL') {
        if (approval.state === 'PENDING' && (Date.parse(approval.expires_at) <= now || !await this.authority(client, organizationId, deployment.requested_by) || !await this.authority(client, organizationId, version.created_by))) {
          await client.query("UPDATE approval_requests SET state='EXPIRED' WHERE organization_id=$1 AND deployment_id=$2", [organizationId, deploymentId]);
          await client.query("UPDATE policy_deployments SET state='CANCELLED',completed_at=now() WHERE organization_id=$1 AND id=$2", [organizationId, deploymentId]);
          await client.query("UPDATE deployment_targets SET state='CANCELLED' WHERE organization_id=$1 AND deployment_id=$2", [organizationId, deploymentId]);
          await this.event(client, deployment, null, 'approval_expired');
        }
        return;
      }
      let watchdogFired = false;
      for (const target of targets) if (target.watchdog_deadline_at && !target.confirmed_at && Date.parse(target.watchdog_deadline_at) <= now && target.rollback_state?.applied && !['ROLLED_BACK', 'ROLLBACK_FAILED'].includes(target.state)) {
        await this.restore(client, deployment, target, true); watchdogFired = true;
      }
      if (watchdogFired) {
        if (deployment.state !== 'ROLLING_BACK') await client.query("UPDATE policy_deployments SET state='PAUSED' WHERE organization_id=$1 AND id=$2", [organizationId, deploymentId]);
        return;
      }
      if (deployment.state === 'ROLLING_BACK') {
        for (const target of targets.filter(target => target.state === 'ROLLING_BACK')) {
          const job = (await client.query("SELECT * FROM agent_jobs WHERE organization_id=$1 AND target_id=$2 AND operation='ROLLBACK_POLICY'", [organizationId, target.id])).rows[0];
          if (!job || Date.parse(job.expires_at) <= now) {
            await client.query("UPDATE deployment_targets SET state='ROLLBACK_FAILED',error_code='OFFLINE_ROLLBACK_TIMEOUT' WHERE organization_id=$1 AND id=$2", [organizationId, target.id]);
            await this.finishJob(client, organizationId, target.id, 'ROLLBACK_POLICY', 'EXPIRED', { error: 'OFFLINE_ROLLBACK_TIMEOUT' });
            await this.event(client, deployment, null, 'rollback_failed', { targetId: target.id, error: 'OFFLINE_ROLLBACK_TIMEOUT' });
          } else if (target.simulation_online) await this.restore(client, deployment, target, false);
        }
        const latest = (await client.query('SELECT state FROM deployment_targets WHERE organization_id=$1 AND deployment_id=$2', [organizationId, deploymentId])).rows;
        const failed = latest.some(target => target.state === 'ROLLBACK_FAILED');
        if (latest.every(target => ['ROLLED_BACK', 'CANCELLED', 'ROLLBACK_FAILED'].includes(target.state))) {
          const state = failed ? 'FAILED' : 'ROLLED_BACK';
          await client.query('UPDATE policy_deployments SET state=$3,completed_at=now() WHERE organization_id=$1 AND id=$2', [organizationId, deploymentId, state]);
          await this.event(client, deployment, null, state.toLowerCase());
        }
        return;
      }
      if (deployment.state === 'PAUSED') return;
      const validAuthority = approval.state === 'APPROVED' && version.state === 'APPROVED' && version.checksum === deployment.target_checksum && await this.authority(client, organizationId, deployment.requested_by) && await this.authority(client, organizationId, approval.approver_id) && await this.authority(client, organizationId, version.created_by);
      const expiredRules = (await client.query("SELECT id FROM firewall_rules WHERE organization_id=$1 AND policy_version_id=$2 AND expires_at IS NOT NULL AND expires_at<=now()+interval '2 minutes' LIMIT 1", [organizationId, deployment.policy_version_id])).rows.length;
      if (!validAuthority || expiredRules || targets.some(target => target.decommissioned_at)) {
        await client.query("UPDATE policy_deployments SET state='PAUSED' WHERE organization_id=$1 AND id=$2", [organizationId, deploymentId]);
        await this.event(client, deployment, null, 'safety_paused', { error: !validAuthority ? 'AUTHORITY_CHANGED' : expiredRules ? 'RULE_EXPIRATION' : 'TARGET_DECOMMISSIONED' });
        return;
      }
      if (deployment.state === 'QUEUED') {
        const busy = await client.query("SELECT targets.id FROM deployment_targets targets JOIN policy_deployments deployments ON deployments.organization_id=targets.organization_id AND deployments.id=targets.deployment_id WHERE targets.organization_id=$1 AND targets.server_id=ANY($2::uuid[]) AND deployments.id<>$3 AND (deployments.state IN ('CANARY','ROLLING_OUT','PAUSED','ROLLING_BACK') OR targets.state IN ('UNKNOWN','ROLLBACK_FAILED')) LIMIT 1", [organizationId, targets.map(target => target.server_id), deploymentId]);
        if (busy.rows.length) return;
        await client.query("UPDATE policy_deployments SET state='CANARY',stage_deadline_at=now()+canary_timeout_seconds*interval '1 second' WHERE organization_id=$1 AND id=$2", [organizationId, deploymentId]);
        deployment.state = 'CANARY'; deployment.stage_deadline_at = new Date(now + deployment.canary_timeout_seconds * 1000);
        await this.event(client, deployment, null, 'canary_started');
      }
      const awaitingPromotion = deployment.state === 'CANARY' && targets.filter(target => target.is_canary).every(target => target.state === 'VERIFIED');
      if (deployment.stage_deadline_at && Date.parse(deployment.stage_deadline_at) <= now && !awaitingPromotion) {
        await client.query("UPDATE policy_deployments SET state='PAUSED' WHERE organization_id=$1 AND id=$2", [organizationId, deploymentId]);
        await this.event(client, deployment, null, 'offline_timeout'); return;
      }
      let failed = false;
      for (const target of targets) {
        if (target.state === 'DISPATCHED') {
          if (Date.parse(target.dispatch_deadline_at) <= now) {
            await client.query("UPDATE deployment_targets SET state='UNKNOWN',error_code='OFFLINE_DISPATCH_TIMEOUT' WHERE organization_id=$1 AND id=$2", [organizationId, target.id]);
            await this.finishJob(client, organizationId, target.id, 'APPLY_POLICY', 'EXPIRED', { error: 'OFFLINE_DISPATCH_TIMEOUT' }); failed = true;
          } else if (target.simulation_online) {
            if (target.simulation_failure === 'APPLY') {
              await client.query("UPDATE deployment_targets SET state='FAILED',error_code='SIMULATED_APPLY_FAILURE' WHERE organization_id=$1 AND id=$2", [organizationId, target.id]);
              await this.finishJob(client, organizationId, target.id, 'APPLY_POLICY', 'FAILED', { error: 'SIMULATED_APPLY_FAILURE' }); failed = true;
            } else {
              await client.query('UPDATE servers SET simulation_firewall_state=$3::jsonb WHERE organization_id=$1 AND id=$2', [organizationId, target.server_id, JSON.stringify({ hash: deployment.target_checksum, versionId: deployment.policy_version_id, deploymentId })]);
              await client.query("UPDATE deployment_targets SET state='APPLIED',rollback_state=jsonb_set(rollback_state,'{applied}','true') WHERE organization_id=$1 AND id=$2", [organizationId, target.id]);
              await this.finishJob(client, organizationId, target.id, 'APPLY_POLICY', 'SUCCEEDED', { appliedChecksum: deployment.target_checksum });
              await this.job(client, deployment, target, 'INSPECT_POLICY', 120);
              await this.event(client, deployment, null, 'target_applied', { targetId: target.id });
            }
          }
        } else if (target.state === 'APPLIED' && target.simulation_online) {
          const current = (await client.query('SELECT simulation_firewall_state FROM servers WHERE organization_id=$1 AND id=$2', [organizationId, target.server_id])).rows[0].simulation_firewall_state;
          const verified = current.hash === deployment.target_checksum && target.simulation_failure !== 'VERIFY';
          const evidence = { mode: 'SIMULATION', nativeStateMatch: current.hash === deployment.target_checksum, managementReachable: target.simulation_failure !== 'VERIFY', controlPlaneReachable: true, observedChecksum: current.hash, receivedAt: new Date(now).toISOString(), hostAttestation: false };
          await client.query('UPDATE deployment_targets SET state=$3,observed_hash=$4,verification_evidence=$5::jsonb,verified_at=CASE WHEN $6 THEN now() ELSE NULL END,confirmed_at=CASE WHEN $6 THEN now() ELSE NULL END,watchdog_deadline_at=CASE WHEN $6 THEN NULL ELSE watchdog_deadline_at END,error_code=$7 WHERE organization_id=$1 AND id=$2', [organizationId, target.id, verified ? 'VERIFIED' : 'FAILED', current.hash, JSON.stringify(evidence), verified, verified ? null : 'SIMULATED_VERIFICATION_FAILED']);
          await this.finishJob(client, organizationId, target.id, 'INSPECT_POLICY', verified ? 'SUCCEEDED' : 'FAILED', evidence);
          await this.event(client, deployment, null, verified ? 'target_verified' : 'verification_failed', { targetId: target.id, evidence });
          if (!verified) failed = true;
        }
      }
      const latest = (await client.query('SELECT * FROM deployment_targets WHERE organization_id=$1 AND deployment_id=$2 ORDER BY server_id', [organizationId, deploymentId])).rows;
      if (failed || latest.some(target => ['FAILED', 'UNKNOWN', 'ROLLBACK_FAILED'].includes(target.state))) {
        await client.query("UPDATE policy_deployments SET state='PAUSED' WHERE organization_id=$1 AND id=$2", [organizationId, deploymentId]);
        await this.event(client, deployment, null, 'verification_paused'); return;
      }
      if (deployment.state === 'ROLLING_OUT' && latest.every(target => target.state === 'VERIFIED')) {
        await client.query("UPDATE policy_deployments SET state='SUCCEEDED',completed_at=now() WHERE organization_id=$1 AND id=$2", [organizationId, deploymentId]);
        await this.event(client, deployment, null, 'succeeded'); return;
      }
      if (deployment.state === 'CANARY' && latest.filter(target => target.is_canary).every(target => target.state === 'VERIFIED')) return;
      const inFlight = latest.filter(target => ['DISPATCHED', 'APPLIED'].includes(target.state)).length;
      const pending = latest.filter(target => target.state === 'PENDING' && target.simulation_online && (deployment.state === 'ROLLING_OUT' || target.is_canary)).slice(0, Math.max(0, deployment.batch_size - inFlight));
      for (const target of pending) {
        const previous = (await client.query('SELECT simulation_firewall_state FROM servers WHERE organization_id=$1 AND id=$2 FOR UPDATE', [organizationId, target.server_id])).rows[0].simulation_firewall_state;
        await client.query("UPDATE deployment_targets SET state='DISPATCHED',dispatch_deadline_at=now()+interval '60 seconds',watchdog_deadline_at=now()+interval '120 seconds',rollback_state=$3::jsonb WHERE organization_id=$1 AND id=$2", [organizationId, target.id, JSON.stringify({ mode: 'SIMULATION', applied: false, previous, preparedAt: new Date(now).toISOString() })]);
        await this.job(client, deployment, target, 'APPLY_POLICY', 60);
        await this.event(client, deployment, null, 'target_dispatched', { targetId: target.id, isCanary: target.is_canary });
      }
    });
  }
}
