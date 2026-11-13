import { Inject, Injectable, NotFoundException } from '@nestjs/common';
import { z } from 'zod';
import { Database } from './database';
import { input, uuid } from './input';
import { Actor, ControlService } from './service';

@Injectable()
export class EmployeeService {
  constructor(@Inject(Database) private readonly db: Database, @Inject(ControlService) private readonly control: ControlService) {}

  async list(actor: Actor, org: string) {
    await this.control.membership(this.db, org, actor, ['OWNER', 'ADMIN']);
    return (await this.db.query(`SELECT e.id,e.name,e.email,e.aadhaar_reviewed_at,e.pan_reviewed_at,
      CASE WHEN m.user_id IS NOT NULL AND u.disabled_at IS NOT NULL THEN 'Disabled' WHEN m.user_id IS NOT NULL THEN 'Active member'
      WHEN EXISTS (SELECT 1 FROM invitations i WHERE i.organization_id=e.organization_id AND i.email=e.email
        AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at>now()) THEN 'Invitation pending'
      ELSE 'No workspace access' END AS login_status,
      (SELECT max(a.created_at) FROM audit_logs a WHERE a.organization_id=e.organization_id
        AND a.actor_id=m.user_id AND a.action='auth.login') AS last_sign_in
      FROM employees e LEFT JOIN users u ON u.email=e.email
      LEFT JOIN memberships m ON m.user_id=u.id AND m.organization_id=e.organization_id
      WHERE e.organization_id=$1 ORDER BY e.name,e.id`, [org])).rows;
  }

  async register(actor: Actor, org: string, body: unknown) {
    const data = input(z.object({ name: z.string().trim().min(1).max(120), email: z.string().trim().email().max(254).toLowerCase() }).strict(), body);
    return this.db.transaction(async client => {
      await this.control.membership(client, org, actor, ['OWNER', 'ADMIN']);
      const employee = (await client.query('INSERT INTO employees (organization_id,name,email) VALUES ($1,$2,$3) ON CONFLICT (organization_id,email) DO NOTHING RETURNING id', [org,data.name,data.email])).rows[0];
      if (employee) await this.control.audit(client, org, actor.id, 'employee.registered', employee.id);
      return { created: Boolean(employee) };
    });
  }

  async review(actor: Actor, org: string, id: string, body: unknown) {
    const { document } = input(z.object({ document: z.enum(['aadhaar', 'pan']) }).strict(), body);
    return this.db.transaction(async client => {
      await this.control.membership(client, org, actor, ['OWNER', 'ADMIN']);
      const column = document === 'aadhaar' ? 'aadhaar_reviewed_at' : 'pan_reviewed_at';
      const result = await client.query(`UPDATE employees SET ${column}=now() WHERE organization_id=$1 AND id=$2 RETURNING id`, [org,input(uuid,id)]);
      if (!result.rows.length) throw new NotFoundException('Employee not found');
      await this.control.audit(client, org, actor.id, 'employee.external_review_recorded', id, { document });
      return { ok: true };
    });
  }
}
