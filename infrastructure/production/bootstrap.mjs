import fs from 'node:fs';
import { randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
const require = createRequire('/app/apps/api/package.json');
require('reflect-metadata');
const { Database } = require('/app/apps/api/dist/database.js');
const { ControlService } = require('/app/apps/api/dist/service.js');
const { AgentService } = require('/app/apps/api/dist/agents.js');
const db = await new Database().open();
try {
  if ((await db.query('SELECT id FROM users LIMIT 1')).rows.length) throw new Error('Bootstrap refuses an existing user database');
  const email = process.env.BOOTSTRAP_EMAIL || 'admin@cybershield360.vvvitsolutions.online';
  const password = randomBytes(24).toString('base64url');
  process.env.ALLOW_REGISTRATION = 'true';
  const control = new ControlService(db);
  await control.register({ email, password, name: 'CyberShield360 Administrator', organization: 'CyberShield360' }, { cookie() {} });
  const user = (await db.query('SELECT id FROM users WHERE email=$1', [email])).rows[0];
  const organization = (await db.query('SELECT organization_id FROM memberships WHERE user_id=$1', [user.id])).rows[0].organization_id;
  await db.query('UPDATE sessions SET revoked_at=now() WHERE user_id=$1', [user.id]);
  const server = await new AgentService(db, control).createServer({ id: user.id }, organization, { hostname: 'srv1955495', os: 'LINUX' });
  fs.writeFileSync('/provisioning/admin-access.json', JSON.stringify({ email, password, url: 'https://cybershield360.vvvitsolutions.online', mfaSetupRequired: true, organizationId: organization }, null, 2), { flag: 'wx', mode: 0o600 });
  fs.writeFileSync('/provisioning/server-enrollment.token', server.enrollmentToken, { flag: 'wx', mode: 0o600 });
  fs.writeFileSync('/provisioning/agent.env', `SERVER_ID=${server.serverId}\nAGENT_API=https://agent1.cybershield360.vvvitsolutions.online\n`, { flag: 'wx', mode: 0o600 });
  process.stdout.write(JSON.stringify({ email, organizationId: organization, serverId: server.serverId, mfaSetupRequired: true, credentialsStoredPrivately: true }) + '\n');
} finally { await db.close(); }
