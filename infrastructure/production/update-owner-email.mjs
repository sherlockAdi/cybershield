import fs from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire('/app/apps/api/package.json');
require('reflect-metadata');
const { Database } = require('/app/apps/api/dist/database.js');
const { ControlService } = require('/app/apps/api/dist/service.js');
const { email: emailSchema, input } = require('/app/apps/api/dist/input.js');
const email = input(emailSchema, process.env.OWNER_EMAIL);
const filename = '/provisioning/admin-access.json';
const access = JSON.parse(fs.readFileSync(filename, 'utf8'));
const db = await new Database().open();
try {
  await db.transaction(async client => {
    await client.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [access.organizationId]);
    const rows = (await client.query("SELECT users.id,users.email FROM users JOIN memberships ON memberships.user_id=users.id WHERE memberships.organization_id=$1 AND memberships.role='OWNER' AND users.email IN ($2,$3) FOR UPDATE OF users", [access.organizationId, access.email, email])).rows;
    if (rows.length !== 1) throw new Error('Expected exactly one matching owner');
    const owner = rows[0];
    const conflict = (await client.query('SELECT id FROM users WHERE email=$1 AND id<>$2', [email, owner.id])).rows;
    if (conflict.length) throw new Error('Email already belongs to another account');
    if (owner.email !== email) {
      await client.query('UPDATE users SET email=$2 WHERE id=$1', [owner.id, email]);
      await client.query('UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL', [owner.id]);
      await new ControlService(db).audit(client, access.organizationId, owner.id, 'account.owner_email_updated', owner.id, { previousEmail: owner.email, email, source: 'authorized-server-provisioning' });
    }
  });
  const temporary = filename + '.new';
  const descriptor = fs.openSync(temporary, 'wx', 0o600);
  try { fs.writeFileSync(descriptor, JSON.stringify({ ...access, email }, null, 2)); fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
  fs.renameSync(temporary, filename);
  process.stdout.write(JSON.stringify({ email, passwordUnchanged: true, organizationUnchanged: true, previousSessionsRevoked: true }) + '\n');
} finally { await db.close(); }
