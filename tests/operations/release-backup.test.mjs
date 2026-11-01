import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { randomBytes, randomUUID, createCipheriv, createDecipheriv } from 'node:crypto';
import { createBackup, restoreBackup, generateKey, privatePermissions } from '../../scripts/backup.mjs';
import { packageRelease, verifyRelease } from '../../scripts/package-release.mjs';
import { checkEnvironment } from '../../scripts/deployment-check.mjs';

const root = fileURLToPath(new URL('../..', import.meta.url));
const runtime = path.join(root, '.runtime');
await fs.mkdir(runtime, { recursive: true });
async function scratch() { const directory = await fs.mkdtemp(path.join(runtime, 'operations-')); await privatePermissions(directory, true); return directory; }

test('encrypted backup authenticates data, preserves empty directories, rejects wrong keys and never overwrites', async () => {
  const directory = await scratch(); const source = path.join(directory, 'source'); await fs.mkdir(path.join(source, 'empty'), { recursive: true });
  await fs.writeFile(path.join(source, 'record.json'), '{"synthetic":true}');
  const key = path.join(directory, 'backup.key'); const wrong = path.join(directory, 'wrong.key'); await generateKey(key); await generateKey(wrong);
  const output = path.join(directory, 'data.sgbak');
  await assert.rejects(createBackup({ source, output, keyFile: key }), /Confirm/);
  await createBackup({ source, output, keyFile: key, confirmed: true });
  assert.equal((await fs.readFile(output)).includes(Buffer.from('synthetic')), false);
  await assert.rejects(restoreBackup({ input: output, destination: path.join(directory, 'wrong'), keyFile: wrong }));
  await assert.rejects(fs.access(path.join(directory, 'wrong')));
  const corrupt = await fs.readFile(output); corrupt[corrupt.length - 1] ^= 1; await fs.writeFile(path.join(directory, 'corrupt.sgbak'), corrupt);
  await assert.rejects(restoreBackup({ input: path.join(directory, 'corrupt.sgbak'), destination: path.join(directory, 'corrupt'), keyFile: key }));
  await assert.rejects(fs.access(path.join(directory, 'corrupt')));
  const destination = path.join(directory, 'restored'); const receipt = await restoreBackup({ input: output, destination, keyFile: key });
  assert.equal(receipt.databaseStarted, false); assert.equal(await fs.readFile(path.join(destination, 'record.json'), 'utf8'), '{"synthetic":true}'); assert.ok((await fs.stat(path.join(destination, 'empty'))).isDirectory());
  await assert.rejects(restoreBackup({ input: output, destination, keyFile: key }), /must not exist/);
  await assert.rejects(generateKey(key));
});

test('closed PGlite database and matching MFA key survive encrypted isolated restore', async () => {
  const require = createRequire(path.join(root, 'apps/api/package.json'));
  const { PGlite } = await import(pathToFileURL(require.resolve('@electric-sql/pglite')).href);
  const directory = await scratch(); const source = path.join(directory, 'staged'); await fs.mkdir(source);
  const db = new PGlite(path.join(source, 'postgres')); await db.waitReady;
  const mfa = randomBytes(32); const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', mfa, iv); const encrypted = Buffer.concat([cipher.update('synthetic-totp-secret'), cipher.final()]);
  await db.exec('CREATE TABLE recovery_probe (id text PRIMARY KEY,encrypted text)'); await db.query('INSERT INTO recovery_probe VALUES ($1,$2)', ['pilot-fixture', JSON.stringify({ iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), content: encrypted.toString('base64') })]);
  await db.close(); await fs.writeFile(path.join(source, 'mfa.key'), mfa, { mode: 0o600 });
  const key = path.join(directory, 'backup.key'); await generateKey(key);
  const output = path.join(directory, 'database.sgbak'); await createBackup({ source, output, keyFile: key, confirmed: true });
  const destination = path.join(directory, 'restored'); await restoreBackup({ input: output, destination, keyFile: key });
  const restored = new PGlite(path.join(destination, 'postgres')); await restored.waitReady;
  try {
    const row = (await restored.query('SELECT encrypted FROM recovery_probe WHERE id=$1', ['pilot-fixture'])).rows[0];
    const envelope = JSON.parse(row.encrypted);
    const decipher = createDecipheriv('aes-256-gcm', await fs.readFile(path.join(destination, 'mfa.key')), Buffer.from(envelope.iv, 'base64')); decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    assert.equal(Buffer.concat([decipher.update(Buffer.from(envelope.content, 'base64')), decipher.final()]).toString(), 'synthetic-totp-secret');
  } finally { await restored.close(); mfa.fill(0); }
});

test('pilot package is allowlisted, checksum-verifiable, unsigned and fails on tampering or extra files', async () => {
  const directory = await scratch(); const output = path.join(directory, 'bundle');
  const result = await packageRelease({ output, version: '0.1.0-pilot.test', includeAgents: false }); assert.equal(result.signed, false);
  const manifest = JSON.parse(await fs.readFile(path.join(output, 'manifest.json'), 'utf8'));
  assert.ok(manifest.files.length > 40);
  assert.ok(manifest.files.every(file => !file.path.split('/').some(part => ['node_modules', '.runtime', '.git', '.env'].includes(part))));
  assert.equal((await verifyRelease(output)).authenticityVerified, false);
  const target = path.join(output, 'source/README.md'); const original = await fs.readFile(target); await fs.appendFile(target, '\nmodified'); await assert.rejects(verifyRelease(output), /checksum/); await fs.writeFile(target, original);
  await fs.writeFile(path.join(output, 'unexpected.txt'), 'not in manifest'); await assert.rejects(verifyRelease(output), /Unexpected/);
  await assert.rejects(packageRelease({ output: path.join(root, 'scripts', randomUUID()), version: '0.1.0-pilot.test', includeAgents: false }), /source folder/);
});

test('deployment preflight rejects insecure/default configuration without disclosing values', () => {
  assert.equal(checkEnvironment({}).valid, false);
  const valid = { NODE_ENV: 'production', APP_ORIGIN: 'https://pilot.internal.invalid', DATABASE_URL: 'postgresql://pilot:synthetic-secure-credential@db.internal/pilot', MFA_ENCRYPTION_KEY: randomBytes(32).toString('base64'), ALLOW_REGISTRATION: 'false' };
  assert.equal(checkEnvironment(valid).valid, true);
  assert.equal(checkEnvironment({ ...valid, ALLOW_REGISTRATION: 'true' }).valid, false);
  assert.equal(checkEnvironment({ ...valid, MFA_ENCRYPTION_KEY: Buffer.alloc(32).toString('base64') }).valid, false);
  assert.equal(checkEnvironment({ ...valid, APP_ORIGIN: 'http://pilot.internal.invalid' }).valid, false);
  assert.equal(JSON.stringify(checkEnvironment({ ...valid, NODE_ENV: 'development' })).includes(valid.DATABASE_URL), false);
});
