import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
export function checkEnvironment(environment) {
  const errors = [];
  if (environment.NODE_ENV !== 'production') errors.push('NODE_ENV must be production');
  try { const origin = new URL(environment.APP_ORIGIN); if (origin.protocol !== 'https:' || origin.origin !== environment.APP_ORIGIN || origin.username || origin.password || /example\.(com|test)$/.test(origin.hostname)) throw new Error(); } catch { errors.push('APP_ORIGIN must be an actual HTTPS origin without path/credentials'); }
  try { const database = new URL(environment.DATABASE_URL); if (!['postgres:', 'postgresql:'].includes(database.protocol) || !database.hostname || !database.pathname.slice(1) || !database.username || !database.password || /replace|password|validation/i.test(decodeURIComponent(database.password))) throw new Error(); } catch { errors.push('DATABASE_URL must reference the intended external PostgreSQL with non-placeholder credentials'); }
  const encoded = environment.MFA_ENCRYPTION_KEY || ''; const key = Buffer.from(encoded, 'base64');
  if (!/^[A-Za-z0-9+/]{43}=$/.test(encoded) || key.length !== 32 || key.every(value => value === key[0])) errors.push('MFA_ENCRYPTION_KEY must be a non-placeholder 32-byte base64 key');
  key.fill(0);
  if (environment.ALLOW_REGISTRATION === 'true') errors.push('Disable public registration before pilot handover');
  return { valid: !errors.length, errors, checked: ['environment-shape', 'production-mode', 'explicit-mfa-key', 'closed-registration'], notChecked: ['database-connectivity', 'database-privileges', 'tls-certificate', 'network-allowlist', 'backups', 'capacity', 'native-execution'], liveFirewallExecutionEnabled: false };
}
async function main() {
  const result = checkEnvironment(process.env);
  const missing = [];
  for (const file of ['apps/api/dist/main.js', 'apps/dashboard/.next/BUILD_ID']) { try { await fs.access(path.join(root, file)); } catch { missing.push(file); } }
  if (missing.length) { result.valid = false; result.errors.push('Build artifacts are missing; run the production build first'); }
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`); if (!result.valid) process.exitCode = 1;
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) main().catch(() => { process.stderr.write('Deployment preflight failed; no credentials are printed.\n'); process.exitCode = 1; });
