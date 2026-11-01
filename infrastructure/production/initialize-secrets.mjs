import fs from 'node:fs';
import { randomBytes } from 'node:crypto';
const destination = process.argv[2];
if (!destination) throw new Error('Provide a new private environment file path');
const content = ['DB_BOOTSTRAP_PASSWORD=' + randomBytes(32).toString('hex'), 'DB_MIGRATOR_PASSWORD=' + randomBytes(32).toString('hex'), 'DB_RUNTIME_PASSWORD=' + randomBytes(32).toString('hex'), 'MFA_ENCRYPTION_KEY=' + randomBytes(32).toString('base64')].join('\n') + '\n';
fs.writeFileSync(destination, content, { flag: 'wx', mode: 0o600 });
process.stdout.write('Private deployment environment created; values are not displayed.\n');
