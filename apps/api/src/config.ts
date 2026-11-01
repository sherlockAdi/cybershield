import path from 'node:path';
import fs from 'node:fs';
import { randomBytes } from 'node:crypto';
import dotenv from 'dotenv';

export const root = path.resolve(__dirname, '../../..');
dotenv.config({ path: path.join(root, '.env'), quiet: true });
export const production = process.env.NODE_ENV === 'production';
export const origin = process.env.APP_ORIGIN || 'http://127.0.0.1:3100';
if (new URL(origin).origin !== origin) throw new Error('APP_ORIGIN must be an origin without a path');
if (production && (!origin.startsWith('https://') || !process.env.DATABASE_URL || !process.env.MFA_ENCRYPTION_KEY)) {
  throw new Error('Production requires HTTPS APP_ORIGIN, DATABASE_URL and MFA_ENCRYPTION_KEY');
}

function encryptionKey() {
  if (process.env.MFA_ENCRYPTION_KEY) {
    const key = Buffer.from(process.env.MFA_ENCRYPTION_KEY, 'base64');
    if (key.length !== 32) throw new Error('MFA_ENCRYPTION_KEY must encode exactly 32 bytes');
    return key;
  }
  const directory = path.join(root, '.runtime');
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const filename = path.join(directory, 'local-mfa-key');
  if (!fs.existsSync(filename)) {
    try { fs.writeFileSync(filename, randomBytes(32), { flag: 'wx', mode: 0o600 }); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
  }
  const key = fs.readFileSync(filename);
  if (key.length !== 32) throw new Error('Invalid local MFA key');
  return key;
}
export const mfaKey = encryptionKey();
