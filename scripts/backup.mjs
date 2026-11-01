import fs from 'node:fs/promises';
import path from 'node:path';
import { constants } from 'node:fs';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { gzipSync, gunzipSync } from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const maxBytes = 64 * 1024 * 1024;
const magic = Buffer.from('SGBAK001');
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const portable = name => name && name !== '.' && name !== '..' && !/[<>:"\\|?*\x00-\x1f]/.test(name) && !/[. ]$/.test(name) && !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name);

export async function privatePermissions(filename, directory = false) {
  if (process.platform !== 'win32') { await fs.chmod(filename, directory ? 0o700 : 0o600); return; }
  execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', "$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; $rights=if($env:SG_PRIVATE_DIRECTORY -eq '1'){'(OI)(CI)(F)'}else{'(F)'}; & icacls.exe $env:SG_PRIVATE_PATH /inheritance:r /grant:r ('*'+$sid+':'+$rights) | Out-Null; if($LASTEXITCODE -ne 0){throw 'Private ACL setup failed'}"], { env: { ...process.env, SG_PRIVATE_PATH: filename, SG_PRIVATE_DIRECTORY: directory ? '1' : '0' }, windowsHide: true, stdio: 'pipe' });
}
async function assertPrivateKey(filename) {
  const info = await fs.lstat(filename);
  if (!info.isFile() || info.isSymbolicLink() || info.size !== 32) throw new Error('Expected a private 32-byte backup key file');
  if (process.platform !== 'win32' && info.mode & 0o077) throw new Error('Backup key permissions must be 0600');
  if (process.platform === 'win32') execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', "$ErrorActionPreference='Stop'; $allowed=@([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544'); $acl=[System.IO.File]::GetAccessControl($env:SG_PRIVATE_PATH); foreach($rule in $acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])){if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $allowed){throw 'Backup key ACL too broad'}}"], { env: { ...process.env, SG_PRIVATE_PATH: filename }, windowsHide: true, stdio: 'pipe' });
}
async function noLinks(filename) {
  let current = path.resolve(filename);
  while (true) {
    try { if ((await fs.lstat(current)).isSymbolicLink()) throw new Error('Symbolic-link paths are not supported'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    const parent = path.dirname(current); if (parent === current) return; current = parent;
  }
}
async function readBounded(filename, limit) {
  const before = await fs.lstat(filename);
  if (!before.isFile() || before.isSymbolicLink() || before.size > limit) throw new Error('File is not regular or exceeds backup limits');
  const file = await fs.open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  try {
    const after = await file.stat();
    if (!after.isFile() || before.ino !== after.ino || before.dev !== after.dev || after.size > limit) throw new Error('File changed during backup');
    const output = Buffer.alloc(after.size + 1); let offset = 0;
    while (offset < output.length) { const read = await file.read(output, offset, output.length - offset, null); if (!read.bytesRead) break; offset += read.bytesRead; }
    if (offset !== after.size || (await file.stat()).mtimeMs !== after.mtimeMs) throw new Error('Source changed; stop writers and restage the backup');
    return output.subarray(0, offset);
  } finally { await file.close(); }
}
async function keyBytes(filename) { await noLinks(filename); await assertPrivateKey(filename); return readBounded(filename, 32); }

export async function generateKey(filename) {
  filename = path.resolve(filename); await noLinks(filename);
  const file = await fs.open(filename, 'wx', 0o600);
  try { await privatePermissions(filename); await file.writeFile(randomBytes(32)); await file.sync(); } finally { await file.close(); }
  return { created: true, bytes: 32 };
}
export async function createBackup({ source, output, keyFile, confirmed = false }) {
  if (!confirmed) throw new Error('Confirm that the source is a stopped, consistent, privately staged snapshot');
  source = path.resolve(source); output = path.resolve(output);
  if (output === source || output.startsWith(source + path.sep)) throw new Error('Backup output must be outside its source');
  if (path.resolve(keyFile) === source || path.resolve(keyFile).startsWith(source + path.sep)) throw new Error('Keep the backup decryption key outside the source');
  await noLinks(source); await noLinks(output);
  const files = []; const directories = []; const names = new Set(); let total = 0;
  async function visit(directory, relative = '') {
    for (const entry of (await fs.readdir(directory, { withFileTypes: true })).sort((left, right) => left.name.localeCompare(right.name))) {
      if (!portable(entry.name)) throw new Error('Nonportable backup path');
      const name = relative ? `${relative}/${entry.name}` : entry.name;
      const folded = name.toLowerCase(); if (names.has(folded) || names.size >= 10000) throw new Error('Duplicate or excessive backup entries'); names.add(folded);
      if (name.split('/').length > 32 || name.toLowerCase() === 'restore_receipt.json' || entry.isSymbolicLink()) throw new Error('Unsupported backup entry');
      if (entry.isDirectory()) { directories.push(name); await visit(path.join(directory, entry.name), name); continue; }
      if (!entry.isFile() || files.length >= 10000) throw new Error('Unsupported file or too many files');
      const content = await readBounded(path.join(directory, entry.name), 16 * 1024 * 1024);
      total += content.length; if (total > maxBytes) throw new Error('Staged backup exceeds 64 MiB; use reviewed external PostgreSQL backup tooling');
      files.push({ path: name, bytes: content.length, sha256: digest(content), content: content.toString('base64') });
    }
  }
  if (!(await fs.lstat(source)).isDirectory()) throw new Error('Backup source must be a directory');
  await visit(source); if (!files.length) throw new Error('Cannot back up an empty source');
  const key = await keyBytes(keyFile);
  try {
    const header = Buffer.from(JSON.stringify({ format: 'serverguard-encrypted-backup', version: 1, cipher: 'AES-256-GCM', createdAt: new Date().toISOString(), keyId: digest(key).slice(0, 16) }));
    const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', key, iv); cipher.setAAD(header);
    const ciphertext = Buffer.concat([cipher.update(gzipSync(Buffer.from(JSON.stringify({ version: 1, directories, files })))), cipher.final()]);
    const length = Buffer.alloc(4); length.writeUInt32BE(header.length);
    const file = await fs.open(output, 'wx', 0o600);
    try { await privatePermissions(output); await file.writeFile(Buffer.concat([magic, length, header, iv, cipher.getAuthTag(), ciphertext])); await file.sync(); } finally { await file.close(); }
    return { files: files.length, plaintextBytes: total, encryptedBytes: (await fs.stat(output)).size, sha256: digest(await readBounded(output, 128 * 1024 * 1024)) };
  } finally { key.fill(0); }
}
export async function restoreBackup({ input, destination, keyFile }) {
  input = path.resolve(input); destination = path.resolve(destination); await noLinks(input); await noLinks(destination);
  try { await fs.lstat(destination); throw new Error('Restore destination must not exist; never overwrite live data'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const envelope = await readBounded(input, 128 * 1024 * 1024);
  if (envelope.length < 56 || !envelope.subarray(0, 8).equals(magic)) throw new Error('Invalid backup format');
  const length = envelope.readUInt32BE(8); if (length < 2 || length > 4096 || 12 + length + 28 >= envelope.length) throw new Error('Invalid backup header');
  const header = envelope.subarray(12, 12 + length); const metadata = JSON.parse(header.toString('utf8'));
  if (metadata.format !== 'serverguard-encrypted-backup' || metadata.version !== 1 || metadata.cipher !== 'AES-256-GCM') throw new Error('Unsupported backup version');
  const key = await keyBytes(keyFile); let decoded;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, envelope.subarray(12 + length, 24 + length));
    decipher.setAAD(header); decipher.setAuthTag(envelope.subarray(24 + length, 40 + length));
    decoded = JSON.parse(gunzipSync(Buffer.concat([decipher.update(envelope.subarray(40 + length)), decipher.final()]), { maxOutputLength: 128 * 1024 * 1024 }).toString('utf8'));
  } finally { key.fill(0); }
  if (decoded.version !== 1 || !Array.isArray(decoded.files) || !Array.isArray(decoded.directories) || !decoded.files.length || decoded.files.length + decoded.directories.length > 10000) throw new Error('Invalid backup manifest');
  let total = 0; const seen = new Set(); const restored = [];
  for (const directory of decoded.directories) {
    if (typeof directory !== 'string' || directory.split('/').length > 32 || !directory.split('/').every(portable) || directory.toLowerCase() === 'restore_receipt.json' || seen.has(directory.toLowerCase())) throw new Error('Unsafe or duplicate directory');
    seen.add(directory.toLowerCase());
  }
  for (const file of decoded.files) {
    if (typeof file.path !== 'string' || file.path.split('/').length > 32 || !file.path.split('/').every(portable) || file.path.toLowerCase() === 'restore_receipt.json') throw new Error('Unsafe restore path');
    const normalized = file.path.toLowerCase(); if (seen.has(normalized)) throw new Error('Duplicate restore path'); seen.add(normalized);
    if (typeof file.content !== 'string' || !Number.isSafeInteger(file.bytes) || file.bytes < 0 || file.bytes > 16 * 1024 * 1024) throw new Error('Invalid file entry');
    const content = Buffer.from(file.content, 'base64'); total += content.length;
    if (total > maxBytes || content.length !== file.bytes || content.toString('base64') !== file.content || digest(content) !== file.sha256) throw new Error('Backup file checksum/size mismatch');
    restored.push({ path: file.path, content });
  }
  const fileNames = new Set(restored.map(file => file.path.toLowerCase()));
  for (const entry of [...decoded.directories, ...restored.map(file => file.path)]) {
    const parts = entry.toLowerCase().split('/'); parts.pop(); while (parts.length) { if (fileNames.has(parts.join('/'))) throw new Error('Restore file/directory conflict'); parts.pop(); }
  }
  await fs.mkdir(destination, { mode: 0o700 }); await privatePermissions(destination, true);
  for (const directory of decoded.directories.sort((left, right) => left.split('/').length - right.split('/').length)) await fs.mkdir(path.join(destination, ...directory.split('/')), { recursive: true, mode: 0o700 });
  for (const file of restored) {
    const target = path.join(destination, ...file.path.split('/')); await fs.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    await fs.writeFile(target, file.content, { flag: 'wx', mode: 0o600 });
  }
  const receipt = { format: 'serverguard-restore-receipt', restoredAt: new Date().toISOString(), files: restored.length, bytes: total, backupSha256: digest(envelope), sourceCreatedAt: metadata.createdAt, databaseStarted: false };
  await fs.writeFile(path.join(destination, 'RESTORE_RECEIPT.json'), JSON.stringify(receipt, null, 2), { flag: 'wx', mode: 0o600 });
  return receipt;
}
async function main() {
  const [command, ...args] = process.argv.slice(2); const options = {};
  for (let index = 0; index < args.length; index++) {
    if (args[index] === '--confirm-consistent-source') { options.confirmed = true; continue; }
    if (!['--source', '--output', '--key-file', '--input', '--destination'].includes(args[index]) || !args[index + 1] || Object.hasOwn(options, args[index])) throw new Error('Invalid command options');
    options[args[index]] = args[++index];
  }
  const keyFile = options['--key-file']; if (!keyFile) throw new Error('A private --key-file is required');
  const result = command === 'keygen' ? await generateKey(keyFile) : command === 'create' ? await createBackup({ source: options['--source'], output: options['--output'], keyFile, confirmed: options.confirmed }) : command === 'restore' ? await restoreBackup({ input: options['--input'], destination: options['--destination'], keyFile }) : (() => { throw new Error('Use keygen, create or restore'); })();
  process.stdout.write(`${JSON.stringify(result)}\n`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) main().catch(() => { process.stderr.write('Backup operation failed; verify options, private permissions, key, source consistency and limits. Existing data is never overwritten.\n'); process.exitCode = 1; });
