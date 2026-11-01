import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const excluded = new Set(['node_modules', '.git', '.runtime', '.codex', '.agents', '.next', 'bin', 'obj', 'dist', 'build', 'coverage', 'backups', 'artifacts', '.pnpm-store', '__pycache__']);
const safe = value => typeof value === 'string' && value.length > 0 && !value.includes('\\') && !value.includes(':') && !path.posix.isAbsolute(value) && value.split('/').every(part => part && part !== '.' && part !== '..');
const hash = content => createHash('sha256').update(content).digest('hex');

export async function packageRelease({ output, version, sourceRoot = root, includeAgents = true }) {
  if (!/^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?$/.test(version)) throw new Error('Use an explicit semantic pilot version');
  output = path.resolve(output); sourceRoot = path.resolve(sourceRoot);
  if (output === sourceRoot || output.startsWith(sourceRoot + path.sep) && !['artifacts', '.runtime'].some(name => output.startsWith(path.join(sourceRoot, name) + path.sep))) throw new Error('Use artifacts/, .runtime/ or an external release destination, never a source folder');
  await fs.mkdir(output, { recursive: false, mode: 0o700 });
  const files = []; const names = new Set();
  async function copy(source, relative) {
    if (!safe(relative) || names.has(relative.toLowerCase())) throw new Error('Invalid or duplicate release path');
    const info = await fs.lstat(source);
    if (!info.isFile() || info.isSymbolicLink() || info.size > 64 * 1024 * 1024) throw new Error('Unsupported release file');
    names.add(relative.toLowerCase());
    const bytes = await fs.readFile(source); const destination = path.join(output, ...relative.split('/'));
    await fs.mkdir(path.dirname(destination), { recursive: true }); await fs.writeFile(destination, bytes, { flag: 'wx', mode: 0o644 });
    files.push({ path: relative, bytes: bytes.length, sha256: hash(bytes) });
  }
  async function walk(directory, relative) {
    for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
      if (excluded.has(entry.name) || entry.name.startsWith('.env') || /\.(env|pem|key|pfx|p12|log|tsbuildinfo|pdb)$/i.test(entry.name) || /^(credentials|secrets|tokens)\.json$/i.test(entry.name)) continue;
      if (entry.isSymbolicLink()) throw new Error('Release source contains a symbolic link');
      if (entry.isDirectory()) await walk(path.join(directory, entry.name), `${relative}/${entry.name}`);
      else await copy(path.join(directory, entry.name), `${relative}/${entry.name}`);
    }
  }
  for (const name of ['README.md', 'package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml', '.env.example', '.gitignore', '.gitattributes']) await copy(path.join(sourceRoot, name), `source/${name}`);
  for (const directory of ['apps', 'agents', 'docs', 'infrastructure', 'packages', 'scripts', 'services', 'tests', '.github']) await walk(path.join(sourceRoot, directory), `source/${directory}`);
  const binaries = [];
  if (includeAgents) {
    await copy(path.join(sourceRoot, 'artifacts/linux-amd64/serverguard-agent'), 'agents/linux-amd64/serverguard-agent'); binaries.push('linux-amd64');
    for (const file of await fs.readdir(path.join(sourceRoot, 'artifacts/windows-x64'))) if (/\.(exe|dll|json)$/i.test(file)) await copy(path.join(sourceRoot, 'artifacts/windows-x64', file), `agents/windows-x64/${file}`);
    if (!files.some(file => file.path === 'agents/windows-x64/ServerGuard.Agent.exe')) throw new Error('Windows agent artifact is missing');
    binaries.push('windows-x64-framework-dependent');
  }
  files.sort((left, right) => left.path.localeCompare(right.path));
  const manifest = { format: 'serverguard-pilot-release', schemaVersion: 1, version, createdAt: new Date().toISOString(), signed: false, sourceOnlyControlPlane: true, requiredNode: '22 or 24', requiredPnpm: '11.25.0', windowsAgentRuntime: '.NET 10', binaries, nativeFirewallExecution: false, automaticOsLogCollection: false, externalNotificationsConfigured: false, files };
  await fs.writeFile(path.join(output, 'manifest.json'), JSON.stringify(manifest, null, 2), { flag: 'wx', mode: 0o644 });
  await verifyRelease(output);
  return { output, version, files: files.length, signed: false, manifestSha256: hash(await fs.readFile(path.join(output, 'manifest.json'))) };
}
export async function verifyRelease(directory) {
  directory = path.resolve(directory);
  if ((await fs.lstat(directory)).isSymbolicLink()) throw new Error('Release directory cannot be a symbolic link');
  const info = await fs.lstat(path.join(directory, 'manifest.json')); if (!info.isFile() || info.isSymbolicLink() || info.size > 4 * 1024 * 1024) throw new Error('Invalid manifest');
  const manifest = JSON.parse(await fs.readFile(path.join(directory, 'manifest.json'), 'utf8'));
  if (manifest.format !== 'serverguard-pilot-release' || manifest.schemaVersion !== 1 || manifest.signed !== false || !Array.isArray(manifest.files) || manifest.files.length > 50000) throw new Error('Unsupported manifest');
  const expected = new Set(['manifest.json']);
  for (const file of manifest.files) {
    if (!safe(file.path) || expected.has(file.path) || !/^[a-f0-9]{64}$/.test(file.sha256) || !Number.isSafeInteger(file.bytes) || file.bytes < 0 || file.bytes > 64 * 1024 * 1024) throw new Error('Invalid manifest entry');
    expected.add(file.path);
  }
  const actual = new Set();
  async function inspect(current, relative = '') {
    for (const entry of await fs.readdir(current, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) throw new Error('Release contains a symbolic link');
      const name = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory()) await inspect(path.join(current, entry.name), name);
      else { if (!entry.isFile() || !expected.has(name)) throw new Error('Unexpected release content'); actual.add(name); }
    }
  }
  await inspect(directory); if (actual.size !== expected.size) throw new Error('Release files missing');
  for (const file of manifest.files) {
    const filename = path.join(directory, ...file.path.split('/')); const stat = await fs.stat(filename);
    if (stat.size !== file.bytes || hash(await fs.readFile(filename)) !== file.sha256) throw new Error('Release checksum mismatch');
  }
  return { verified: true, files: manifest.files.length, signed: manifest.signed === true, authenticityVerified: false };
}
async function main() {
  const [command, directory, version] = process.argv.slice(2);
  const result = command === 'verify' ? await verifyRelease(directory) : command === 'create' ? await packageRelease({ output: directory, version }) : (() => { throw new Error('Use create <new-output-directory> <pilot-version> or verify <directory>'); })();
  process.stdout.write(`${JSON.stringify(result)}\n`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) main().catch(() => { process.stderr.write('Release packaging/verification failed. Check inputs, missing artifacts, unsafe paths or modified files. Partial output is not a release.\n'); process.exitCode = 1; });
