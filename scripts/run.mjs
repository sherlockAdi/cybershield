import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const root = fileURLToPath(new URL('..', import.meta.url));
const mode = process.argv[2] || 'dev';
const children = [];
const require = createRequire(import.meta.url);
const engineDirectory = path.dirname(path.dirname(require.resolve('@prisma/engines', { paths: [require.resolve('prisma/package.json')] })));
if (process.platform === 'win32') {
  const schemaEngine = path.join(engineDirectory, 'schema-engine-windows.exe');
  const queryEngine = path.join(engineDirectory, 'query_engine-windows.dll.node');
  if (fs.existsSync(schemaEngine)) process.env.PRISMA_SCHEMA_ENGINE_BINARY ||= schemaEngine;
  if (fs.existsSync(queryEngine)) process.env.PRISMA_QUERY_ENGINE_LIBRARY ||= queryEngine;
}
const bin = (name, file) => path.join(root, name, 'node_modules', file);
function execute(file, args, cwd = root) {
  const child = spawn(process.execPath, [file, ...args], { cwd, stdio: 'inherit', env: process.env });
  children.push(child);
  return new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('exit', code => code === 0 ? resolve() : reject(new Error(`Process exited with ${code}`)));
  });
}
function stop() { for (const child of children) child.kill(); }
process.on('SIGINT', () => { stop(); process.exit(0); });
process.on('SIGTERM', () => { stop(); process.exit(0); });
try {
  const api = path.join(root, 'apps/api');
  const dashboard = path.join(root, 'apps/dashboard');
  if (mode === 'dev' || mode === 'start') {
    const apiRun = mode === 'dev'
      ? execute(bin('', 'tsx/dist/cli.mjs'), ['watch', 'src/main.ts'], api)
      : execute(path.join(api, 'dist/main.js'), [], api);
    const bindHost = process.env.DASHBOARD_BIND_HOST || '127.0.0.1';
    if (!['127.0.0.1', '0.0.0.0'].includes(bindHost)) throw new Error('Unsupported dashboard bind host');
    await Promise.all([apiRun, execute(bin('apps/dashboard', 'next/dist/bin/next'), [mode, '--hostname', bindHost, '--port', '3100'], dashboard)]);
  } else if (mode === 'build' || mode === 'check') {
    process.env.DATABASE_URL ||= 'postgresql://validation:validation@127.0.0.1:54329/validation';
    await execute(bin('', 'typescript/bin/tsc'), mode === 'check' ? ['--noEmit', '-p', 'apps/api/tsconfig.json'] : ['-p', 'apps/api/tsconfig.json']);
    await execute(bin('', 'prisma/build/index.js'), ['validate', '--schema', 'infrastructure/database/schema.prisma']);
    if (mode === 'build') await execute(bin('apps/dashboard', 'next/dist/bin/next'), ['build'], dashboard);
    else await execute(bin('', 'typescript/bin/tsc'), ['--noEmit', '-p', 'apps/dashboard/tsconfig.json']);
  } else if (mode === 'test') {
    await execute('--test', ['tests/operations/release-backup.test.mjs']);
    await execute(bin('', 'tsx/dist/cli.mjs'), ['--test', '../../tests/security/foundation.test.ts', '../../tests/security/documents.test.ts', '../../tests/security/agents.test.ts', '../../tests/security/telemetry.test.ts', '../../tests/security/activity.test.ts', '../../tests/security/host-management.test.ts', '../../tests/security/firewall.test.ts', '../../tests/security/rollouts.test.ts', '../../tests/security/detections.test.ts'], api);
  } else if (mode.startsWith('db:')) {
    const command = mode.slice(3);
    if (!['validate', 'format', 'generate', 'deploy', 'status'].includes(command)) throw new Error('Unsupported database command');
    if (['validate', 'format', 'generate'].includes(command)) process.env.DATABASE_URL ||= 'postgresql://validation:validation@127.0.0.1:54329/validation';
    await execute(bin('', 'prisma/build/index.js'), [...(['deploy', 'status'].includes(command) ? ['migrate', command] : [command]), '--schema', 'infrastructure/database/schema.prisma']);
  } else throw new Error(`Unknown command: ${mode}`);
} catch (error) { console.error(error.message); stop(); process.exit(1); }
