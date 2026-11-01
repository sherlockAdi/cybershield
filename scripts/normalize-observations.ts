import { normalizeJournal, normalizeWindows } from '../apps/api/src/observations';

async function main() {
  const format = process.argv[2];
  if (!['journal', 'windows-security'].includes(format)) throw new Error('Usage: tsx scripts/normalize-observations.ts journal|windows-security < input.jsonl');
  let input = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) { input += chunk; if (Buffer.byteLength(input) > 1024 * 1024) throw new Error('Input exceeds 1 MiB; split the export'); }
  let count = 0;
  const normalized = [];
  for (const line of input.replace(/^\uFEFF/, '').split(/\r?\n/)) {
    if (!line.trim()) continue;
    if (++count > 1000) throw new Error('Input exceeds 1000 records');
    const result = (format === 'journal' ? normalizeJournal : normalizeWindows)(JSON.parse(line));
    if (result) normalized.push(result);
    if (normalized.length > 90) throw new Error('Output exceeds 90 observations');
  }
  const output = normalized.map(event => JSON.stringify(event)).join('\n') + (normalized.length ? '\n' : '');
  if (Buffer.byteLength(output) > 32768) throw new Error('Output exceeds 32 KiB');
  process.stdout.write(output);
  process.stderr.write(`Normalized ${normalized.length} observations; ignored ${count - normalized.length} unsupported records.\n`);
}
main().catch(() => { process.stderr.write('Normalization failed: check format/JSON and documented input limits. No raw record is logged.\n'); process.exitCode = 1; });
