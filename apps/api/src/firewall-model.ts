import { isIP } from 'node:net';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { uuid } from './input';

const identity = uuid.transform(value => value.toLowerCase());

export function network(value: string) {
  const parts = value.split('/');
  if (parts.length > 2 || value.includes('%') || value.includes('.') && value.includes(':')) throw new Error('Use an unambiguous IPv4 or IPv6 network');
  const family = isIP(parts[0]);
  if (!family) throw new Error('Expected an IP address, not a hostname');
  const bits = family === 4 ? 32 : 128;
  if (parts[1] !== undefined && !/^(0|[1-9][0-9]{0,2})$/.test(parts[1])) throw new Error('Invalid network prefix');
  const prefix = parts[1] === undefined ? bits : Number(parts[1]);
  if (prefix > bits) throw new Error('Network prefix out of range');
  let address: bigint;
  let canonical: string;
  if (family === 4) {
    address = parts[0].split('.').reduce((total, octet) => total * 256n + BigInt(octet), 0n);
    canonical = parts[0];
  } else {
    const halves = parts[0].toLowerCase().split('::');
    const left = halves[0] ? halves[0].split(':') : [];
    const right = halves[1] ? halves[1].split(':') : [];
    const words = halves.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
    address = words.reduce((total, word) => total * 65536n + BigInt(`0x${word}`), 0n);
    canonical = new URL(`http://[${parts[0]}]/`).hostname.slice(1, -1);
    if (address >> 32n === 65535n) throw new Error('IPv4-mapped IPv6 is unsupported');
  }
  const shift = BigInt(bits - prefix);
  if (address >> shift << shift !== address) throw new Error('CIDR has host bits set; provide a network address');
  return { cidr: `${canonical}/${prefix}`, family, bits, prefix, address };
}

export const cidr = z.string().max(64).transform((value, context) => {
  try { return network(value).cidr; } catch (error) { context.addIssue({ code: 'custom', message: (error as Error).message }); return z.NEVER; }
});
export const ruleSchema = z.object({
  id: identity, action: z.enum(['ALLOW', 'BLOCK']), direction: z.enum(['INBOUND', 'OUTBOUND']), cidr,
  protocol: z.enum(['TCP', 'UDP', 'ICMP']), portStart: z.number().int().min(1).max(65535).nullable(), portEnd: z.number().int().min(1).max(65535).nullable(),
  expiresAt: z.string().datetime().transform(value => new Date(value).toISOString()).nullable(), reason: z.string().trim().min(3).max(1000),
}).strict().superRefine((rule, context) => {
  if (rule.protocol === 'ICMP' ? rule.portStart !== null || rule.portEnd !== null : rule.portStart === null || rule.portEnd === null || rule.portStart > rule.portEnd) context.addIssue({ code: 'custom', message: 'TCP/UDP require an ordered port range; ICMP prohibits ports' });
});
export const targetSchema = z.object({ type: z.enum(['SERVER', 'GROUP']), id: identity }).strict();
export const contentSchema = z.object({ target: targetSchema, rules: z.array(ruleSchema).min(1).max(50) }).strict().refine(value => new Set(value.rules.map(rule => rule.id)).size === value.rules.length, 'Rule IDs must be unique');
export type FirewallRule = z.infer<typeof ruleSchema>;
export type PolicyContent = z.infer<typeof contentSchema>;

export function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.entries(value).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0).map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(',')}}`;
  return JSON.stringify(value);
}
export function policyChecksum(content: PolicyContent, targetIds: string[]) {
  return createHash('sha256').update(canonical({ schemaVersion: 1, target: content.target, targetIds: [...targetIds].sort(), rules: [...content.rules].sort((left, right) => left.id.localeCompare(right.id)) })).digest('hex');
}
export function contains(cidrValue: string, address: string) {
  const net = network(cidrValue); const host = network(address);
  return net.family === host.family && net.address >> BigInt(net.bits - net.prefix) === host.address >> BigInt(net.bits - net.prefix);
}
export function risks(rules: FirewallRule[], targetCount: number, now = Date.now()) {
  const reasons = new Set<string>(); const blockers = new Set<string>();
  if (targetCount > 5) reasons.add('More than five target servers');
  for (const rule of rules.filter(rule => !rule.expiresAt || Date.parse(rule.expiresAt) > now)) {
    const net = network(rule.cidr);
    if (net.prefix < (net.family === 4 ? 24 : 64)) reasons.add('Broad source/destination network');
    if (rule.direction === 'OUTBOUND') reasons.add('Outbound traffic change');
    if (rule.portStart === 1 && rule.portEnd === 65535) reasons.add('All-port range');
    const management = rule.direction === 'INBOUND' && rule.portStart !== null && rule.portEnd !== null && [22, 3389].some(port => rule.portStart! <= port && rule.portEnd! >= port);
    if (management) reasons.add('Touches SSH/RDP management ports');
    if (management && rule.action === 'BLOCK') blockers.add('Management-port blocking requires an independently verified recovery path; unavailable in this milestone');
    if (rule.direction === 'OUTBOUND' && rule.action === 'BLOCK') blockers.add('Outbound blocking requires verified control-plane egress/recovery safeguards; unavailable in this milestone');
  }
  return { highImpact: reasons.size > 0, reasons: [...reasons], blockers: [...blockers] };
}
export const packetSchema = z.object({ address: z.string().max(64).refine(value => {
  if (value.includes('/')) return false;
  try { network(value); return true; } catch { return false; }
}, 'Expected an unambiguous plain IPv4/IPv6 address'), direction: z.enum(['INBOUND', 'OUTBOUND']), protocol: z.enum(['TCP', 'UDP', 'ICMP']), port: z.number().int().min(1).max(65535).nullable() }).strict().refine(packet => packet.protocol === 'ICMP' ? packet.port === null : packet.port !== null, 'TCP/UDP need a destination port; ICMP prohibits one');
export function simulate(rules: FirewallRule[], packet: z.infer<typeof packetSchema>, now = Date.now()) {
  const matches = rules.filter(rule => (!rule.expiresAt || Date.parse(rule.expiresAt) > now) && rule.direction === packet.direction && rule.protocol === packet.protocol && contains(rule.cidr, packet.address) && (rule.protocol === 'ICMP' || packet.port! >= rule.portStart! && packet.port! <= rule.portEnd!));
  return { managedVerdict: matches.some(rule => rule.action === 'BLOCK') ? 'BLOCK' : matches.length ? 'ALLOW' : 'NO_MATCH', matchedRuleIds: matches.map(rule => rule.id), scope: 'Selected version only; other ServerGuard policies and external/default firewall policy may still deny traffic' };
}

export function nativePlan(versionId: string, os: string, rules: FirewallRule[], now = Date.now()) {
  const active = rules.filter(rule => !rule.expiresAt || Date.parse(rule.expiresAt) > now).sort((left, right) => (left.action === right.action ? left.id.localeCompare(right.id) : left.action === 'BLOCK' ? -1 : 1));
  const namespace = `sg_${versionId.replaceAll('-', '')}`;
  const warnings = ['PREVIEW ONLY: no live host inspection or mutation', 'ALLOW cannot override external deny/default policies', 'Approval, coexistence inspection, watchdog and native verification are required before any execution'];
  if (active.some(rule => rule.expiresAt)) warnings.push('Temporary rules require durable offline expiration scheduling before execution');
  if (os === 'LINUX') {
    const lines = [`table inet ${namespace} {`];
    for (const direction of ['INBOUND', 'OUTBOUND']) {
      lines.push(` chain ${direction.toLowerCase()} {`, `  type filter hook ${direction === 'INBOUND' ? 'input' : 'output'} priority 10; policy accept;`);
      for (const rule of active.filter(rule => rule.direction === direction)) {
        const family = network(rule.cidr).family === 4 ? 'ip' : 'ip6';
        const protocol = rule.protocol.toLowerCase();
        const matcher = rule.protocol === 'ICMP' ? `meta l4proto ${family === 'ip' ? 'icmp' : 'ipv6-icmp'}` : `${protocol} dport ${rule.portStart === rule.portEnd ? rule.portStart : `${rule.portStart}-${rule.portEnd}`}`;
        lines.push(`  ${family} ${direction === 'INBOUND' ? 'saddr' : 'daddr'} ${rule.cidr} ${matcher} ${rule.action === 'BLOCK' ? 'drop' : 'accept'} comment "sg:${rule.id}"`);
      }
      lines.push(' }');
    }
    lines.push('}');
    return { adapter: 'nftables', executable: false, status: 'UNVERIFIED', namespace, warnings, artifact: lines.join('\n'), inspection: ['Reject firewalld ownership', 'Inspect nftables base chains and priorities', 'Require verified management/control-plane paths', 'Native syntax check with nft --check --file in isolated VM'] };
  }
  return { adapter: 'windows-netsecurity', executable: false, status: 'UNVERIFIED', namespace, warnings, commands: active.map(rule => ({ command: 'New-NetFirewallRule', parameters: { Name: `${namespace}_${rule.id}`, DisplayName: `${namespace}_${rule.id}`, Group: namespace, PolicyStore: 'PersistentStore', Direction: rule.direction === 'INBOUND' ? 'Inbound' : 'Outbound', Action: rule.action === 'BLOCK' ? 'Block' : 'Allow', Protocol: rule.protocol === 'ICMP' ? network(rule.cidr).family === 4 ? 'ICMPv4' : 'ICMPv6' : rule.protocol, RemoteAddress: rule.cidr, ...(rule.protocol === 'ICMP' ? {} : { [rule.direction === 'INBOUND' ? 'LocalPort' : 'RemotePort']: rule.portStart === rule.portEnd ? String(rule.portStart) : `${rule.portStart}-${rule.portEnd}` }), Profile: 'Any', Enabled: 'True', EdgeTraversalPolicy: 'Block' } })), inspection: ['Inspect ActiveStore and effective GPO', 'Require enabled firewall profiles and local-rule merging', 'Reject unsupported authenticated-bypass conflicts', 'Verify protected management/control-plane reachability'] };
}
