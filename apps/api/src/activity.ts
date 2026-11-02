import { BadRequestException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { z } from 'zod';
import { Database } from './database';
import { Actor, ControlService } from './service';
import { input, uuid } from './input';

export function indiaDay(value?: string, now = Date.now()) {
  const today = new Date(now + 19800000).toISOString().slice(0, 10);
  const day = value || today;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) throw new BadRequestException('Use YYYY-MM-DD');
  const start = new Date(`${day}T00:00:00+05:30`);
  if (!Number.isFinite(start.getTime()) || new Date(start.getTime() + 19800000).toISOString().slice(0, 10) !== day || day > today || start.getTime() < now - 31 * 86400000) throw new BadRequestException('Choose a valid day within the last 30 days, not the future');
  return { date: day, timeZone: 'Asia/Kolkata', start: start.toISOString(), end: new Date(Math.min(start.getTime() + 86400000, now)).toISOString() };
}

@Injectable()
export class ActivityService {
  constructor(@Inject(Database) private readonly db: Database, @Inject(ControlService) private readonly control: ControlService) {}
  async report(actor: Actor, organizationId: string, serverId: string, query: unknown) {
    const filter = input(z.object({ date: z.string().optional(), loginCursor: uuid.optional(), before: z.string().datetime().optional() }).strict(), query); const window = indiaDay(filter.date);
    if (filter.before && filter.before < window.end) window.end = filter.before;
    await this.control.membership(this.db, organizationId, actor);
    if (!(await this.db.query('SELECT id FROM servers WHERE organization_id=$1 AND id=$2', [organizationId, input(uuid, serverId)])).rows.length) throw new NotFoundException('Server not found');
    const params = [organizationId, serverId, new Date(window.start), new Date(window.end)];
    const range = 'organization_id=$1 AND server_id=$2 AND occurred_at>=$3 AND occurred_at<$4';
    const summary = (await this.db.query(`SELECT count(*) FILTER(WHERE kind='AUTH_SUCCESS')::int AS successful_logins,count(*) FILTER(WHERE kind='AUTH_FAILURE')::int AS failed_logins,count(*) FILTER(WHERE kind='NETWORK_CONNECTION')::int AS connection_observations,count(*) FILTER(WHERE kind='PROCESS_START')::int AS process_starts,count(DISTINCT COALESCE(payload->>'peerIp',payload->>'sourceIp')) FILTER(WHERE kind IN ('AUTH_SUCCESS','AUTH_FAILURE','NETWORK_CONNECTION','ICMP_ECHO'))::int AS unique_observed_ips,count(DISTINCT payload->>'peerIp') FILTER(WHERE kind='ICMP_ECHO')::int AS unique_ping_ips,COALESCE(sum(CASE WHEN kind='ICMP_ECHO' AND payload->>'requestCount' ~ '^[1-9][0-9]{0,8}$' THEN (payload->>'requestCount')::bigint ELSE 0 END),0)::text AS ping_requests FROM security_events WHERE ${range}`, params)).rows[0];
    const peers = (await this.db.query(`SELECT COALESCE(payload->>'peerIp',payload->>'sourceIp') AS ip,count(*) FILTER(WHERE kind='AUTH_SUCCESS')::int AS successful_logins,count(*) FILTER(WHERE kind='AUTH_FAILURE')::int AS failed_logins,count(*) FILTER(WHERE kind='NETWORK_CONNECTION')::int AS connections,COALESCE(sum(CASE WHEN kind='ICMP_ECHO' AND payload->>'requestCount' ~ '^[1-9][0-9]{0,8}$' THEN (payload->>'requestCount')::bigint ELSE 0 END),0)::text AS ping_requests,min(occurred_at) AS first_seen,max(occurred_at) AS last_seen FROM security_events WHERE ${range} AND kind IN ('AUTH_SUCCESS','AUTH_FAILURE','NETWORK_CONNECTION','ICMP_ECHO') AND COALESCE(payload->>'peerIp',payload->>'sourceIp') IS NOT NULL GROUP BY ip ORDER BY count(*) DESC,ip LIMIT 100`, params)).rows;
    let anchor: { occurred_at?: Date; id?: string } = {};
    if (filter.loginCursor) {
      anchor = (await this.db.query(`SELECT id,occurred_at FROM security_events WHERE ${range} AND id=$5 AND kind IN ('AUTH_SUCCESS','AUTH_FAILURE')`, [...params, filter.loginCursor])).rows[0];
      if (!anchor) throw new BadRequestException('Invalid login cursor');
    }
    const logins = (await this.db.query(`SELECT id,kind,occurred_at,received_at,payload->>'account' AS account,payload->>'sourceIp' AS source_ip,payload->>'service' AS service FROM security_events WHERE ${range} AND kind IN ('AUTH_SUCCESS','AUTH_FAILURE') AND ($5::timestamptz IS NULL OR (occurred_at,id)<($5::timestamptz,$6::uuid)) ORDER BY occurred_at DESC,id DESC LIMIT 11`, [...params, anchor.occurred_at || null, anchor.id || null])).rows;
    const connections = (await this.db.query(`SELECT id,occurred_at,payload->>'peerIp' AS peer_ip,payload->>'direction' AS direction,payload->>'transport' AS transport,payload->>'localPort' AS local_port,payload->>'peerPort' AS peer_port FROM security_events WHERE ${range} AND kind='NETWORK_CONNECTION' ORDER BY occurred_at DESC,id DESC LIMIT 100`, params)).rows;
    const collectors = (await this.db.query("SELECT DISTINCT ON(payload->>'collector') payload,received_at FROM security_events WHERE organization_id=$1 AND server_id=$2 AND kind='TELEMETRY_STATUS' ORDER BY payload->>'collector',received_at DESC,id DESC", [organizationId, serverId])).rows.map(row => ({ ...row.payload, receivedAt: row.received_at, stale: Date.now() - new Date(row.received_at).getTime() > 120000 }));
    return { window, summary, peers, logins: logins.slice(0, 10), nextLoginCursor: logins.length > 10 ? logins[9].id : null, connections, collectors, limits: { peers: 100, logins: 10, connections: 100 }, scope: 'Recorded observations, not complete traffic accounting. Connection snapshots miss short-lived flows. Ping counts are received ICMP echo requests, not unique ping commands or active reachability tests.' };
  }
}
