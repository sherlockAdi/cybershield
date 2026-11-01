import { PGlite } from '@electric-sql/pglite';
import { Pool, PoolClient } from 'pg';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { root } from './config';

export type Row = Record<string, any>;
export interface Queryable {
  query<T extends Row = Row>(sql: string, params?: any[]): Promise<{ rows: T[] }>;
}

export class Database implements Queryable {
  private embedded?: PGlite;
  private pool?: Pool;
  readonly mode = process.env.DATABASE_URL ? 'external-postgresql' : 'embedded-postgresql';

  async open(memory = false) {
    if (process.env.DATABASE_URL && !memory) {
      this.pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 10 });
      await this.pool.query('SELECT id FROM users LIMIT 0');
    } else {
      this.embedded = new PGlite(memory ? 'memory://' : path.join(root, '.runtime/postgres'));
      await this.embedded.waitReady;
      await this.embedded.exec('CREATE TABLE IF NOT EXISTS _serverguard_migrations (name TEXT PRIMARY KEY, checksum TEXT NOT NULL)');
      const migrationRoot = path.join(root, 'infrastructure/database/migrations');
      const directories = (await fs.readdir(migrationRoot, { withFileTypes: true })).filter(entry => entry.isDirectory()).sort((left, right) => left.name.localeCompare(right.name));
      for (const directory of directories) {
        const sql = await fs.readFile(path.join(migrationRoot, directory.name, 'migration.sql'), 'utf8');
        const checksum = createHash('sha256').update(sql).digest('hex');
        const prior = await this.embedded.query<{ checksum: string }>('SELECT checksum FROM _serverguard_migrations WHERE name=$1', [directory.name]);
        if (prior.rows.length) {
          if (prior.rows[0].checksum !== checksum) throw new Error(`Applied migration changed: ${directory.name}`);
          continue;
        }
        await this.embedded.transaction(async transaction => {
          await transaction.exec(sql);
          await transaction.query('INSERT INTO _serverguard_migrations (name,checksum) VALUES ($1,$2)', [directory.name, checksum]);
        });
      }
    }
    return this;
  }

  async query<T extends Row = Row>(sql: string, params: any[] = []): Promise<{ rows: T[] }> {
    if (this.embedded) return this.embedded.query<T>(sql, params);
    return this.pool!.query<T>(sql, params);
  }

  async transaction<T>(work: (client: Queryable) => Promise<T>): Promise<T> {
    if (this.embedded) return this.embedded.transaction(transaction => work(transaction));
    const client: PoolClient = await this.pool!.connect();
    try {
      await client.query('BEGIN');
      const result = await work(client);
      await client.query('COMMIT');
      return result;
    } catch (error) { await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
  }

  async close() { await this.embedded?.close(); await this.pool?.end(); }
}
