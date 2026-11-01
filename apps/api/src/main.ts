import { createApp } from './app';
import { RolloutService } from './rollouts';
import { DetectionService } from './detections';

async function main() {
  const { app, db } = await createApp();
  const bindHost = process.env.API_BIND_HOST || '127.0.0.1';
  if (!['127.0.0.1', '0.0.0.0'].includes(bindHost)) throw new Error('Unsupported API bind host');
  await app.listen(4100, bindHost);
  app.get(RolloutService).start();
  app.get(DetectionService).start();
  console.log(`ServerGuard API: http://127.0.0.1:4100 (${db.mode})`);
  const shutdown = async () => { await app.close(); await db.close(); process.exit(0); };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
}
main().catch(error => { console.error('API startup failed:', error.message); process.exit(1); });
