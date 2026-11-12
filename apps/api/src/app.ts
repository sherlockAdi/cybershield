import 'reflect-metadata';
import { Body, Controller, Get, Post, Patch, Delete, Param, Query, Req, Res, Inject, Module, HttpException, Catch, ArgumentsHost, ExceptionFilter } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import type { Request, Response, NextFunction } from 'express';
import express from 'express';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { Database } from './database';
import { ControlService } from './service';
import { origin, root } from './config';
import path from 'node:path';
import { AgentService, AgentRequest } from './agents';
import { TelemetryService } from './telemetry';
import { FirewallService } from './firewall';
import { RolloutService } from './rollouts';
import { DetectionService } from './detections';
import { HostManagementService } from './host-management';
import { ActivityService } from './activity';
import { ScreenshotService } from './screenshots';
import { DeviceService } from './devices';
import { DocumentService } from './documents';

@Catch()
class SafeErrors implements ExceptionFilter {
  catch(error: unknown, host: ArgumentsHost) {
    const response = host.switchToHttp().getResponse<Response>();
    const parserType = (error as { type?: string })?.type;
    const status = error instanceof HttpException ? error.getStatus() : parserType === 'entity.too.large' ? 413 : parserType === 'entity.parse.failed' ? 400 : 500;
    response.status(status).json({ statusCode: status, message: error instanceof HttpException ? error.message : status === 413 ? 'Payload too large' : status === 400 ? 'Invalid JSON body' : 'An internal error occurred' });
    if (status === 500) console.error('Request failed:', (error as { code?: string }).code || 'internal_error');
  }
}

@Controller('api')
class ApiController {
  constructor(@Inject(ScreenshotService) private readonly screenshots: ScreenshotService, @Inject(DeviceService) private readonly devices: DeviceService, @Inject(DocumentService) private readonly documents: DocumentService, @Inject(HostManagementService) private readonly management: HostManagementService, @Inject(ControlService) private readonly service: ControlService, @Inject(AgentService) private readonly agents: AgentService, @Inject(TelemetryService) private readonly telemetry: TelemetryService, @Inject(FirewallService) private readonly firewall: FirewallService, @Inject(RolloutService) private readonly rollouts: RolloutService, @Inject(DetectionService) private readonly detections: DetectionService, @Inject(ActivityService) private readonly activity: ActivityService) {}
  @Get('organizations/:id/servers/:serverId/activity') async serverActivity(@Req() request: Request, @Param('id') id: string, @Param('serverId') serverId: string, @Query() query: unknown) { return this.activity.report(await this.service.authenticate(request), id, serverId, query); }

  @Get('organizations/:id/security/settings') async detectionSettings(@Req() request: Request, @Param('id') id: string) { return this.detections.config(await this.service.authenticate(request), id); }
  @Patch('organizations/:id/security/settings') async setDetectionSettings(@Req() request: Request, @Param('id') id: string, @Body() body: unknown) { return this.detections.updateConfig(await this.service.authenticate(request), id, body); }
  @Get('organizations/:id/incidents') async incidents(@Req() request: Request, @Param('id') id: string, @Query() query: unknown) { return this.detections.incidents(await this.service.authenticate(request), id, query); }
  @Get('organizations/:id/incidents/:incidentId') async incident(@Req() request: Request, @Param('id') id: string, @Param('incidentId') incidentId: string) { return this.detections.incident(await this.service.authenticate(request), id, incidentId); }
  @Patch('organizations/:id/incidents/:incidentId') async incidentState(@Req() request: Request, @Param('id') id: string, @Param('incidentId') incidentId: string, @Body() body: unknown) { return this.detections.updateIncident(await this.service.authenticate(request), id, incidentId, body); }
  @Get('organizations/:id/notifications') async notifications(@Req() request: Request, @Param('id') id: string, @Query() query: unknown) { return this.detections.inbox(await this.service.authenticate(request), id, query); }
  @Patch('organizations/:id/notifications/:notificationId/read') async notificationRead(@Req() request: Request, @Param('id') id: string, @Param('notificationId') notificationId: string, @Body() body: unknown) { return this.detections.read(await this.service.authenticate(request), id, notificationId, body); }
  @Get('organizations/:id/security/deliveries') async deliveries(@Req() request: Request, @Param('id') id: string) { return this.detections.deliveries(await this.service.authenticate(request), id); }
  @Post('organizations/:id/security/deliveries/:deliveryId/retry') async retryDelivery(@Req() request: Request, @Param('id') id: string, @Param('deliveryId') deliveryId: string, @Body() body: unknown) { return this.detections.retry(await this.service.authenticate(request), id, deliveryId, body); }

  @Get('organizations/:id/rollouts') async rolloutsList(@Req() request: Request, @Param('id') id: string, @Query() query: unknown) { return this.rollouts.list(await this.service.authenticate(request), id, query); }
  @Post('organizations/:id/rollouts') async requestRollout(@Req() request: Request, @Param('id') id: string, @Body() body: unknown) { return this.rollouts.request(await this.service.authenticate(request), id, body); }
  @Get('organizations/:id/rollouts/:deploymentId') async rolloutDetail(@Req() request: Request, @Param('id') id: string, @Param('deploymentId') deploymentId: string) { return this.rollouts.detail(await this.service.authenticate(request), id, deploymentId); }
  @Post('organizations/:id/rollouts/:deploymentId/decision') async rolloutDecision(@Req() request: Request, @Param('id') id: string, @Param('deploymentId') deploymentId: string, @Body() body: unknown) { return this.rollouts.decide(await this.service.authenticate(request), id, deploymentId, body); }
  @Post('organizations/:id/rollouts/:deploymentId/actions') async rolloutAction(@Req() request: Request, @Param('id') id: string, @Param('deploymentId') deploymentId: string, @Body() body: unknown) { return this.rollouts.action(await this.service.authenticate(request), id, deploymentId, body); }
  @Patch('organizations/:id/rollouts/:deploymentId/targets/:targetId/scenario') async rolloutScenario(@Req() request: Request, @Param('id') id: string, @Param('deploymentId') deploymentId: string, @Param('targetId') targetId: string, @Body() body: unknown) { return this.rollouts.scenario(await this.service.authenticate(request), id, deploymentId, targetId, body); }

  @Get('organizations/:id/firewall/policies') async policies(@Req() request: Request, @Param('id') id: string, @Query() query: unknown) { return this.firewall.list(await this.service.authenticate(request), id, query); }
  @Post('organizations/:id/firewall/policies') async createPolicy(@Req() request: Request, @Param('id') id: string, @Body() body: unknown) { return this.firewall.create(await this.service.authenticate(request), id, body); }
  @Get('organizations/:id/firewall/policies/:policyId') async policy(@Req() request: Request, @Param('id') id: string, @Param('policyId') policyId: string, @Query('versionId') versionId?: string) { return this.firewall.detail(await this.service.authenticate(request), id, policyId, versionId); }
  @Patch('organizations/:id/firewall/policies/:policyId/versions/:versionId') async savePolicy(@Req() request: Request, @Param('id') id: string, @Param('policyId') policyId: string, @Param('versionId') versionId: string, @Body() body: unknown) { return this.firewall.save(await this.service.authenticate(request), id, policyId, versionId, body); }
  @Post('organizations/:id/firewall/policies/:policyId/versions/:versionId/revise') async revisePolicy(@Req() request: Request, @Param('id') id: string, @Param('policyId') policyId: string, @Param('versionId') versionId: string) { return this.firewall.revise(await this.service.authenticate(request), id, policyId, versionId); }
  @Post('organizations/:id/firewall/policies/:policyId/versions/:versionId/preview') async previewPolicy(@Req() request: Request, @Param('id') id: string, @Param('policyId') policyId: string, @Param('versionId') versionId: string, @Body() body: unknown) { return this.firewall.preview(await this.service.authenticate(request), id, policyId, versionId, body); }
  @Post('organizations/:id/firewall/policies/:policyId/versions/:versionId/submit') async submitPolicy(@Req() request: Request, @Param('id') id: string, @Param('policyId') policyId: string, @Param('versionId') versionId: string, @Body() body: unknown) { return this.firewall.submit(await this.service.authenticate(request), id, policyId, versionId, body); }
  @Get('organizations/:id/firewall/policies/:policyId/history') async policyHistory(@Req() request: Request, @Param('id') id: string, @Param('policyId') policyId: string, @Query() query: unknown) { return this.firewall.history(await this.service.authenticate(request), id, policyId, query); }

  @Get('organizations/:id/documents/vault') async documentVault(@Req() req: Request, @Param('id') id: string) { return { vault: await this.documents.vault(await this.service.authenticate(req),id) }; }
  @Post('organizations/:id/documents/vault') async createDocumentVault(@Req() req: Request, @Param('id') id: string, @Body() body: unknown) { return this.documents.createVault(await this.service.authenticate(req),id,body); }
  @Get('organizations/:id/documents') async documentList(@Req() req: Request, @Param('id') id: string) { return this.documents.list(await this.service.authenticate(req),id); }
  @Post('organizations/:id/documents') async createDocument(@Req() req: Request, @Param('id') id: string, @Body() body: unknown) { return this.documents.create(await this.service.authenticate(req),id,body); }
  @Post('organizations/:id/documents/:doc/chunks') async uploadDocumentChunk(@Req() req: Request, @Param('id') id: string, @Param('doc') doc: string, @Body() body: unknown) { return this.documents.uploadChunk(await this.service.authenticate(req),id,doc,body); }
  @Get('organizations/:id/documents/:doc/chunks/:index') async readDocumentChunk(@Req() req: Request, @Param('id') id: string, @Param('doc') doc: string, @Param('index') index: string) { return this.documents.chunk(await this.service.authenticate(req),id,doc,index); }
  @Post('organizations/:id/documents/:doc/complete') async completeDocument(@Req() req: Request, @Param('id') id: string, @Param('doc') doc: string) { return this.documents.complete(await this.service.authenticate(req),id,doc); }
  @Delete('organizations/:id/documents/:doc') async removeDocument(@Req() req: Request, @Param('id') id: string, @Param('doc') doc: string) { return this.documents.remove(await this.service.authenticate(req),id,doc); }
  @Get('organizations/:id/documents/:doc/links') async documentLinks(@Req() req: Request, @Param('id') id: string, @Param('doc') doc: string) { return this.documents.links(await this.service.authenticate(req),id,doc); }
  @Post('organizations/:id/documents/:doc/links') async shareDocument(@Req() req: Request, @Param('id') id: string, @Param('doc') doc: string, @Body() body: unknown) { return this.documents.share(await this.service.authenticate(req),id,doc,body); }
  @Delete('organizations/:id/documents/:doc/links/:link') async revokeDocumentLink(@Req() req: Request, @Param('id') id: string, @Param('doc') doc: string, @Param('link') link: string) { return this.documents.revoke(await this.service.authenticate(req),id,doc,link); }
  @Post('documents/public') async publicDocument(@Body() body: unknown) { return this.documents.publicRead(body); }

  @Get('organizations/:id/devices') async deviceList(@Req() req: Request, @Param('id') id: string, @Query() query: unknown) { return this.devices.list(await this.service.authenticate(req),id,query); }
  @Get('organizations/:id/devices/:device') async deviceDetail(@Req() req: Request, @Param('id') id: string, @Param('device') device: string) { return this.devices.read(await this.service.authenticate(req),id,device); }
  @Patch('organizations/:id/devices/:device') async deviceSave(@Req() req: Request, @Param('id') id: string, @Param('device') device: string, @Body() body: unknown) { return this.devices.save(await this.service.authenticate(req),id,device,body); }
  @Get('organizations/:id/devices/:device/screenshots') async screenshotRead(@Req() req: Request, @Res({ passthrough: true }) res: Response, @Param('id') id: string, @Param('device') device: string) { res.setHeader('Cache-Control','no-store'); return this.screenshots.read(await this.service.authenticate(req),id,device); }
  @Patch('organizations/:id/devices/:device/screenshots') async screenshotConfig(@Req() req: Request, @Param('id') id: string, @Param('device') device: string, @Body() body: unknown) { return this.screenshots.configure(await this.service.authenticate(req),id,device,body); }
  @Post('agent/v1/screenshot') async screenshotUpload(@Req() req: AgentRequest) { return this.screenshots.ingest(req); }
  @Get('health') health() { return { status: 'ok', milestone: 'week-8-detections', database: this.service.db.mode }; }
  @Post('agent/v1/events') ingestEvents(@Req() request: AgentRequest) { return this.telemetry.ingest(request); }
  @Get('organizations/:id/inventory') async inventory(@Req() request: Request, @Param('id') id: string, @Query() query: unknown) { return this.telemetry.inventory(await this.service.authenticate(request), id, query); }
  @Get('organizations/:id/events') async events(@Req() request: Request, @Param('id') id: string, @Query() query: unknown) { return this.telemetry.events(await this.service.authenticate(request), id, query); }
  @Get('organizations/:id/servers/:serverId/management') async hostManagement(@Req() request: Request, @Param('id') id: string, @Param('serverId') serverId: string) { return this.management.read(await this.service.authenticate(request), id, serverId); }
  @Post('organizations/:id/servers/:serverId/commands') async hostCommand(@Req() request: Request, @Param('id') id: string, @Param('serverId') serverId: string, @Body() body: unknown) { return this.management.command(await this.service.authenticate(request), id, serverId, body); }
  @Get('organizations/:id/groups') async groups(@Req() request: Request, @Param('id') id: string) { return this.telemetry.groups(await this.service.authenticate(request), id); }
  @Post('organizations/:id/groups') async createGroup(@Req() request: Request, @Param('id') id: string, @Body() body: unknown) { return this.telemetry.createGroup(await this.service.authenticate(request), id, body); }
  @Patch('organizations/:id/servers/:serverId/metadata') async metadata(@Req() request: Request, @Param('id') id: string, @Param('serverId') serverId: string, @Body() body: unknown) { return this.telemetry.updateMetadata(await this.service.authenticate(request), id, serverId, body); }
  @Get('organizations/:id/servers/:serverId/metrics') async metrics(@Req() request: Request, @Param('id') id: string, @Param('serverId') serverId: string, @Query() query: unknown) { return this.telemetry.history(await this.service.authenticate(request), id, serverId, query); }
  @Post('agent/v1/enroll') enrollAgent(@Req() request: AgentRequest) { return this.agents.enroll(request); }
  @Post('agent/v1/heartbeat') heartbeat(@Req() request: AgentRequest) { return this.agents.heartbeat(request); }
  @Get('organizations/:id/servers') async servers(@Req() request: Request, @Param('id') id: string) { return this.agents.servers(await this.service.authenticate(request), id); }
  @Post('organizations/:id/servers') async createServer(@Req() request: Request, @Param('id') id: string, @Body() body: unknown) { return this.agents.createServer(await this.service.authenticate(request), id, body); }
  @Post('organizations/:id/servers/:serverId/enrollment') async agentEnrollment(@Req() request: Request, @Param('id') id: string, @Param('serverId') serverId: string) { return this.agents.issueEnrollment(await this.service.authenticate(request), id, serverId); }
  @Post('organizations/:id/servers/:serverId/revoke') async revokeAgent(@Req() request: Request, @Param('id') id: string, @Param('serverId') serverId: string) { return this.agents.revoke(await this.service.authenticate(request), id, serverId); }
  @Post('organizations/:id/servers/:serverId/decommission') async decommissionServer(@Req() request: Request, @Param('id') id: string, @Param('serverId') serverId: string) { return this.agents.revoke(await this.service.authenticate(request), id, serverId, true); }
  @Post('auth/register') register(@Body() body: unknown, @Res({ passthrough: true }) response: Response) { return this.service.register(body, response); }
  @Post('auth/login') login(@Body() body: unknown, @Res({ passthrough: true }) response: Response) { return this.service.login(body, response); }
  @Post('auth/refresh') refresh(@Req() request: Request, @Res({ passthrough: true }) response: Response) { return this.service.refresh(request, response); }
  @Post('auth/logout') logout(@Req() request: Request, @Res({ passthrough: true }) response: Response) { return this.service.logout(request, response); }
  @Get('auth/me') async me(@Req() request: Request) { return this.service.me(await this.service.authenticate(request, false)); }
  @Post('auth/mfa/setup') async setup(@Req() request: Request) { return this.service.mfaSetup(await this.service.authenticate(request, false)); }
  @Post('auth/mfa/confirm') async confirm(@Req() request: Request, @Body() body: unknown) { return this.service.mfaConfirm(await this.service.authenticate(request, false), body); }
  @Get('auth/sessions') async sessions(@Req() request: Request) { return this.service.sessions(await this.service.authenticate(request)); }
  @Delete('auth/sessions/:id') async revokeSession(@Req() request: Request, @Param('id') id: string) { return this.service.revokeSession(await this.service.authenticate(request), id); }
  @Post('organizations') async create(@Req() request: Request, @Body() body: unknown) { return this.service.createOrganization(await this.service.authenticate(request), body); }
  @Post('invitations/accept') async accept(@Req() request: Request, @Body() body: unknown) { return this.service.acceptInvite(await this.service.authenticate(request), body); }
  @Get('organizations/:id/overview') async overview(@Req() request: Request, @Param('id') id: string) { return this.service.overview(await this.service.authenticate(request), id); }
  @Patch('organizations/:id') async update(@Req() request: Request, @Param('id') id: string, @Body() body: unknown) { return this.service.updateOrganization(await this.service.authenticate(request), id, body); }
  @Get('organizations/:id/members') async members(@Req() request: Request, @Param('id') id: string) { return this.service.members(await this.service.authenticate(request), id); }
  @Patch('organizations/:id/members/:userId') async change(@Req() request: Request, @Param('id') id: string, @Param('userId') userId: string, @Body() body: unknown) { return this.service.changeMember(await this.service.authenticate(request), id, userId, body); }
  @Delete('organizations/:id/members/:userId') async remove(@Req() request: Request, @Param('id') id: string, @Param('userId') userId: string) { return this.service.changeMember(await this.service.authenticate(request), id, userId, {}, true); }
  @Get('organizations/:id/invitations') async invitations(@Req() request: Request, @Param('id') id: string) { return this.service.invitations(await this.service.authenticate(request), id); }
  @Post('organizations/:id/invitations') async invite(@Req() request: Request, @Param('id') id: string, @Body() body: unknown) { return this.service.invite(await this.service.authenticate(request), id, body); }
  @Delete('organizations/:id/invitations/:invitationId') async revoke(@Req() request: Request, @Param('id') id: string, @Param('invitationId') invitationId: string) { return this.service.revokeInvite(await this.service.authenticate(request), id, invitationId); }
}

export async function createApp(database?: Database) {
  const db = database || await new Database().open();
  @Module({ controllers: [ApiController], providers: [{ provide: Database, useValue: db }, ControlService, AgentService, TelemetryService, FirewallService, RolloutService, DetectionService, ActivityService, HostManagementService, DocumentService, DeviceService, ScreenshotService] })
  class AppModule {}
  const app = await NestFactory.create(AppModule, { logger: ['error', 'warn'], bodyParser: false });
  app.use(helmet());
  app.use(cookieParser());
  const attempts = new Map<string, { count: number; expires: number }>();
  app.use((request: Request, response: Response, next: NextFunction) => {
    response.setHeader('Cache-Control', 'no-store');
    if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method)) {
      const agentRequest = request.method === 'POST' && ['/api/agent/v1/enroll', '/api/agent/v1/heartbeat', '/api/agent/v1/events'].includes(request.originalUrl);
      if (agentRequest ? request.headers.origin !== undefined : request.headers.origin !== origin) { response.status(403).json({ message: 'Untrusted request origin' }); return; }
      if (!request.is('application/json') && request.method !== 'DELETE') { response.status(415).json({ message: 'Use application/json' }); return; }
      const now = Date.now();
      for (const [key, entry] of attempts) if (entry.expires <= now) attempts.delete(key);
      const sensitive = /\/auth\/(login|register|mfa\/confirm)/.test(request.path) || request.path === '/api/agent/v1/enroll';
      const documentTransfer = request.path === '/api/documents/public' ? 'document-public' : /^\/api\/organizations\/[0-9a-f-]{36}\/documents\/[0-9a-f-]{36}\/chunks$/.test(request.path) ? 'document-upload' : '';
      const key = `${request.socket.remoteAddress}:${sensitive ? request.path : agentRequest ? 'agent' : documentTransfer || 'write'}`;
      const entry = attempts.get(key) || { count: 0, expires: now + (sensitive ? 15 * 60000 : 60000) };
      entry.count++;
      attempts.set(key, entry);
      if (entry.count > (sensitive ? 20 : agentRequest ? 4000 : documentTransfer ? 600 : 120)) { response.setHeader('Retry-After', String(Math.ceil((entry.expires - now) / 1000))); response.status(429).json({ message: 'Too many attempts. Please try later.' }); return; }
    }
    next();
  });
  const rawBody = (request: express.Request, _response: express.Response, buffer: Buffer) => { (request as AgentRequest).rawBody = Buffer.from(buffer); };
  app.use('/api/agent/v1/releases', express.static(path.join(root, 'agent-release'), { index: false, dotfiles: 'deny', fallthrough: false, maxAge: 0, redirect: false }));
  const normalJson = express.json({ limit: '16kb', verify: rawBody });
  const heartbeatJson = express.json({ limit: '256kb', verify: rawBody });
  const documentJson = express.json({ limit: '70kb' });
  const eventsJson = express.json({ limit: '64kb', verify: rawBody });
  app.use((request: Request, response: Response, next: NextFunction) => (request.method === 'POST' && /^\/api\/organizations\/[0-9a-f-]{36}\/documents\/[0-9a-f-]{36}\/chunks$/.test(request.path) ? documentJson : request.originalUrl === '/api/agent/v1/events' ? eventsJson : ['/api/agent/v1/heartbeat','/api/agent/v1/screenshot'].includes(request.originalUrl) ? heartbeatJson : normalJson)(request, response, next));
  app.useGlobalFilters(new SafeErrors());
  app.enableShutdownHooks();
  return { app, db };
}
