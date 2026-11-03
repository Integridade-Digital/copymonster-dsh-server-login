/**
 * DSH launch / supervise / restart routes + the reverse proxy to a running
 * instance. Launch resolves the requested folder, reads its enabled plugins,
 * writes a cordis patch, and spawns a main+watchdog pair; restart writes a
 * post-restart command handoff and respawns the main.
 * @module dsh-server-login/web/routes/dsh
 */

import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify'
import { resolveSessionUser, requireAuth } from '../middleware/authn.js'
import { toPublicUser } from '../../db/types.js'
import { sendFsError } from './desktop.js'
import { AlreadyRunningError } from '../../supervisor/orchestrator.js'
import { renderPatch } from '../../supervisor/patch.js'
import { subdomainForUser } from '../../supervisor/proxy.js'

const launchSchema = {
  body: {
    type: 'object',
    required: ['folder'],
    additionalProperties: false,
    properties: { folder: { type: 'string', maxLength: 512 } },
  },
} as const

const restartSchema = {
  body: {
    type: 'object',
    required: ['command'],
    additionalProperties: false,
    properties: { command: { type: 'string', maxLength: 1024 } },
  },
} as const

const STATUS_TIMEOUT = Symbol('status-timeout')
const STATUS_OPERATION_TIMEOUT_MS = 5000

async function withTimeout<T>(operation: Promise<T>, timeoutMs: number): Promise<T | typeof STATUS_TIMEOUT> {
  let timer: NodeJS.Timeout | undefined
  try {
    return await Promise.race([
      operation,
      new Promise<typeof STATUS_TIMEOUT>((resolve) => {
        timer = setTimeout(() => resolve(STATUS_TIMEOUT), timeoutMs)
        timer.unref()
      }),
    ])
  } finally {
    if (timer !== undefined) clearTimeout(timer)
  }
}

async function requireStatusAuth(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const user = await withTimeout(
    resolveSessionUser(request.server, request.headers.cookie),
    STATUS_OPERATION_TIMEOUT_MS,
  )
  if (user === STATUS_TIMEOUT) {
    reply.code(503).header('retry-after', '3').send({ error: 'status_unavailable', stage: 'authentication' })
    return
  }
  if (user === undefined) {
    reply.code(401).send({ error: 'unauthorized' })
    return
  }
  request.user = toPublicUser(user)
}

function dshUrl(baseDomain: string, user: { id: string; username: string }): string {
  const sub = subdomainForUser(baseDomain, user.username)
  return sub !== null ? `https://${sub}/` : `/u/${user.id}/dsh/`
}

export const dshRoutes: FastifyPluginAsync = async (app) => {
  app.post('/api/dsh/launch', { preHandler: requireAuth, schema: launchSchema }, async (request, reply) => {
    const { folder } = request.body as { folder: string }
    const user = request.user!
    const fs = app.userFs
    let folderAbs: string
    try {
      folderAbs = fs.resolvePath(user.id, folder)
      if (!(await fs.isDirectory(user.id, folder))) {
        return reply.code(400).send({ error: 'not_a_folder' })
      }
    } catch (err) {
      return sendFsError(reply, err)
    }

    // Per-folder plugin selection → cordis patch. Rendered here but *not*
    // written: the spawner decides where it lands (a file under local, a
    // ConfigMap under k8s, where the control plane has no user volume).
    let patch: string | undefined
    if (app.config.enablePatch) {
      const workspace = await app.db.findWorkspaceByPath(user.id, folder)
      // Only inject plugins the user still has installed; a stale selection for
      // a since-removed bundle would otherwise fail to resolve in the child DSH.
      const installed = new Set((await fs.listInstalledPlugins(user.id)).map((plugin) => plugin.id))
      const enabled = (workspace === undefined ? [] : await app.db.getEnabledPluginIds(workspace.id))
        .filter((id) => installed.has(id))
      patch = renderPatch(enabled)
    }

    try {
      const instance = await app.supervisor.launch(user.id, folderAbs, patch)
      return {
        instance: { id: instance.id, port: instance.port, status: instance.status },
        url: dshUrl(app.config.baseDomain, user),
      }
    } catch (err) {
      if (err instanceof AlreadyRunningError) return reply.code(409).send({ error: 'already_running' })
      throw err
    }
  })

  app.post('/api/dsh/restart', { preHandler: requireAuth, schema: restartSchema }, async (request, reply) => {
    const { command } = request.body as { command: string }
    const user = request.user!
    await app.userFs.writeHandoff(user.id, JSON.stringify({ command, createdAt: Date.now() }))
    const instance = await app.supervisor.restartMain(user.id)
    if (instance === undefined) return reply.code(404).send({ error: 'not_running' })
    await app.supervisor.spawnWatchdog(user.id)
    return {
      instance: { id: instance.id, port: instance.port, status: instance.status },
      url: dshUrl(app.config.baseDomain, user),
    }
  })

  app.post('/api/dsh/stop', { preHandler: requireAuth }, async (request) => {
    await app.supervisor.stop(request.user!.id)
    return { ok: true }
  })

  app.get('/api/dsh/status', { preHandler: requireStatusAuth }, async (request, reply) => {
    try {
      const status = await withTimeout(
        app.supervisor.status(request.user!.id),
        STATUS_OPERATION_TIMEOUT_MS,
      )
      if (status === STATUS_TIMEOUT) {
        request.log.error({ userId: request.user!.id }, 'DSH status lookup timed out')
        return reply.code(503).header('retry-after', '3').send({ error: 'status_unavailable', stage: 'supervisor' })
      }
      const { main, watchdog } = status
      const isRunning = main?.status === 'running'
      const result = {
        running: isRunning,
        status: main?.status ?? 'stopped',
        instance: main
          ? { id: main.id, port: main.port, status: main.status, exitCode: main.exitCode, lastError: main.lastError }
          : null,
        watchdog: watchdog ? { id: watchdog.id, status: watchdog.status, exitCode: watchdog.exitCode } : null,
        url: dshUrl(app.config.baseDomain, request.user!),
      }
      return result
    } catch (err: any) {
      throw err
    }
  })

}
