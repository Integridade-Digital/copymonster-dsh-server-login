/**
 * The per-user file sidecar (docs/k8s.md §4.10).
 *
 * Runs inside the user's own Pod as the user's uid, so it *can* read and write
 * their `0700` directory — the thing the control plane (uid 65532, no volume)
 * cannot do. It serves exactly one user: the root is fixed at startup, and no
 * request carries a user id.
 *
 * **Bearer token.** The NetworkPolicy still limits who can reach port 8082, but
 * the sidecar also requires the shared token the control plane presents
 * (`DSH_SERVER_LOGIN_FILE_SERVICE_TOKEN`), so a widened policy or a stray Pod
 * does not by itself grant access to a tenant's files. `/healthz` stays open for
 * the kubelet probe, which carries no credentials.
 * @module dsh-server-login/web/file-service
 */

import { createHash, timingSafeEqual } from 'node:crypto'
import Fastify, { type FastifyInstance, type FastifyReply } from 'fastify'
import { LocalUserFs } from '../fs/local-user-fs.js'
import { UserFsError } from '../fs/user-fs.js'

/** Port the sidecar binds; the per-user Service targets it directly. */
export const FILE_SERVICE_PORT = 8082

/** Env var carrying the single user root this sidecar serves. */
export const USER_ROOT_ENV = 'DSH_SERVER_LOGIN_USER_ROOT'

/** The sidecar serves one user, so the id crossing {@link UserFs} is a constant. */
const SOLE_USER = 'self'

/**
 * Token shared by the control plane and one user's file sidecar.
 *
 * Derived from the deployment secret and the user id so both sides compute the
 * same value without storing it, and a token leaked from one sidecar cannot
 * read another tenant's files.
 *
 * @param secret - deployment secret from {@link FILE_SERVICE_TOKEN_ENV}.
 * @param userId - the tenant whose sidecar receives the token.
 * @returns the token text, or an empty string when no secret is configured.
 */
export function fileServiceTokenFor(secret: string, userId: string): string {
  if (secret === '') return ''
  return createHash('sha256').update(secret).update(userId).digest('hex')
}

/** Env var carrying the shared control-plane secret; both sides must set it. */
export const FILE_SERVICE_TOKEN_ENV = 'DSH_SERVER_LOGIN_FILE_SERVICE_TOKEN'

/** Env var naming the single user whose root this sidecar serves. */
export const FILE_SERVICE_USER_ENV = 'DSH_SERVER_LOGIN_FILE_SERVICE_USER'

/** Header the control plane presents on every sidecar call. */
export const FILE_SERVICE_TOKEN_HEADER = 'x-dsh-file-token'

const pathSchema = {
  body: {
    type: 'object',
    required: ['path'],
    additionalProperties: false,
    properties: { path: { type: 'string', maxLength: 512 } },
  },
} as const

const entrySchema = {
  body: {
    type: 'object',
    required: ['path', 'name', 'type'],
    additionalProperties: false,
    properties: {
      path: { type: 'string', maxLength: 512 },
      name: { type: 'string', maxLength: 255 },
      type: { type: 'string', enum: ['file', 'dir'] },
    },
  },
} as const

const uploadSchema = {
  body: {
    type: 'object',
    required: ['path', 'name', 'data'],
    additionalProperties: false,
    properties: {
      path: { type: 'string', maxLength: 512 },
      name: { type: 'string', maxLength: 255 },
      data: { type: 'string' },
    },
  },
} as const

const handoffSchema = {
  body: {
    type: 'object',
    required: ['content'],
    additionalProperties: false,
    properties: { content: { type: 'string', maxLength: 8192 } },
  },
} as const

/** Reply with the seam's own wire form so the client can rebuild the error. */
function fail(reply: FastifyReply, err: unknown): FastifyReply {
  if (err instanceof UserFsError) return reply.code(err.status).send({ error: err.code })
  throw err
}

/**
 * Compare two tokens without leaking their length or prefix through timing.
 * @param presented - the header value the caller sent.
 * @param expected - the configured token.
 * @returns true when they match.
 */
function timingSafeEqualString(presented: string, expected: string): boolean {
  const a = Buffer.from(presented, 'utf8')
  const b = Buffer.from(expected, 'utf8')
  return a.length === b.length && timingSafeEqual(a, b)
}

/**
 * Build the sidecar's Fastify instance. Does not listen; the caller binds.
 * @param root - the user's data root inside the Pod.
 * @param options - `bodyLimit` must exceed the control plane's upload cap.
 */
export function buildFileService(
  root: string,
  options: { bodyLimit: number; logLevel: string; token: string },
): FastifyInstance {
  // Fail closed: without a token every request would be unauthenticated, which is
  // exactly the state this check exists to prevent.
  if (options.token === '') {
    throw new Error(`${FILE_SERVICE_TOKEN_ENV} must be set for the file sidecar`)
  }
  const fs = new LocalUserFs(() => root)
  const app = Fastify({ logger: { level: options.logLevel }, bodyLimit: options.bodyLimit })

  app.addHook('onRequest', async (request, reply) => {
    // The kubelet readiness probe has no credentials and reveals only liveness.
    if (request.url.split('?')[0] === '/healthz') return
    const presented = request.headers[FILE_SERVICE_TOKEN_HEADER]
    if (typeof presented !== 'string' || !timingSafeEqualString(presented, options.token)) {
      reply.code(401).send({ error: 'unauthorized' })
    }
  })

  app.get('/healthz', async () => ({ ok: true }))

  app.get('/fs/tree', async (request, reply) => {
    const { path = '' } = request.query as { path?: string }
    try {
      return { entries: await fs.listDir(SOLE_USER, path) }
    } catch (err) {
      return fail(reply, err)
    }
  })

  app.get('/fs/stat', async (request, reply) => {
    const { path = '' } = request.query as { path?: string }
    try {
      return { isDirectory: await fs.isDirectory(SOLE_USER, path) }
    } catch (err) {
      return fail(reply, err)
    }
  })

  app.get('/fs/plugins', async () => ({ plugins: await fs.listInstalledPlugins(SOLE_USER) }))

  app.post('/fs/init', async () => {
    await fs.initUserRoot(SOLE_USER)
    return { ok: true }
  })

  app.post('/fs/mkdir', { schema: pathSchema }, async (request, reply) => {
    const { path } = request.body as { path: string }
    try {
      await fs.mkdir(SOLE_USER, path)
      return { ok: true }
    } catch (err) {
      return fail(reply, err)
    }
  })

  app.post('/fs/create', { schema: entrySchema }, async (request, reply) => {
    const { path, name, type } = request.body as { path: string; name: string; type: 'file' | 'dir' }
    try {
      return { name: await fs.createEntry(SOLE_USER, path, name, type) }
    } catch (err) {
      return fail(reply, err)
    }
  })

  app.post('/fs/upload', { schema: uploadSchema }, async (request, reply) => {
    const { path, name, data } = request.body as { path: string; name: string; data: string }
    try {
      return { name: await fs.upload(SOLE_USER, path, name, Buffer.from(data, 'base64')) }
    } catch (err) {
      return fail(reply, err)
    }
  })

  app.post('/fs/handoff', { schema: handoffSchema }, async (request) => {
    const { content } = request.body as { content: string }
    await fs.writeHandoff(SOLE_USER, content)
    return { ok: true }
  })

  return app
}
