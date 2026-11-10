// The file sidecar requires the per-user token; the kubelet probe stays open
// and a caller without the token is refused (SEC-012).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  buildFileService,
  FILE_SERVICE_TOKEN_HEADER,
  FILE_SERVICE_USER_ENV,
  fileServiceTokenFor,
} from '../lib/web/file-service.js'

const SECRET = 'file-service-test-secret'
const USER = 'user-aaaa'

function makeSidecar() {
  const root = mkdtempSync(join(tmpdir(), 'dsh-fs-auth-'))
  const app = buildFileService(root, {
    bodyLimit: 1024 * 1024,
    logLevel: 'error',
    token: fileServiceTokenFor(SECRET, USER),
  })
  return { app, root }
}

test('file-service: a request without the token is refused', async () => {
  const { app, root } = makeSidecar()
  try {
    const res = await app.inject({ method: 'GET', url: '/fs/tree' })
    assert.equal(res.statusCode, 401)
    assert.equal(res.json().error, 'unauthorized')
  } finally {
    await app.close()
    rmSync(root, { recursive: true, force: true })
  }
})

test('file-service: a wrong token is refused', async () => {
  const { app, root } = makeSidecar()
  try {
    const res = await app.inject({
      method: 'GET',
      url: '/fs/tree',
      headers: { [FILE_SERVICE_TOKEN_HEADER]: 'not-the-token' },
    })
    assert.equal(res.statusCode, 401)
  } finally {
    await app.close()
    rmSync(root, { recursive: true, force: true })
  }
})

test("file-service: another tenant's token is refused", async () => {
  const { app, root } = makeSidecar()
  try {
    const res = await app.inject({
      method: 'GET',
      url: '/fs/tree',
      headers: { [FILE_SERVICE_TOKEN_HEADER]: fileServiceTokenFor(SECRET, 'user-bbbb') },
    })
    assert.equal(res.statusCode, 401)
  } finally {
    await app.close()
    rmSync(root, { recursive: true, force: true })
  }
})

test('file-service: the control-plane token is accepted', async () => {
  const { app, root } = makeSidecar()
  try {
    const res = await app.inject({
      method: 'GET',
      url: '/fs/tree',
      headers: { [FILE_SERVICE_TOKEN_HEADER]: fileServiceTokenFor(SECRET, USER) },
    })
    assert.equal(res.statusCode, 200)
    assert.deepEqual(res.json(), { entries: [] })
  } finally {
    await app.close()
    rmSync(root, { recursive: true, force: true })
  }
})

test('file-service: the readiness probe stays open for the kubelet', async () => {
  const { app, root } = makeSidecar()
  try {
    const res = await app.inject({ method: 'GET', url: '/healthz' })
    assert.equal(res.statusCode, 200)
  } finally {
    await app.close()
    rmSync(root, { recursive: true, force: true })
  }
})

test('file-service: the sidecar refuses to start without a token', () => {
  assert.throws(
    () => buildFileService('/tmp/x', { bodyLimit: 1024, logLevel: 'error', token: '' }),
    /must be set for the file sidecar/,
  )
})

test('file-service: the token is per user and stable', () => {
  assert.equal(fileServiceTokenFor(SECRET, USER), fileServiceTokenFor(SECRET, USER))
  assert.notEqual(fileServiceTokenFor(SECRET, USER), fileServiceTokenFor(SECRET, 'user-bbbb'))
  assert.notEqual(fileServiceTokenFor(SECRET, USER), fileServiceTokenFor('other-secret', USER))
  assert.equal(fileServiceTokenFor('', USER), '')
  assert.equal(FILE_SERVICE_USER_ENV, 'DSH_SERVER_LOGIN_FILE_SERVICE_USER')
})
