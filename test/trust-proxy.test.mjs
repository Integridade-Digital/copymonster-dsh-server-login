// Only the edge may set X-Forwarded-For, so a direct client cannot choose the
// address used for rate limiting and audit (SEC-011).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import Fastify from 'fastify'
import { TRUSTED_PROXY_PEERS, trustedProxyPeers } from '../lib/web/server.js'

function appWithTrust(trustProxy) {
  const app = Fastify({ trustProxy })
  app.get('/ip', async (request) => ({ ip: request.ip }))
  return app
}

test('trustProxy: loopback is the default trusted peer', () => {
  assert.deepEqual([...TRUSTED_PROXY_PEERS], ['127.0.0.1', '::1'])
  assert.deepEqual(trustedProxyPeers({ trustedProxyCidrs: [] }), ['127.0.0.1', '::1'])
})

test('trustProxy: configured peers are appended, never replace loopback', () => {
  assert.deepEqual(
    trustedProxyPeers({ trustedProxyCidrs: ['10.0.0.0/8', '172.16.0.1'] }),
    ['127.0.0.1', '::1', '10.0.0.0/8', '172.16.0.1'],
  )
})

test('trustProxy: a direct client cannot spoof its address', async () => {
  const app = appWithTrust([...TRUSTED_PROXY_PEERS])
  try {
    const res = await app.inject({
      method: 'GET',
      url: '/ip',
      remoteAddress: '203.0.113.9',
      headers: { 'x-forwarded-for': '10.9.9.9' },
    })
    assert.equal(res.json().ip, '203.0.113.9')
  } finally {
    await app.close()
  }
})

test('trustProxy: the edge can still forward the real client address', async () => {
  const app = appWithTrust([...TRUSTED_PROXY_PEERS])
  try {
    const res = await app.inject({
      method: 'GET',
      url: '/ip',
      remoteAddress: '127.0.0.1',
      headers: { 'x-forwarded-for': '198.51.100.7' },
    })
    assert.equal(res.json().ip, '198.51.100.7')
  } finally {
    await app.close()
  }
})
