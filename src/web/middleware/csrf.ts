/**
 * Cross-site request forgery guard for state-changing requests.
 *
 * Over HTTPS the session cookie is `SameSite=None` so it can cross the
 * `app.<baseDomain>` ↔ `<tenant>.<baseDomain>` boundary. That removes the
 * browser's SameSite protection, so every mutating request must prove it came
 * from the platform: `Origin` (or `Referer` when `Origin` is absent) has to
 * name the request's own host, `<baseDomain>` or one of its subdomains, or the
 * main-app origin. A cookie-bearing request only trusts its own host and the
 * apex/main-app origins, because the shared cookie spans every tenant
 * subdomain. Requests that carry neither header are only accepted from a
 * loopback peer, which covers server-to-server calls and the local smoke
 * scripts; browsers always send `Origin` on a cross-site POST.
 * @module dsh-server-login/web/middleware/csrf
 */

import type { FastifyInstance } from 'fastify'
import type { ServerConfig } from '../../config.js'
import { parseCookie } from '../auth.js'

/** Methods that change state and therefore require a platform origin. */
const MUTATING_METHODS: ReadonlySet<string> = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

/** IPv4/IPv6 literal addresses that only a local peer can present. */
const LOOPBACK_ADDRESS = /^(?:::1|::ffff:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})$/

/** Hostnames accepted as loopback, including the bracket form `URL` returns. */
const LOOPBACK_HOSTNAMES: ReadonlySet<string> = new Set(['localhost', '127.0.0.1', '[::1]', '::1'])

/** Origin policy derived from the deployment configuration. */
export interface CsrfOriginPolicy {
  /** Registrable platform hosts; their subdomains are also accepted. */
  readonly platformHosts: readonly string[]
  /** Apex and main-app hostnames trusted for cookie-bearing cross-subdomain calls. */
  readonly cookieTrustedHosts: readonly string[]
  /** Whether loopback origins are accepted (local development only). */
  readonly allowLoopback: boolean
}

/** Request facts the guard reads; separated so the decision stays unit-testable. */
export interface MutationRequestView {
  /** HTTP method as received. */
  readonly method: string
  /** Raw `Origin` header, when present. */
  readonly origin?: string | undefined
  /** Raw `Referer` header, when present. */
  readonly referer?: string | undefined
  /** Client-facing host headers (`host` and `x-forwarded-host`). */
  readonly hosts: readonly string[]
  /** Socket peer address after `trustProxy` resolution. */
  readonly remoteAddress: string | undefined
  /** Whether the request carries a `sid` cookie. */
  readonly hasSessionCookie: boolean
}

/** Split a host header into a lowercase hostname and an explicit port. */
function splitHost(value: string): { hostname: string; port: string } | undefined {
  try {
    const url = new URL(`http://${value.trim()}`)
    return { hostname: url.hostname.toLowerCase(), port: url.port }
  } catch {
    return undefined
  }
}

/** Parse an `Origin`/`Referer` value, rejecting non-HTTP and malformed values. */
function parseOrigin(value: string): URL | undefined {
  try {
    const url = new URL(value.trim())
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return undefined
    if (url.username !== '' || url.password !== '') return undefined
    return url
  } catch {
    return undefined
  }
}

/** True when `hostname` is a platform host or one of its subdomains. */
function isPlatformHost(hostname: string, policy: CsrfOriginPolicy): boolean {
  const name = hostname.toLowerCase()
  return policy.platformHosts.some((base) => name === base || name.endsWith(`.${base}`))
}

/** True when the origin names one of this request's own hosts. */
function isSameHost(origin: URL, hosts: readonly string[]): boolean {
  const originPort = origin.port !== '' ? origin.port : origin.protocol === 'https:' ? '443' : '80'
  for (const host of hosts) {
    const parsed = splitHost(host)
    if (parsed === undefined) continue
    if (origin.hostname.toLowerCase() !== parsed.hostname) continue
    const hostPort = parsed.port !== '' ? parsed.port : '80'
    if (hostPort === originPort || parsed.port === '') return true
  }
  return false
}

/**
 * Build the origin policy for a deployment.
 *
 * `baseDomain` and `cookieDomain` accept themselves and every subdomain for
 * requests without a session cookie (login and the SSO exchange). With a
 * cookie, only the request's own host and the main app are trusted: the
 * session cookie spans every tenant subdomain, so a page served by one tenant
 * must not be able to mutate another tenant's session.
 *
 * @param config - deployment configuration.
 * @returns the immutable policy the request guard uses.
 */
export function buildCsrfOriginPolicy(
  config: Pick<ServerConfig, 'baseDomain' | 'cookieDomain' | 'mainAppUrl' | 'secureCookies'>,
): CsrfOriginPolicy {
  const hosts = new Set<string>()
  for (const value of [config.baseDomain, config.cookieDomain]) {
    const name = value.trim().replace(/^\./, '').toLowerCase()
    if (name !== '') hosts.add(name)
  }
  const mainApp = parseOrigin(config.mainAppUrl)
  const cookieHosts = new Set(hosts)
  if (mainApp !== undefined) cookieHosts.add(mainApp.hostname.toLowerCase())
  return {
    platformHosts: [...hosts],
    cookieTrustedHosts: [...cookieHosts],
    allowLoopback: !config.secureCookies,
  }
}

/** True when the request method can change server or tenant state. */
export function isMutatingMethod(method: string): boolean {
  return MUTATING_METHODS.has(method.toUpperCase())
}

/** True when `origin` names a source this request may trust. */
function isTrustedSource(origin: URL, view: MutationRequestView, policy: CsrfOriginPolicy): boolean {
  if (isSameHost(origin, view.hosts)) return true
  const hostname = origin.hostname.toLowerCase()
  if (policy.cookieTrustedHosts.includes(hostname)) return true
  if (view.hasSessionCookie) return policy.allowLoopback && LOOPBACK_HOSTNAMES.has(hostname)
  return (
    isPlatformHost(hostname, policy) || (policy.allowLoopback && LOOPBACK_HOSTNAMES.has(hostname))
  )
}

/**
 * Decide whether a mutating request carries a trustworthy source.
 *
 * @param view - request headers, peer address, and cookie presence.
 * @param policy - origins accepted for this deployment.
 * @returns true when the request may proceed.
 */
export function isAllowedMutation(view: MutationRequestView, policy: CsrfOriginPolicy): boolean {
  if (!isMutatingMethod(view.method)) return true

  if (view.origin !== undefined) {
    const origin = parseOrigin(view.origin)
    if (origin === undefined) return false
    return isTrustedSource(origin, view, policy)
  }

  if (view.referer !== undefined) {
    const referer = parseOrigin(view.referer)
    if (referer === undefined) return false
    return isTrustedSource(referer, view, policy)
  }

  // No browser-supplied source. Browsers always send Origin for cross-site
  // mutations, so this is a server-to-server or local tooling call. A cookie
  // is only trusted when the peer itself is local.
  if (!view.hasSessionCookie) return true
  return view.remoteAddress !== undefined && LOOPBACK_ADDRESS.test(view.remoteAddress)
}

/**
 * Register the CSRF guard.
 *
 * The hook must run before the subdomain proxy so mutations forwarded to a
 * tenant DSH are checked as well.
 *
 * @param app - Fastify instance whose routes this guard protects.
 */
export async function csrfGuard(app: FastifyInstance): Promise<void> {
  const policy = buildCsrfOriginPolicy(app.config)

  app.addHook('onRequest', async (request, reply) => {
    if (!isMutatingMethod(request.method)) return

    const forwardedHost = request.headers['x-forwarded-host']
    const hosts = [
      request.headers.host,
      typeof forwardedHost === 'string' ? forwardedHost : Array.isArray(forwardedHost) ? forwardedHost[0] : undefined,
    ].filter((host): host is string => host !== undefined && host !== '')

    const allowed = isAllowedMutation(
      {
        method: request.method,
        origin: request.headers.origin,
        referer: request.headers.referer,
        hosts,
        remoteAddress: request.ip,
        hasSessionCookie: parseCookie(request.headers.cookie, 'sid') !== undefined,
      },
      policy,
    )

    if (allowed) return
    return reply.code(403).send({ error: 'csrf_origin_rejected' })
  })
}
