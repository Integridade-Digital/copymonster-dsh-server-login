/**
 * Backend abstraction for per-user DSH lifecycle (docs/k8s.md §5.2).
 *
 * `local` spawns child processes (setuid/iptables) via `LocalSpawner`; `k8s`
 * creates/deletes per-user DSH Pods via the K8s API (`K8sSpawner`). The route
 * layer depends only on this interface, so both backends coexist behind the
 * same API. Shared instance/status types live here so neither backend owns
 * them.
 * @module dsh-server-login/supervisor/spawner
 */

export type InstanceStatus = 'starting' | 'running' | 'crashed' | 'stopped'
export type InstanceRole = 'main' | 'watchdog'

/** A tracked DSH instance (main or watchdog). `port`/`pid` are local-only. */
export interface Instance {
  id: string
  userId: string
  role: InstanceRole
  folder: string
  port?: number
  status: InstanceStatus
  pid?: number
  exitCode?: number
  lastError?: string
  /** Rendered cordis patch **content**, not a path — see {@link Spawner.launch}. */
  patch?: string
  /** Parsed from the child's readiness line for the browser-auth exchange. */
  authToken?: string
  /**
   * Transient systemd scope holding this child, when resource limits are on.
   * Stopping the scope is what actually ends the tenant: killing the
   * `systemd-run` wrapper leaves the scope's process alive.
   */
  scopeUnit?: string
}

/**
 * A tenant whose Linux account exists with a different identity than the
 * database records. Launching it would give one tenant another tenant's files,
 * so provisioning stops and reports the mismatch instead of reusing the account.
 */
export class ProvisioningConflict extends Error {
  constructor(
    /** Tenant whose account is inconsistent. */
    readonly tenant: string,
    /** What disagreed: the account's uid, name, or group id. */
    readonly mismatch: 'uid' | 'name' | 'gid',
    /** Value found on the host. */
    readonly actual: string | number | undefined,
    /** Value the database expects. */
    readonly expected: string | number,
  ) {
    super(`provisioning conflict for ${tenant}: ${mismatch} is ${String(actual)}, expected ${String(expected)}`)
    this.name = 'ProvisioningConflict'
  }
}

/** A provisioning step failed for a reason other than an identity mismatch. */
export class ProvisioningError extends Error {
  constructor(
    /** Tenant being provisioned. */
    readonly tenant: string,
    message: string,
  ) {
    super(message)
    this.name = 'ProvisioningError'
  }
}

/** Tenant lifecycle as reported by `GET /api/dsh/status`. */
export type TenantState = 'stopped' | 'starting' | 'running' | 'failed'

/** Thrown when a user already has a running main DSH. */
export class AlreadyRunningError extends Error {
  constructor(userId: string) {
    super(`user ${userId} already has a running DSH`)
    this.name = 'AlreadyRunningError'
  }
}

/** A user's main + watchdog pair. */
export interface UserStatus {
  main?: Instance
  watchdog?: Instance
}

/** The host:port the proxy forwards a user's DSH traffic to. */
export interface Endpoint {
  host: string
  port: number
  /** One-time launch token for the DSH browser-auth cookie exchange. */
  authToken?: string
}

/** A main DSH Pod as observed by the k8s backend (for reconcile + the watch). */
export interface LivePod {
  name: string
  userId: string
  running: boolean
  crashed: boolean
}

/**
 * The lifecycle seam the route layer delegates to.
 *
 * `endpointFor` is spawner-specific: local → `127.0.0.1:<port>`, k8s → the
 * per-user Headless Service DNS (docs/k8s.md §5.4).
 *
 * `launch` takes the rendered cordis patch as **content**, not a path: under
 * k8s the control plane holds no user volume, so it can neither write the patch
 * nor read it back. `LocalSpawner` materializes it to a file (it does have the
 * volume) and `K8sSpawner` puts it straight into a ConfigMap.
 */
export interface Spawner {
  launch(userId: string, folder: string, patch?: string): Promise<Instance>
  restartMain(userId: string): Promise<Instance | undefined>
  spawnWatchdog(userId: string): Promise<Instance | undefined>
  status(userId: string): Promise<UserStatus>
  endpointFor(userId: string): Promise<Endpoint | undefined>
  /**
   * Lifecycle state of the tenant's instance. A backend that cannot report it
   * omits the method and the proxy assumes `stopped`.
   */
  lifecycle?(userId: string): Promise<{ state: TenantState; lastError?: string }>
  stop(userId: string): Promise<void>
  teardown(): Promise<void>
  /** Make the user's file sidecar exist and be ready (k8s). No-op under local,
   * where the control plane touches the volume in-process. */
  ensureFileService(userId: string): Promise<void>
  /**
   * Create the tenant's Linux account, without launching it. Backends without
   * OS accounts omit the method and the exchange skips the check.
   */
  ensureLinuxAccount?(userId: string): Promise<void>
  registerWebSocket?(userId: string, socket: any): void
  touchActivity?(userId: string): void
}
