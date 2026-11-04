/**
 * Per-user DSH supervisor: a resident main DSH plus an **on-demand** watchdog.
 *
 * The watchdog is not spawned at launch; it is pulled up once when the main
 * crashes (to repair) or when a post-restart command must be executed. This
 * keeps the steady-state footprint at one process per active user while still
 * providing crash repair + command handoff. The watchdog's agent-level
 * repair/session-resume is harness-internal and deferred to real-harness
 * integration (see docs/blueprint.md §4).
 * @module dsh-server-login/supervisor/orchestrator
 */

import { spawn, type ChildProcess, type StdioOptions } from 'node:child_process'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { chmodSync, chownSync, existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { ServerConfig } from '../config.js'
import type { User } from '../db/types.js'
import { grantUserRootPermissions, handoffPath, homeRoot, userRoot, workspaceRoot } from '../fs/workspace.js'
import { createPortGuard, type PortGuard } from './firewall.js'
import { findFreePort, scrubEnv, sanitizePath, resolveBinary } from './spawn.js'
import {
  AlreadyRunningError,
  type Endpoint,
  type Instance,
  type InstanceRole,
  type InstanceStatus,
  type Spawner,
  type UserStatus,
} from './spawner.js'

// Re-exported so existing importers (routes) keep resolving from this module.
export { AlreadyRunningError, type Instance, type InstanceRole, type InstanceStatus, type UserStatus }

/** Task given to the one-shot headless watchdog so it doesn't error on a
 * missing task; executes any post-restart command from the handoff path. */
const WATCHDOG_TASK = 'Read DSH_SERVER_LOGIN_HANDOFF_PATH. If it contains a JSON {"command": ...}, run that command. Then exit.'

/** Platform billing credentials the tenant web process needs to serve checkout. */
const STRIPE_ENV_KEYS = ['STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET'] as const

/**
 * Local backend: owns the lifecycle of per-user DSH process pairs via
 * child_process. State is in-memory. Implements {@link Spawner}.
 */
export class LocalSpawner implements Spawner {
  private readonly mains = new Map<string, Instance>()
  private readonly watchdogs = new Map<string, Instance>()
  private readonly children = new Map<string, ChildProcess>()
  private readonly restartTimers = new Map<string, NodeJS.Timeout>()
  private readonly activeWsSockets = new Map<string, Set<any>>()
  private readonly idleTimers = new Map<string, NodeJS.Timeout>()
  private readonly IDLE_TIMEOUT_MS = 30 * 60 * 1000 // 30 minutes idle timeout

  private readonly portGuard: PortGuard | undefined

  constructor(
    private readonly config: ServerConfig,
    /** Resolve the user's own API key (decrypted); null = user has none. */
    private readonly resolveApiKey: (userId: string) => Promise<string | null>,
    /** Resolve the user's assigned Linux uid (falls back to hash when unset). */
    private readonly resolveUid: (userId: string) => Promise<number>,
    /** Database adapter: usernames for Linux provisioning, plan limits for scopes. */
    private readonly db: { findUserById(id: string): Promise<User | undefined> },
  ) {
    this.portGuard = createPortGuard(config.portGuard)
  }

  /** Ensure the Linux user/group for the tenant's UID exists (idempotent). */
  private async provisionLinuxUser(userId: string): Promise<void> {
    const uid = await this.resolveUid(userId)
    const user = await this.db.findUserById(userId)
    const username = user?.username ?? `user-${uid}`

    try {
      execFileSync('id', ['-u', String(uid)], { stdio: 'ignore' })
      return // already exists
    } catch {
      // user doesn't exist, create it
    }

    try {
      execFileSync('groupadd', ['-g', String(uid), username], { stdio: 'ignore' })
    } catch {
      // group might already exist
    }

    try {
      execFileSync('useradd', [
        '-u', String(uid),
        '-g', String(uid),
        '-d', userRoot(this.config.dataRoot, userId),
        '-M',
        '-s', '/bin/bash',
        username
      ], { stdio: 'ignore' })
    } catch (e) {
      // race condition: another process created it
      try {
        execFileSync('id', ['-u', String(uid)], { stdio: 'ignore' })
      } catch {
        throw e
      }
    }
  }

  /** Spawn the resident main DSH for a user (watchdog is pulled up on demand). */
  async launch(userId: string, folder: string, patch?: string): Promise<Instance> {
    if (this.mains.has(userId)) throw new AlreadyRunningError(userId)
    const inst = await this.spawnInstance(userId, 'main', folder, patch)
    this.scheduleIdleShutdown(userId)
    return inst
  }

  /** Stop the current main (clean) and respawn it with the same folder/patch. */
  async restartMain(userId: string): Promise<Instance | undefined> {
    const current = this.mains.get(userId)
    if (current === undefined) return undefined
    this.killInstance(userId, current)
    return await this.spawnInstance(userId, 'main', current.folder, current.patch)
  }

  /** Spawn a one-shot watchdog for the user's current main (repair / execute). */
  async spawnWatchdog(userId: string): Promise<Instance | undefined> {
    if (!this.config.enablePatch) return undefined // watchdog needs the runtime patch
    if (this.watchdogs.has(userId)) return this.watchdogs.get(userId)
    const main = this.mains.get(userId)
    if (main === undefined) return undefined
    return await this.spawnInstance(userId, 'watchdog', main.folder, main.patch)
  }

  /** Current main + watchdog for a user. */
  async status(userId: string): Promise<UserStatus> {
    return { main: this.mains.get(userId), watchdog: this.watchdogs.get(userId) }
  }

  /** Endpoint the proxy forwards to (local → the running main's loopback port). */
  async endpointFor(userId: string): Promise<Endpoint | undefined> {
    const instance = this.mains.get(userId)
    if (instance === undefined || instance.status !== 'running' || instance.port === undefined) return undefined
    return { host: '127.0.0.1', port: instance.port }
  }

  /** Stop both processes for a user (cancelling any pending restart). */
  async stop(userId: string): Promise<void> {
    const timer = this.restartTimers.get(userId)
    if (timer !== undefined) {
      clearTimeout(timer)
      this.restartTimers.delete(userId)
    }
    const main = this.mains.get(userId)
    const watchdog = this.watchdogs.get(userId)
    if (main !== undefined) this.killInstance(userId, main)
    if (watchdog !== undefined) this.killInstance(userId, watchdog)
    this.mains.delete(userId)
    this.watchdogs.delete(userId)
    this.touchActivity(userId)
    this.activeWsSockets.delete(userId)
  }

  touchActivity(userId: string): void {
    const timer = this.idleTimers.get(userId)
    if (timer !== undefined) {
      clearTimeout(timer)
      this.idleTimers.delete(userId)
    }
  }

  registerWebSocket(userId: string, socket: any): void {
    this.touchActivity(userId)
    let set = this.activeWsSockets.get(userId)
    if (!set) {
      set = new Set()
      this.activeWsSockets.set(userId, set)
    }
    set.add(socket)

    const cleanup = () => {
      set?.delete(socket)
      if ((set?.size ?? 0) === 0) {
        this.scheduleIdleShutdown(userId)
      }
    }
    socket.once('close', cleanup)
    socket.once('end', cleanup)
    socket.once('error', cleanup)
  }

  private scheduleIdleShutdown(userId: string): void {
    this.touchActivity(userId)
    const timer = setTimeout(async () => {
      const activeCount = this.activeWsSockets.get(userId)?.size ?? 0
      if (activeCount === 0 && this.mains.has(userId)) {
        await this.stop(userId).catch(() => {})
      }
    }, this.IDLE_TIMEOUT_MS)
    this.idleTimers.set(userId, timer)
  }

  /** Stop every tracked process on shutdown. */
  async teardown(): Promise<void> {
    for (const userId of [...this.mains.keys(), ...this.watchdogs.keys()]) await this.stop(userId)
  }

  /** No-op: local mode has no sidecar — the control plane owns the volume. */
  async ensureFileService(_userId: string): Promise<void> {}

  private handoffPath(userId: string): string {
    return handoffPath(userRoot(this.config.dataRoot, userId))
  }

  /** Materialize the rendered patch so the dsh CLI can `--patch <file>` it.
   * Per role, so a watchdog spawning alongside its main never races the file. */
  private writePatch(userId: string, role: InstanceRole, patch: string): string {
    const dir = join(userRoot(this.config.dataRoot, userId), 'patches')
    mkdirSync(dir, { recursive: true, mode: 0o755 })
    const path = join(dir, `${role}.yml`)
    writeFileSync(path, patch, { mode: 0o644 })
    if (this.config.isolationMode === 'account' && typeof process.getuid === 'function' && process.getuid() === 0) {
      void this.resolveUid(userId).then((uid) => {
        try {
          chownSync(dir, uid, uid)
          chownSync(path, uid, uid)
        } catch {}
      }).catch(() => {})
    }
    return path
  }

  private async baseEnv(userId: string): Promise<Record<string, string>> {
    const root = userRoot(this.config.dataRoot, userId)
    const home = homeRoot(root)
    const workspace = workspaceRoot(root)
    const apiKey = await this.resolveApiKey(userId)
    const scrubbed = scrubEnv(process.env)
    return {
      ...scrubbed,
      PATH: sanitizePath(scrubbed.PATH ?? process.env.PATH),
      // HOME drives the child's directory picker default (homedir()); point it
      // at the user's workspace so their folders show, not DSH's internal home.
      HOME: workspace,
      // DSH's own state (profiles/sessions/credentials) stays in `home`.
      DSH_HOME: home,
      // Each user's own key; omit entirely when unset so the harness reports
      // "no key" instead of a header-hostile value.
      ...(apiKey !== null ? { DEEPSEEK_API_KEY: apiKey } : {}),
    }
  }

  private async spawnInstance(userId: string, role: InstanceRole, folder: string, patch?: string): Promise<Instance> {
    const isMain = role === 'main'
    const port = isMain ? await findFreePort() : undefined
    const instance: Instance = {
      id: randomUUID(),
      userId,
      role,
      folder,
      port,
      status: 'starting',
      patch,
    }
    const map = role === 'main' ? this.mains : this.watchdogs
    map.set(userId, instance)

    const [command = 'dsh', ...args] = this.config.dshCommand
    const launchArgs = ['--profile', role === 'main' ? 'web' : 'headless']
    // --patch is a launcher flag and must precede any app/inner args (--host/--port
    // for web, the task string for headless): dsh forwards the first unrecognized
    // token onward, so a trailing --patch reaches the app as an unknown option.
    // Off by default so the child boots even on older dsh versions.
    if (this.config.enablePatch && patch !== undefined) {
      launchArgs.push('--patch', this.writePatch(userId, role, patch))
    }
    if (role === 'main') {
      launchArgs.push('--host', '127.0.0.1', '--port', String(port))
    } else {
      launchArgs.push(WATCHDOG_TASK)
    }

    const env: Record<string, string> = {
      ...(await this.baseEnv(userId)),
      DSH_SERVER_LOGIN_ROLE: role,
      DSH_SERVER_LOGIN_BASE_DOMAIN: this.config.baseDomain,
      DSH_SERVER_LOGIN_HANDOFF_PATH: this.handoffPath(userId), // both roles: main writes, watchdog reads
    }
    if (isMain) {
      env.DSH_SERVER_LOGIN_PORT = String(port)
      // Billing is served by the tenant's web process, which the browser
      // reaches on the tenant subdomain, so the checkout and portal routes need
      // the platform's Stripe credentials. The headless watchdog serves no
      // browser routes and never receives them.
      for (const key of STRIPE_ENV_KEYS) {
        const value = process.env[key]
        if (value !== undefined && value !== '') env[key] = value
      }
    }

    const child = await this.spawnAsUser(userId, role, command, [...args, ...launchArgs], { cwd: folder, env })
    if (this.config.resourceScopes) instance.scopeUnit = this.scopeUnitName(userId, role)
    this.trackChild(userId, instance, child)
    return instance
  }

  /** Spawn the child, optionally through the account-level setuid wrapper. */
  private async spawnAsUser(
    userId: string,
    role: InstanceRole,
    command: string,
    args: string[],
    options: { cwd: string; env: Record<string, string> },
  ): Promise<ChildProcess> {
    const stdio: StdioOptions = ['ignore', 'pipe', 'pipe']
    const env = {
      ...options.env,
      PATH: sanitizePath(options.env.PATH ?? process.env.PATH),
    }
    const resolvedOptions = { ...options, env, stdio }

    // Ensure working directory exists before spawning
    if (resolvedOptions.cwd) {
      mkdirSync(resolvedOptions.cwd, { recursive: true, mode: 0o755 })
    }

    if (this.config.isolationMode !== 'account') {
      const resolvedCommand = resolveBinary(command, env.PATH)
      return spawn(resolvedCommand, args, resolvedOptions)
    }
    // Ensure the Linux user exists before attempting setpriv
    await this.provisionLinuxUser(userId)
    const uid = await this.resolveUid(userId)
    if (typeof process.getuid === 'function' && process.getuid() === 0) {
      try {
        const root = userRoot(this.config.dataRoot, userId)
        // The recursive grant widens the whole tree, so it runs first and the
        // restrictive modes come after it; the reverse order reopened the
        // owner-only directories on every spawn.
        grantUserRootPermissions(root, uid)
        // Traversal without listing for the shared parents: a tenant uid must
        // reach its own root, and must not enumerate the other tenants. The
        // per-user root, its home and its workspace stay owner-only.
        chmodSync(this.config.dataRoot, 0o711)
        chmodSync(join(this.config.dataRoot, 'users'), 0o711)
        chmodSync(root, 0o700)
        chmodSync(homeRoot(root), 0o700)
        chmodSync(workspaceRoot(root), 0o700)
      } catch (error) {
        // A permission failure here leaves the tenant unable to read its own
        // root, which surfaces later as an opaque EACCES inside the child.
        const detail = error instanceof Error ? error.message : String(error)
        console.warn(`[provisioning] prepare tenant root failed for ${userId}: ${detail}`)
      }
    }
    const resolvedCommand = resolveBinary(command, env.PATH)
    const prefix = this.config.spawnAsUserCommand.map((part) =>
      part.replaceAll('{UID}', String(uid)).replaceAll('{GID}', String(uid)),
    )
    let [asCommand = 'setpriv', ...asArgs] = prefix
    asCommand = resolveBinary(asCommand, env.PATH)

    // A configured resource limit wraps the whole privilege-drop in a transient
    // systemd scope. The scope runs as the orchestrator's own user: systemd
    // cannot set `SupplementaryGroups` on a scope unit, and inheriting the
    // caller's groups would leave the tenant inside group root, which both
    // denies it /root and hands it group-root access.
    const scopeArgs = await this.resourceScopeArgs(userId, role)
    if (scopeArgs !== undefined) {
      const runner = resolveBinary('systemd-run', env.PATH)
      return spawn(runner, [...scopeArgs, asCommand, ...asArgs, resolvedCommand, ...args], resolvedOptions)
    }

    return spawn(asCommand, [...asArgs, resolvedCommand, ...args], resolvedOptions)
  }

  /**
   * Build the `systemd-run --scope` prefix that caps one tenant's resources.
   *
   * The plan-derived values stored on the user row win; the global config is
   * the fallback for a tenant whose plan is unknown. Only the limits are set
   * here: the caller composes this prefix with the setpriv prefix, so the
   * scope never changes the child's identity or groups. `--collect` removes
   * the transient unit when the child exits.
   * @param userId - the tenant whose stored plan limits apply.
   * @returns the argv prefix, or undefined when no limit is configured.
   */
  /**
   * Name the transient scope after the tenant and role.
   * @param userId - tenant the scope belongs to.
   * @param role - main or watchdog, so a restart never collides with a live scope.
   * @returns a systemd-safe unit name.
   */
  private scopeUnitName(userId: string, role: InstanceRole): string {
    const safe = userId.replace(/[^A-Za-z0-9_.-]/g, '-').slice(0, 48)
    return `copymonster-${role}-${safe}.scope`
  }

  private async resourceScopeArgs(userId: string, role: InstanceRole): Promise<string[] | undefined> {
    if (!this.config.resourceScopes) return undefined
    const user = await this.db.findUserById(userId)
    const memoryMax = user?.memory_max ?? this.config.memoryMax
    const cpuQuota = user?.cpu_quota ?? this.config.cpuQuota
    const tasksMax = user?.tasks_max ?? this.config.tasksMax
    if (memoryMax == null && cpuQuota == null && tasksMax == null) return undefined
    const args = ['--scope', '--quiet', '--collect', `--unit=${this.scopeUnitName(userId, role)}`]
    if (memoryMax !== undefined) args.push('-p', `MemoryMax=${memoryMax}`)
    if (cpuQuota !== undefined) args.push('-p', `CPUQuota=${cpuQuota}`)
    if (tasksMax !== undefined) args.push('-p', `TasksMax=${tasksMax}`)
    args.push('--')
    return args
  }

  private trackChild(userId: string, instance: Instance, child: ChildProcess): void {
    this.children.set(instance.id, child)
    child.on('spawn', () => {
      instance.status = 'running'
      instance.pid = child.pid ?? undefined
      if (instance.role === 'main' && instance.port !== undefined && this.portGuard !== undefined) {
        try {
          this.portGuard.install(instance.port)
        } catch (error) {
          // Fail closed: without the port guard a co-tenant could reach this
          // DSH's loopback RPC directly. Kill the just-spawned child and mark
          // the instance crashed rather than serve unguarded.
          instance.status = 'crashed'
          instance.lastError = error instanceof Error ? error.message : String(error)
          child.kill('SIGKILL')
        }
      }
    })
    child.stdout?.pipe(process.stdout)
    let stderrTail = ''
    child.stderr?.on('data', (chunk: Buffer) => {
      stderrTail = (stderrTail + chunk.toString()).slice(-2048)
      // Also surface the child's stderr on the orchestrator's own stderr so a
      // boot crash is visible in journald instead of only in lastError.
      process.stderr.write(`[dsh-child ${instance.role}] ${chunk.toString()}`)
    })
    child.on('error', (err) => {
      instance.status = 'crashed'
      instance.lastError = err.message
      this.children.delete(instance.id)
      process.stderr.write(`[dsh-child ${instance.role}] spawn error: ${err.message}\n`)
    })
    child.on('exit', (code) => {
      instance.exitCode = code ?? undefined
      this.children.delete(instance.id)
      // Release the loopback port guard as soon as the main's process is gone
      // (explicit stop, restart, and crash all funnel through this handler).
      if (instance.role === 'main' && instance.port !== undefined) {
        this.portGuard?.remove(instance.port)
      }
      const map = instance.role === 'main' ? this.mains : this.watchdogs
      // Only act if this instance is still the current one (avoid a stale
      // exit handler touching a freshly restarted instance).
      if (map.get(userId)?.id !== instance.id) return
      if (instance.status === 'stopped') {
        map.delete(userId)
        return
      }
      // A one-shot watchdog that finished cleanly is not restarted.
      if (instance.role === 'watchdog' && code === 0) {
        instance.status = 'stopped'
        map.delete(userId)
        return
      }
      instance.status = 'crashed'
      instance.lastError = stderrTail.slice(-500) || undefined
      if (instance.role === 'main') {
        void this.spawnWatchdog(userId)
        this.scheduleRestart(userId, instance)
      } else {
        map.delete(userId)
      }
    })
  }

  private scheduleRestart(userId: string, instance: Instance): void {
    const timer = setTimeout(() => {
      this.restartTimers.delete(userId)
      void this.spawnInstance(userId, instance.role, instance.folder, instance.patch)
    }, this.config.restartBackoffMs)
    timer.unref()
    this.restartTimers.set(userId, timer)
  }

  private killInstance(userId: string, instance: Instance): void {
    instance.status = 'stopped'
    // With resource scopes the tenant lives inside a transient unit, and
    // killing the `systemd-run` wrapper does not end it. `cgroup.kill` empties
    // the delegated subtree synchronously; `systemctl stop` would block here
    // because systemd is already stopping this service.
    if (instance.scopeUnit !== undefined) {
      let killed = false
      for (const dir of [`/sys/fs/cgroup/system.slice/${instance.scopeUnit}`, `/sys/fs/cgroup/${instance.scopeUnit}`]) {
        try {
          writeFileSync(join(dir, 'cgroup.kill'), '1')
          killed = true
          break
        } catch {}
      }
      if (!killed) {
        try {
          execFileSync('systemctl', ['stop', '--no-block', instance.scopeUnit], { stdio: 'ignore', timeout: 5_000 })
        } catch {}
      }
    }
    const child = this.children.get(instance.id)
    if (child === undefined) return
    child.kill('SIGTERM')
    const killer = setTimeout(() => {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL')
    }, 5000)
    killer.unref()
  }
}
