/**
 * Direct-filesystem {@link UserFs}: the control plane owns the users volume and
 * touches it in-process. This is the `deployMode=local` implementation, and it
 * is also what the per-user file sidecar runs behind its HTTP surface — the
 * sidecar is just a `LocalUserFs` pinned to one user's root.
 * @module dsh-server-login/fs/local-user-fs
 */

import {
  chownSync,
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import { mkdir, writeFile } from 'node:fs/promises'
import { stat } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { dump as dumpYaml, load as loadYaml } from 'js-yaml'
import { PathEscapeError, resolveWithinRoot, safeFilename } from '../web/middleware/fs-guard.js'
import { listInstalledPlugins, type PluginInfo } from './plugins.js'
import { UserFsError, type UserFs } from './user-fs.js'
import { ensureDir, grantUserRootPermissions, handoffPath, homeRoot, listDir, rejectSymlinkEscape, workspaceRoot, type FsEntry } from './workspace.js'

/** Resolve a user id to that user's data root (`<dataRoot>/users/<id>`, or a
 * fixed directory when the sidecar serves exactly one user). */
export type UserRootResolver = (userId: string) => string

/** Map a Node errno onto the wire code the desktop already handles. */
function fsError(err: unknown, onMissing: 'not_found' | 'parent_missing'): never {
  const code = (err as NodeJS.ErrnoException).code
  if (code === 'EEXIST') throw new UserFsError('exists')
  if (code === 'ENOENT' || code === 'ENOTDIR') throw new UserFsError(onMissing)
  throw err
}


function chownRecursiveSync(targetPath: string, uid: number, gid: number): void {
  try {
    chownSync(targetPath, uid, gid)
    const entries = readdirSync(targetPath, { withFileTypes: true })
    for (const entry of entries) {
      const full = join(targetPath, entry.name)
      if (entry.isDirectory()) {
        chownRecursiveSync(full, uid, gid)
      } else {
        try {
          chownSync(full, uid, gid)
        } catch {}
      }
    }
  } catch {}
}

const COPYMONSTER_BUNDLE = '@deepseek-ai/dsh-copymonster'
const WEB_APP_BUNDLE = '@deepseek-ai/dsh-web-app'

/** Shared workspace sandbox the tenant DSH writes under, unless configured. */
const DEFAULT_COPYMONSTER_DATA_DIR = '/var/copymonster/data'

/**
 * Credential store the platform operator configures once, read at provisioning
 * so every tenant reaches the same provider. The file holds `refs` (plaintext
 * `NAME: value` pairs the harness resolves `apiKeyEnv` from) and `records`
 * (per-tenant grants) — only `refs` are shared.
 */
const DEFAULT_GLOBAL_CREDENTIALS = '/root/.dsh/.credentials.yaml'

/** Shape of a harness credential store, as far as provisioning reads it. */
interface CredentialStore {
  version?: number
  refs?: Record<string, string>
  records?: Record<string, unknown>
}

/**
 * Merge the operator's provider credentials into one tenant's store.
 *
 * The operator's `refs` win: the Models surface is admin-only, so a tenant
 * cannot choose a provider, and a stale per-tenant key would silently override
 * the one the admin configured. The tenant's own `records` are preserved.
 * @param home - the tenant's DSH home directory.
 */
function seedGlobalCredentials(home: string): void {
  const source = process.env.DSH_SERVER_LOGIN_GLOBAL_CREDENTIALS ?? DEFAULT_GLOBAL_CREDENTIALS
  if (!existsSync(source)) return

  let shared: CredentialStore
  try {
    const parsed: unknown = loadYaml(readFileSync(source, 'utf8'))
    if (parsed === null || typeof parsed !== 'object') return
    shared = parsed as CredentialStore
  } catch (error) {
    warnProvisioning('read global credentials', source, error)
    return
  }

  const refs = shared.refs
  if (refs === undefined || typeof refs !== 'object') return

  const target = join(home, '.credentials.yaml')
  let tenant: CredentialStore = {}
  if (existsSync(target)) {
    try {
      const parsed: unknown = loadYaml(readFileSync(target, 'utf8'))
      if (parsed !== null && typeof parsed === 'object') tenant = parsed as CredentialStore
    } catch (error) {
      warnProvisioning('read tenant credentials', target, error)
      return
    }
  }

  const merged: CredentialStore = {
    version: tenant.version ?? shared.version ?? 1,
    refs: { ...(tenant.refs ?? {}), ...refs },
    ...(tenant.records === undefined ? {} : { records: tenant.records }),
  }

  try {
    writeFileSync(target, dumpYaml(merged, { lineWidth: 120 }), { mode: 0o600 })
  } catch (error) {
    warnProvisioning('write tenant credentials', target, error)
  }
}

/**
 * Prepare the shared workspace sandbox for tenant uids.
 *
 * The sandbox lives at `<dir>/<tenantId>/<userId>/workspaces` and is created by
 * the tenant's own DSH process, which runs as that tenant's uid, while the
 * parent directory is created by the root control plane. Without a writable
 * parent the tenant fails with `EACCES` on its first workspace. The sticky
 * world-writable mode gives the directory `/tmp` semantics: every tenant
 * creates its own entry and the sticky bit stops one tenant from removing
 * another's. Tenant ids are UUIDs, so a tenant cannot address another's entry.
 * @param dataRoot - the shared sandbox root to prepare.
 */
function ensureSharedSandboxRoot(dataRoot: string): void {
  mkdirSync(dataRoot, { recursive: true, mode: 0o1777 })
  chmodSync(dataRoot, 0o1777)
  for (const entry of readdirSync(dataRoot, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue
    try {
      chmodSync(join(dataRoot, entry.name), 0o1777)
    } catch (error) {
      warnProvisioning('prepare shared sandbox', join(dataRoot, entry.name), error)
    }
  }
}

/** Log one provisioning failure that would otherwise pass silently. */
function warnProvisioning(step: string, target: string, error: unknown): void {
  const detail = error instanceof Error ? error.message : String(error)
  console.warn(`[provisioning] ${step} failed for ${target}: ${detail}`)
}

/** This package's root, used to expose `dsh-server-login/runtime` to tenants. */
const PACKAGE_ROOT = fileURLToPath(new URL('../../', import.meta.url))

/**
 * Expose a package to a tenant profile by placing a link in the user root's
 * `node_modules`, which Node walks up to from `<home>/profiles/<name>/`.
 * @param root - the tenant root directory.
 * @param name - the bare package name to link.
 * @param target - the package directory the link points at.
 */
function linkPackageIntoUserRoot(root: string, name: string, target: string): void {
  const modulesDir = join(root, 'node_modules')
  ensureDir(modulesDir)
  const link = join(modulesDir, name)
  if (existsSync(link)) return
  try {
    symlinkSync(target, link, 'dir')
  } catch (error) {
    // Without this link the tenant cannot resolve `dsh-server-login/runtime`
    // and its child fails to boot, so the failure must reach the journal.
    warnProvisioning('link package', link, error)
  }
}

/** Restrict a file to its owner when the recursive permission pass widened it. */
function restrictToOwner(targetPath: string): void {
  try {
    if (existsSync(targetPath)) chmodSync(targetPath, 0o600)
  } catch {}
}

function ensureCopyMonsterBundle(packageJsonPath: string): void {
  try {
    if (!existsSync(packageJsonPath)) return
    const raw = readFileSync(packageJsonPath, 'utf8')
    const manifest = JSON.parse(raw)
    const profile = manifest?.dsh?.profile
    if (profile === undefined || !Array.isArray(profile.bundles)) return
    if (profile.bundles.includes(COPYMONSTER_BUNDLE)) return
    const bundles = [...profile.bundles]
    const anchorIdx = bundles.indexOf(WEB_APP_BUNDLE)
    if (anchorIdx === -1) {
      bundles.push(COPYMONSTER_BUNDLE)
    } else {
      bundles.splice(anchorIdx + 1, 0, COPYMONSTER_BUNDLE)
    }
    manifest.dsh.profile.bundles = bundles
    writeFileSync(packageJsonPath, `${JSON.stringify(manifest, undefined, 2)}\n`)
  } catch (error) {
    warnProvisioning('ensure CopyMonster bundle', packageJsonPath, error)
  }
}

export class LocalUserFs implements UserFs {
  constructor(private readonly rootFor: UserRootResolver) {}

  async initUserRoot(userId: string, uid?: number): Promise<void> {
    const root = this.rootFor(userId)
    ensureDir(homeRoot(root))
    ensureDir(workspaceRoot(root))
    ensureDir(join(workspaceRoot(root), 'workspace'))

    // The workspace sandbox sits outside this per-user root, so the tenant uid
    // needs the shared root prepared before its DSH can create a workspace.
    if (typeof process.getuid === 'function' && process.getuid() === 0) {
      try {
        ensureSharedSandboxRoot(process.env.COPYMONSTER_DATA_DIR ?? DEFAULT_COPYMONSTER_DATA_DIR)
      } catch {}
    }

    // Provision the resident web profile so the per-user DSH can boot without
    // missing node_modules. Check known template profile locations.
    const candidateTemplates = [
      '/root/.dsh/profiles/web',
      '/var/lib/copymonster-dsh/profiles/web',
      join(homedir(), '.dsh', 'profiles', 'web'),
    ]
    const templateProfile = candidateTemplates.find((p) => existsSync(p))
    const userProfile = join(homeRoot(root), 'profiles', 'web')

    if (templateProfile && !existsSync(userProfile)) {
      cpSync(templateProfile, userProfile, {
        recursive: true,
        filter: (src) => src !== join(templateProfile, 'node_modules'),
      })
    }

    // Share the template's installed dependencies rather than copying them: the
    // profile's own links resolve against the template tree, and every tenant
    // reads the same modules without a per-tenant install.
    const templateModules = templateProfile === undefined ? undefined : join(templateProfile, 'node_modules')
    const userModules = join(userProfile, 'node_modules')
    if (templateModules !== undefined && existsSync(templateModules) && !existsSync(userModules)) {
      try {
        symlinkSync(realpathSync(templateModules), userModules, 'dir')
      } catch (error) {
        warnProvisioning('share template node_modules', userModules, error)
      }
    }

    // The supervisor patch mounts `dsh-server-login/runtime` in every child, and
    // Node resolves it by walking up from `<home>/profiles/<profile>/`.
    linkPackageIntoUserRoot(root, 'dsh-server-login', PACKAGE_ROOT)

    // Always ensure the tenant's web profile includes the CopyMonster bundle
    const userPackageJson = join(userProfile, 'package.json')
    ensureCopyMonsterBundle(userPackageJson)

    // The operator configures the provider once; every tenant consumes it.
    seedGlobalCredentials(homeRoot(root))

    // The roots were created by the (possibly root) control plane; the DSH child
    // runs as the user's own uid and must be able to traverse + write them.
    // Recursively chown the entire tree so the tenant has full permission over all files.
    if (uid !== undefined && typeof process.getuid === 'function' && process.getuid() === 0) {
      try {
        grantUserRootPermissions(root, uid)
        // The recursive pass above grants group/other read so the tenant's own
        // DSH can traverse what the control plane created. The per-user root,
        // its home and its workspace stay owner-only: the tenant owns them and
        // runs as this uid, so 0700 is enough for it and stops another tenant
        // from reading this one's sessions, credentials and workspace files.
        chmodSync(root, 0o700)
        chmodSync(homeRoot(root), 0o700)
        chmodSync(workspaceRoot(root), 0o700)
      } catch (error) {
        warnProvisioning('grant user root permissions', root, error)
        chownRecursiveSync(root, uid, uid)
        // The recursive pass grants group/other read; credential stores must stay
        // owner-only or the credentials plugin refuses to start.
        restrictToOwner(join(homeRoot(root), '.credentials.yaml'))
      }
    }
  }

  resolvePath(userId: string, relPath: string): string {
    return this.resolve(userId, relPath)
  }

  async listDir(userId: string, relPath: string): Promise<FsEntry[]> {
    const abs = this.resolve(userId, relPath)
    await this.assertNoLinks(userId, abs)
    try {
      return await listDir(abs)
    } catch (err) {
      fsError(err, 'not_found')
    }
  }

  async mkdir(userId: string, relPath: string): Promise<void> {
    const abs = this.resolve(userId, relPath)
    await this.assertNoLinks(userId, abs)
    try {
      await mkdir(abs)
    } catch (err) {
      fsError(err, 'parent_missing')
    }
  }

  async createEntry(userId: string, relPath: string, name: string, type: 'file' | 'dir'): Promise<string> {
    const dirAbs = this.resolve(userId, relPath)
    const filename = this.sanitize(name)
    const target = join(dirAbs, filename)
    await this.assertNoLinks(userId, target)
    try {
      if (type === 'dir') await mkdir(target)
      else await writeFile(target, '')
    } catch (err) {
      fsError(err, 'parent_missing')
    }
    return filename
  }

  async upload(userId: string, relPath: string, name: string, data: Buffer): Promise<string> {
    const dirAbs = this.resolve(userId, relPath)
    const filename = this.sanitize(name)
    const target = join(dirAbs, filename)
    await this.assertNoLinks(userId, target)
    try {
      await writeFile(target, data)
    } catch (err) {
      fsError(err, 'parent_missing')
    }
    return filename
  }

  async isDirectory(userId: string, relPath: string): Promise<boolean> {
    const abs = this.resolve(userId, relPath)
    await this.assertNoLinks(userId, abs)
    try {
      return (await stat(abs)).isDirectory()
    } catch (err) {
      fsError(err, 'not_found')
    }
  }

  async listInstalledPlugins(userId: string): Promise<PluginInfo[]> {
    return listInstalledPlugins(this.rootFor(userId))
  }

  async writeHandoff(userId: string, content: string): Promise<void> {
    const root = this.rootFor(userId)
    ensureDir(root)
    await writeFile(handoffPath(root), content)
  }

  /** Resolve a workspace-relative path, self-healing the root the way the
   * pre-seam routes did (every one of them called `ensureWorkspaceRoot` first). */
  private resolve(userId: string, relPath: string): string {
    const ws = workspaceRoot(this.rootFor(userId))
    ensureDir(ws)
    try {
      return resolveWithinRoot(ws, relPath)
    } catch (err) {
      if (err instanceof PathEscapeError) throw new UserFsError('bad_path')
      throw err
    }
  }

  /** The lexical guard above is prefix-only and blind to links planted inside
   * the workspace, so every operation re-walks its final absolute path (the
   * write target for upload/createEntry) and rejects any symlink component —
   * `writeFile`/`mkdir` would otherwise follow it outside the root with this
   * process's privileges. Surfaces as the usual `bad_path` wire code. */
  private async assertNoLinks(userId: string, abs: string): Promise<void> {
    try {
      await rejectSymlinkEscape(workspaceRoot(this.rootFor(userId)), abs)
    } catch (err) {
      if (err instanceof PathEscapeError) throw new UserFsError('bad_path')
      throw err
    }
  }

  private sanitize(name: string): string {
    try {
      return safeFilename(name)
    } catch (err) {
      if (err instanceof PathEscapeError) throw new UserFsError('bad_name')
      throw err
    }
  }
}
