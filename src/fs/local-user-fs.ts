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
  } catch {}
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
  } catch {}
}

export class LocalUserFs implements UserFs {
  constructor(private readonly rootFor: UserRootResolver) {}

  async initUserRoot(userId: string, uid?: number): Promise<void> {
    const root = this.rootFor(userId)
    ensureDir(homeRoot(root))
    ensureDir(workspaceRoot(root))
    ensureDir(join(workspaceRoot(root), 'workspace'))

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
      } catch {}
    }

    // The supervisor patch mounts `dsh-server-login/runtime` in every child, and
    // Node resolves it by walking up from `<home>/profiles/<profile>/`.
    linkPackageIntoUserRoot(root, 'dsh-server-login', PACKAGE_ROOT)

    // Always ensure the tenant's web profile includes the CopyMonster bundle
    const userPackageJson = join(userProfile, 'package.json')
    ensureCopyMonsterBundle(userPackageJson)

    // The roots were created by the (possibly root) control plane; the DSH child
    // runs as the user's own uid and must be able to traverse + write them.
    // Recursively chown the entire tree so the tenant has full permission over all files.
    if (uid !== undefined && typeof process.getuid === 'function' && process.getuid() === 0) {
      try {
        grantUserRootPermissions(root, uid)
        chmodSync(root, 0o755)
        chmodSync(homeRoot(root), 0o755)
        chmodSync(workspaceRoot(root), 0o755)
      } catch {
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
