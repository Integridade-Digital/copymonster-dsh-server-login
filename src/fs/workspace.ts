/**
 * Per-user filesystem layout + low-level helpers. This module is the single
 * place that knows the `users/<id>/{home,ws}` shape — the control plane, the
 * local spawner, the k8s Pod spec, and the file sidecar all derive their paths
 * from here so the four never drift apart.
 *
 * Isolation is enforced by the caller (see fs-guard).
 * @module dsh-server-login/fs/workspace
 */

import { execFileSync } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, readdirSync, statSync } from 'node:fs'
import type { Dirent } from 'node:fs'
import { lstat, readdir, stat } from 'node:fs/promises'
import { join, relative, sep } from 'node:path'
import { PathEscapeError } from '../web/middleware/fs-guard.js'

// Layout segment names. Exported so the k8s Pod spec can build the same layout
// with POSIX separators (`join` would emit backslashes when the control plane
// is developed/tested on Windows) without duplicating the literals.
export const USERS_DIR = 'users'
export const WORKSPACE_DIR = 'ws'
export const HOME_DIR = 'home'
export const HANDOFF_FILE = 'handoff.json'

/** A user's own data root (`<dataRoot>/users/<id>`). */
export function userRoot(dataRoot: string, userId: string): string {
  return join(dataRoot, USERS_DIR, userId)
}

/** The workspace (user-visible files) within a user root. */
export function workspaceRoot(root: string): string {
  return join(root, WORKSPACE_DIR)
}

/** DSH's own state (profiles/sessions/credentials) within a user root. */
export function homeRoot(root: string): string {
  return join(root, HOME_DIR)
}

/** The watchdog command handoff within a user root. */
export function handoffPath(root: string): string {
  return join(root, HANDOFF_FILE)
}

/** Create a directory (0700) if it does not exist. */
export function ensureDir(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 })
}

/** Files under a user root whose contents must stay readable only by the tenant. */
const OWNER_ONLY_FILES = ['.credentials.yaml']

/** Shared Workspace sandbox the tenant DSH writes under, unless configured. */
export const DEFAULT_SANDBOX_DATA_DIR = '/var/copymonster/data'

/**
 * Prepare one tenant's Workspace sandbox and hand it to that tenant's uid.
 *
 * The sandbox lives at `<dataRoot>/<tenantId>/<userId>/workspaces`, outside the
 * per-user root {@link grantUserRootPermissions} owns, so a directory the
 * control plane created as root leaves the tenant's DSH unable to create a
 * Workspace: `mkdir` fails with `EACCES` and the picker never opens one. The
 * tenant id comes from the directory name because the control plane keeps it
 * only in Supabase.
 *
 * A tenant with no directory for this user is skipped: the tenant's own DSH
 * creates that tree on first use.
 * @param dataRoot - shared sandbox root holding one directory per tenant.
 * @param userId - Supabase identity naming this user's directory in each tenant.
 * @param uid - the tenant's Linux uid (also used as gid).
 */
export function grantUserSandboxPermissions(dataRoot: string, userId: string, uid: number): void {
  let tenants: Dirent[]
  try {
    tenants = readdirSync(dataRoot, { withFileTypes: true })
  } catch {
    return
  }
  for (const tenant of tenants) {
    if (!tenant.isDirectory()) continue
    const userDir = join(dataRoot, tenant.name, userId)
    if (!existsSync(userDir)) continue
    const sandbox = join(userDir, 'workspaces')
    try {
      mkdirSync(sandbox, { recursive: true, mode: 0o700 })
      const owner = statSync(sandbox)
      if (owner.uid !== uid || owner.gid !== uid) {
        execFileSync('chown', ['-R', `${uid}:${uid}`, sandbox], { stdio: 'ignore' })
      }
      chmodSync(sandbox, 0o700)
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      console.warn(`[provisioning] prepare workspace sandbox failed for ${sandbox}: ${detail}`)
    }
  }
}

/**
 * Hand a user root to the tenant's own uid. The recursive pass makes the tree
 * traversable and writable by that uid, so it widens group/other bits too;
 * owner-only files are restored afterwards.
 * @param root - the user root directory.
 * @param uid - the tenant's Linux uid (also used as gid).
 */
export function grantUserRootPermissions(root: string, uid: number): void {
  execFileSync('chown', ['-R', `${uid}:${uid}`, root], { stdio: 'ignore' })
  execFileSync('chmod', ['-R', 'u+rwX,go+rX', root], { stdio: 'ignore' })
  for (const name of OWNER_ONLY_FILES) {
    const target = join(homeRoot(root), name)
    try {
      if (existsSync(target)) chmodSync(target, 0o600)
    } catch {}
  }
}

/**
 * Reject `abs` when any path component between `root` and `abs` (inclusive) is
 * a symbolic link. The lexical guard (`resolveWithinRoot`) cannot see links
 * planted INSIDE the workspace: an upload through `ws/link -> /etc` passes the
 * prefix check and lands outside the user's root with the caller's privileges.
 * The desktop surface never needs symlinks, so they are forbidden here; the
 * user's DSH process keeps its normal kernel view of links.
 *
 * Only components strictly below `root` are inspected — the data root itself
 * may legitimately sit behind a link. A missing (or not-a-directory) component
 * ends the walk: nothing can exist below it, and the caller's own open/stat
 * will surface that as its usual errno.
 */
export async function rejectSymlinkEscape(root: string, abs: string): Promise<void> {
  const rel = relative(root, abs)
  if (rel === '') return // abs IS the root
  if (rel.startsWith('..')) throw new PathEscapeError(abs, root)
  let current = root
  for (const segment of rel.split(sep)) {
    if (segment === '' || segment === '.') continue
    current = join(current, segment)
    try {
      const stats = await lstat(current)
      if (stats.isSymbolicLink()) throw new PathEscapeError(abs, root)
    } catch (err) {
      if (err instanceof PathEscapeError) throw err
      const code = (err as NodeJS.ErrnoException).code
      // Missing/not-a-directory component: nothing below it can exist either.
      if (code === 'ENOENT' || code === 'ENOTDIR') return
      throw err
    }
  }
}

/** One filesystem entry as returned to the desktop. */
export interface FsEntry {
  name: string
  type: 'file' | 'dir'
  size: number
  mtimeMs: number
}

/** List the immediate children of a directory (async, non-blocking). */
export async function listDir(absPath: string): Promise<FsEntry[]> {
  const entries = await readdir(absPath, { withFileTypes: true })
  const result: FsEntry[] = []
  for (const entry of entries) {
    const st = await stat(join(absPath, entry.name))
    result.push({
      name: entry.name,
      type: st.isDirectory() ? 'dir' : 'file',
      size: st.isFile() ? st.size : 0,
      mtimeMs: st.mtimeMs,
    })
  }
  return result
}
