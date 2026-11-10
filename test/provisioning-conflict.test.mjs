// Provisioning must fail closed on an identity mismatch instead of reusing a
// Linux account that belongs to another uid (Fase 5 / 5.2.1).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, chmodSync, mkdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execFileSync } from 'node:child_process'

// The supervisor shells out to id/getent/groupadd/useradd. The test replaces
// them with scripts that answer from a fixed table, so it exercises the real
// decision logic without touching the host's account database.
const ACCOUNTS = { byName: {}, byUid: {}, groups: {} }

function script(dir, name, body) {
  const path = join(dir, name)
  writeFileSync(path, `#!/bin/sh\n${body}\n`)
  chmodSync(path, 0o755)
  return path
}

function makeBin() {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-provision-bin-'))
  const table = join(dir, 'accounts.json')

  script(dir, 'id', `
ARGV="$*" node -e '
const t = JSON.parse(require("fs").readFileSync(process.env.ACCOUNTS, "utf8"));
const [op, key] = process.env.ARGV.split(" ");
if (op === "-u") { const v = t.byName[key]; if (v === undefined) process.exit(1); process.stdout.write(String(v) + "\\n"); }
else { const v = t.byUid[key]; if (v === undefined) process.exit(1); process.stdout.write(v + "\\n"); }
'`)
  script(dir, 'getent', `
ARGV="$*" node -e '
const t = JSON.parse(require("fs").readFileSync(process.env.ACCOUNTS, "utf8"));
const [db, key] = process.env.ARGV.split(" ");
if (db === "passwd") { const v = t.byUid[key]; if (v === undefined) process.exit(2); process.stdout.write(v + ":x:" + key + ":" + key + "::/home/" + v + ":/bin/bash\\n"); }
else { const v = t.groups[key]; if (v === undefined) process.exit(2); process.stdout.write(key + ":x:" + v + ":\\n"); }
'`)
  script(dir, 'groupadd', `ARGV="$*" node -e '
const fs = require("fs"); const t = JSON.parse(fs.readFileSync(process.env.ACCOUNTS, "utf8"));
const argv = process.env.ARGV.split(" ");
const gid = Number(argv[argv.indexOf("-g") + 1]);
const name = argv[argv.length - 1];
if (t.groups[name] !== undefined) { process.stderr.write("group exists\\n"); process.exit(9); }
t.groups[name] = gid; fs.writeFileSync(process.env.ACCOUNTS, JSON.stringify(t));
'`)
  script(dir, 'useradd', `ARGV="$*" node -e '
const fs = require("fs"); const t = JSON.parse(fs.readFileSync(process.env.ACCOUNTS, "utf8"));
const argv = process.env.ARGV.split(" ");
const name = argv[argv.length - 1];
const uid = argv[argv.indexOf("-u") + 1];
if (t.byUid[uid] !== undefined || t.byName[name] !== undefined) {
  process.stderr.write("useradd: UID " + uid + " is not unique\\n");
  process.exit(4);
}
t.byName[name] = Number(uid); t.byUid[String(uid)] = name;
fs.writeFileSync(process.env.ACCOUNTS, JSON.stringify(t));
'`)

  return { dir, table }
}

async function withProvisioning(run) {
  const { dir, table } = makeBin()
  writeFileSync(table, JSON.stringify(ACCOUNTS))
  const savedPath = process.env.PATH
  const savedTable = process.env.ACCOUNTS
  process.env.PATH = `${dir}:${savedPath}`
  process.env.ACCOUNTS = table
  const { LocalSpawner } = await import('../lib/supervisor/orchestrator.js')
  try {
    await run(LocalSpawner, dir)
  } finally {
    process.env.PATH = savedPath
    if (savedTable === undefined) delete process.env.ACCOUNTS
    else process.env.ACCOUNTS = savedTable
    rmSync(dir, { recursive: true, force: true })
  }
}

function spawner(LocalSpawner, uid, username) {
  const config = {
    dataRoot: '/tmp/dsh-provision-test',
    isolationMode: 'account',
    portGuard: false,
    baseUid: 100000,
    baseDomain: '',
    enablePatch: false,
    resourceScopes: false,
    spawnAsUserCommand: ['/usr/bin/setpriv'],
    dshCommand: ['dsh'],
  }
  return new LocalSpawner(
    config,
    async () => null,
    async () => uid,
    { findUserById: async () => ({ id: 'tenant-1', username, uid }) },
  )
}

async function attempt(LocalSpawner, uid, username) {
  // The SSO exchange calls this same entry point, so a conflict fails the login.
  const instance = spawner(LocalSpawner, uid, username)
  return instance.ensureLinuxAccount('tenant-1')
}

test('provisioning: a free uid and name create the account', async () => {
  await withProvisioning(async (LocalSpawner) => {
    await attempt(LocalSpawner, 100010, 'alice')
    const table = JSON.parse(execFileSync('cat', [process.env.ACCOUNTS], { encoding: 'utf8' }))
    assert.equal(table.byName.alice, 100010)
  })
})

test('provisioning: an existing match is idempotent', async () => {
  await withProvisioning(async (LocalSpawner) => {
    await attempt(LocalSpawner, 100010, 'alice')
    await attempt(LocalSpawner, 100010, 'alice')
    const table = JSON.parse(execFileSync('cat', [process.env.ACCOUNTS], { encoding: 'utf8' }))
    assert.equal(table.byName.alice, 100010)
  })
})

test('provisioning: a name already owned by another uid is a conflict', async () => {
  await withProvisioning(async (LocalSpawner) => {
    const table = { byName: { alice: 100008 }, byUid: { 100008: 'alice' }, groups: { alice: 100008 } }
    writeFileSync(process.env.ACCOUNTS, JSON.stringify(table))
    await assert.rejects(
      () => attempt(LocalSpawner, 100010, 'alice'),
      (error) => error.name === 'ProvisioningConflict' && error.mismatch === 'uid' && error.actual === 100008,
    )
  })
})

test('provisioning: a uid already owned by another name is a conflict', async () => {
  await withProvisioning(async (LocalSpawner) => {
    const table = { byName: { bob: 100010 }, byUid: { 100010: 'bob' }, groups: { bob: 100010 } }
    writeFileSync(process.env.ACCOUNTS, JSON.stringify(table))
    await assert.rejects(
      () => attempt(LocalSpawner, 100010, 'alice'),
      (error) => error.name === 'ProvisioningConflict' && error.mismatch === 'name',
    )
  })
})
