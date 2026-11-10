// Uid allocation must never hand a removed tenant's uid to a new tenant: the
// old derivation (baseUid + SQLite rowid) reused ids after a delete (Fase 5).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { openDatabase } from '../lib/db/connection.js'
import { createUser, nextUid } from '../lib/db/repo.js'
import { runSqliteMigrations } from '../lib/db/schema.js'

const BASE_UID = 100000

async function withDb(run) {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-uid-seq-'))
  const db = openDatabase(join(dir, 'server-login.db'))
  runSqliteMigrations(db)
  try {
    await run(db)
  } finally {
    db.close()
    rmSync(dir, { recursive: true, force: true })
  }
}

function newUser(db, id, username) {
  return createUser(db, {
    id,
    username,
    passHash: 'x',
    role: 'active',
    homeDir: `/tmp/${username}`,
  }, BASE_UID)
}

test('uid: allocation starts above the base and increases', async () => {
  await withDb(async (db) => {
    const first = newUser(db, 'u-1', 'alice')
    const second = newUser(db, 'u-2', 'bobby')
    assert.equal(first.uid, BASE_UID + 1)
    assert.equal(second.uid, BASE_UID + 2)
  })
})

test('uid: a deleted user\'s uid is never reissued', async () => {
  await withDb(async (db) => {
    const first = newUser(db, 'u-1', 'alice')
    const second = newUser(db, 'u-2', 'bobby')
    db.prepare('DELETE FROM users WHERE id = ?').run(second.id)

    const third = newUser(db, 'u-3', 'caroline')
    assert.notEqual(third.uid, second.uid)
    assert.ok(third.uid > second.uid)
    assert.notEqual(third.uid, first.uid)
  })
})

test('uid: a fresh sequence continues above uids already assigned', async () => {
  await withDb(async (db) => {
    // Simulates a database migrated from the rowid derivation: users exist with
    // uids, but the sequence table is still empty.
    newUser(db, 'u-1', 'alice')
    const highest = db.prepare('SELECT MAX(uid) AS m FROM users').get().m
    db.prepare("DELETE FROM uid_sequence WHERE name = 'users'").run()

    const next = nextUid(db, BASE_UID)
    assert.equal(next, Number(highest) + 1)
  })
})

test('uid: the sequence keeps moving forward across many users', async () => {
  await withDb(async (db) => {
    const uids = []
    for (let i = 0; i < 5; i += 1) uids.push(newUser(db, `u-${i}`, `tenant${i}`).uid)
    assert.deepEqual([...uids].sort((a, b) => a - b), uids)
    assert.equal(new Set(uids).size, uids.length)
  })
})
