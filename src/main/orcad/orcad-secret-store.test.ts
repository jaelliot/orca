import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync
} from 'node:fs'
import { randomBytes } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { classifyUnenvelopedCredential } from '../../shared/secret-at-rest-protection'
import { _resetSecretStoreForTests, setSecretStore } from '../../shared/secret-store'
import { readStoredCredentialToken, writeEncryptedCredential } from '../integration-credential-file'
import type { OrcadLegacyKeyLookup, OrcadLegacyKeyringReader } from './orcad-legacy-keyring-key'
import type { OrcadKeyringLookup, OrcadOsKeyring } from './orcad-os-keyring'
import { keyringAccount, orcadSecretStateFileName } from './orcad-secret-key-record'
import {
  deriveOrcadSealingKey,
  orcadSealingKeyCheck,
  sealOrcadSecret
} from './orcad-secret-sealing'
import { createOrcadSecretStore } from './orcad-secret-store'

const MACHINE_A = '0123456789abcdef0123456789abcdef'
const MACHINE_B = 'fedcba9876543210fedcba9876543210'
const STATE_A = orcadSecretStateFileName(MACHINE_A)

function fakeLegacyKeyring(answer: OrcadLegacyKeyLookup) {
  const reads: string[] = []
  const read: OrcadLegacyKeyringReader = async (account) => {
    reads.push(account)
    return answer
  }
  return { read, reads }
}

type FakeKeyring = OrcadOsKeyring & {
  items: Map<string, string>
  failure: OrcadKeyringLookup | null
  storeWorks: boolean
}

function fakeKeyring(): FakeKeyring {
  const items = new Map<string, string>()
  const keyring: FakeKeyring = {
    label: 'the test keyring',
    items,
    failure: null,
    storeWorks: true,
    async lookup(account) {
      if (keyring.failure) {
        return keyring.failure
      }
      const value = items.get(account)
      return value ? { kind: 'found', value } : { kind: 'missing' }
    },
    async store(account, value) {
      if (keyring.storeWorks) {
        items.set(account, value)
      }
      return keyring.storeWorks
    }
  }
  return keyring
}

describe('createOrcadSecretStore', () => {
  let keyDir: string

  beforeEach(() => {
    keyDir = mkdtempSync(join(tmpdir(), 'orcad-secret-store-'))
  })

  afterEach(() => {
    _resetSecretStoreForTests()
    rmSync(keyDir, { recursive: true, force: true })
    vi.restoreAllMocks()
  })

  const prepare = async (
    options: {
      legacyKeyring?: OrcadLegacyKeyringReader | null
      osKeyring?: OrcadOsKeyring | null
      machine?: string | null
      env?: NodeJS.ProcessEnv
      log?: (message: string) => void
    } = {}
  ) => {
    const store = createOrcadSecretStore(options.log ?? (() => {}))
    const ready = await store.prepare({
      keyDir,
      platform: 'linux',
      env: options.env ?? {},
      legacyKeyring: options.legacyKeyring ?? null,
      osKeyring: options.osKeyring ?? null,
      machineIdentity: () => (options.machine === undefined ? MACHINE_A : options.machine),
      isTemporaryKeyDir: () => false
    })
    return { store, ready }
  }

  const legacyKeyringHost = () => {
    const master = randomBytes(32)
    const key = deriveOrcadSealingKey(master, '')
    const record = {
      version: 1,
      backend: 'os-keyring',
      account: 'home-0123456789abcdef',
      check: orcadSealingKeyCheck(key)
    }
    writeFileSync(join(keyDir, STATE_A), JSON.stringify(record), {
      mode: 0o600
    })
    return {
      encodedKey: master.toString('base64'),
      sealed: sealOrcadSecret(key, 'lin_api_secret')
    }
  }

  const STRICT = { ORCA_HEADLESS_SECRET_STORE: 'keyring' }

  it('uses a strict keyring record on new hosts and never persists the master key', async () => {
    const keyring = fakeKeyring()
    const first = await prepare({ env: STRICT, osKeyring: keyring })
    expect(first.ready).toBe(true)
    expect(first.store.describeProtectionGap()).toBeNull()
    const record = JSON.parse(readFileSync(join(keyDir, STATE_A), 'utf8'))
    expect(record).toMatchObject({ backend: 'os-keyring-strict', hostBound: false })
    expect(record).not.toHaveProperty('key')
    expect(keyring.items.size).toBe(1)
    const master = [...keyring.items.values()][0]
    expect(readFileSync(join(keyDir, STATE_A), 'utf8')).not.toContain(master)
    const sealed = first.store.encryptString('lin_api_secret')
    expect(sealed.includes(Buffer.from('lin_api_secret'))).toBe(false)
    const reopened = await prepare({ osKeyring: keyring })
    expect(reopened.ready).toBe(true)
    expect(reopened.store.decryptString(sealed)).toBe('lin_api_secret')
    expect(JSON.parse(readFileSync(join(keyDir, STATE_A), 'utf8')).backend).toBe(
      'os-keyring-strict'
    )
  })

  it('never falls back to a file or plaintext if strict mode has no keyring', async () => {
    const { store, ready } = await prepare({ env: STRICT })
    expect(ready).toBe(false)
    expect(store.isEncryptionAvailable()).toBe(true)
    setSecretStore(store)
    expect(() => writeEncryptedCredential('Linear', join(keyDir, 'token.enc'), 'secret')).toThrow(
      /cannot unseal/
    )
    expect(readdirSync(keyDir)).toEqual([])
  })

  it('moves an existing file key to the strict keyring without changing ciphertext', async () => {
    const sealed = (await prepare()).store.encryptString('lin_api_secret')
    const previous = JSON.parse(readFileSync(join(keyDir, STATE_A), 'utf8'))
    const keyring = fakeKeyring()
    const migrated = await prepare({ env: STRICT, osKeyring: keyring })
    expect(migrated.ready).toBe(true)
    expect(migrated.store.decryptString(sealed)).toBe('lin_api_secret')
    const record = JSON.parse(readFileSync(join(keyDir, STATE_A), 'utf8'))
    expect(record).toMatchObject({
      backend: 'os-keyring-strict',
      hostBound: true,
      check: previous.check
    })
    expect(record).not.toHaveProperty('key')
    expect(keyring.items.get(keyringAccount(keyDir, MACHINE_A, previous.check))).toBe(previous.key)
    expect((await prepare({ osKeyring: keyring })).store.decryptString(sealed)).toBe(
      'lin_api_secret'
    )
  })

  it.each(['locked', 'timed out', 'write failed', 'conflicting item'] as const)(
    'preserves existing encrypted credentials when strict migration is %s',
    async (failure) => {
      const keyring = fakeKeyring()
      const initial = (await prepare()).store
      const saved = join(keyDir, 'saved.enc')
      setSecretStore(initial)
      writeEncryptedCredential('Linear', saved, 'secret-before')
      const ciphertext = readFileSync(saved)
      const stateBefore = readFileSync(join(keyDir, STATE_A))
      if (failure === 'locked' || failure === 'timed out') {
        keyring.failure = { kind: 'unreachable', reason: failure }
      } else if (failure === 'write failed') {
        keyring.storeWorks = false
      } else {
        keyring.items.set(
          keyringAccount(keyDir, MACHINE_A, JSON.parse(stateBefore.toString('utf8')).check),
          randomBytes(32).toString('base64')
        )
      }
      const failed = await prepare({ env: STRICT, osKeyring: keyring })
      expect(failed.ready).toBe(false)
      expect(failed.store.isEncryptionAvailable()).toBe(true)
      setSecretStore(failed.store)
      expect(() => writeEncryptedCredential('Linear', saved, 'replacement')).toThrow()
      expect(readFileSync(join(keyDir, STATE_A))).toEqual(stateBefore)
      expect(readFileSync(saved)).toEqual(ciphertext)
      keyring.failure = null
      keyring.storeWorks = true
      keyring.items.clear()
      const recovered = await prepare({ env: STRICT, osKeyring: keyring })
      expect(recovered.ready).toBe(true)
      expect(recovered.store.decryptString(ciphertext)).toBe('secret-before')
    }
  )

  it('upgrades an existing legacy keyring record to strict without writing its master key', async () => {
    const { encodedKey, sealed } = legacyKeyringHost()
    const keyring = fakeKeyring()
    keyring.items.set('home-0123456789abcdef', encodedKey)
    const migrated = await prepare({ env: STRICT, osKeyring: keyring })
    expect(migrated.ready).toBe(true)
    expect(migrated.store.decryptString(sealed)).toBe('lin_api_secret')
    const record = JSON.parse(readFileSync(join(keyDir, STATE_A), 'utf8'))
    expect(record).toMatchObject({
      backend: 'os-keyring-strict',
      account: 'home-0123456789abcdef',
      hostBound: false
    })
    expect(record).not.toHaveProperty('key')
  })

  it('preserves strict records and refuses writes when their keyring becomes locked', async () => {
    const keyring = fakeKeyring()
    const first = await prepare({ env: STRICT, osKeyring: keyring })
    const sealed = first.store.encryptString('secret-before')
    const before = readFileSync(join(keyDir, STATE_A))
    keyring.failure = { kind: 'unreachable', reason: 'locked' }
    const locked = await prepare({ osKeyring: keyring })
    expect(locked.ready).toBe(false)
    expect(locked.store.isEncryptionAvailable()).toBe(true)
    expect(() => locked.store.decryptString(sealed)).toThrow(/cannot unseal/)
    expect(readFileSync(join(keyDir, STATE_A))).toEqual(before)
    keyring.failure = null
    expect((await prepare({ osKeyring: keyring })).store.decryptString(sealed)).toBe(
      'secret-before'
    )
  })

  it('keeps the file-mode winner usable when it races strict keyring creation', async () => {
    const keyring = fakeKeyring()
    const save = keyring.store.bind(keyring)
    const concurrent: { sealed: Buffer } = { sealed: Buffer.alloc(0) }
    let raced = false
    keyring.store = async (account, value) => {
      const stored = await save(account, value)
      if (!raced) {
        raced = true
        const fileMode = await prepare()
        expect(fileMode.ready).toBe(true)
        concurrent.sealed = fileMode.store.encryptString('file-winner')
      }
      return stored
    }
    const strict = await prepare({ env: STRICT, osKeyring: keyring })
    expect(strict.ready).toBe(true)
    expect(strict.store.decryptString(concurrent.sealed)).toBe('file-winner')
    const record = JSON.parse(readFileSync(join(keyDir, STATE_A), 'utf8'))
    expect(record.backend).toBe('os-keyring-strict')
    expect(keyring.items.get(record.account)).toBeDefined()
    expect(
      (await prepare({ env: STRICT, osKeyring: keyring })).store.decryptString(concurrent.sealed)
    ).toBe('file-winner')
  })

  it('refuses implicit plaintext overwrite of strict credentials in temporary profiles', async () => {
    const keyring = fakeKeyring()
    const original = (await prepare({ env: STRICT, osKeyring: keyring })).store
    const saved = join(keyDir, 'token.enc')
    setSecretStore(original)
    writeEncryptedCredential('Linear', saved, 'previous-secret')
    const before = readFileSync(saved)
    const stateBefore = readFileSync(join(keyDir, STATE_A))
    const temporary = createOrcadSecretStore()
    const ready = await temporary.prepare({
      keyDir,
      userDataPath: '/tmp/orcad-smoke-profile',
      env: {},
      osKeyring: keyring,
      machineIdentity: () => MACHINE_A
    })
    expect(ready).toBe(false)
    expect(temporary.isEncryptionAvailable()).toBe(true)
    setSecretStore(temporary)
    expect(() => writeEncryptedCredential('Linear', saved, 'replacement')).toThrow(/cannot unseal/)
    expect(readFileSync(saved)).toEqual(before)
    expect(readFileSync(join(keyDir, STATE_A))).toEqual(stateBefore)
  })

  it('refuses temporary-profile plaintext when the saved key record is unreadable', async () => {
    const statePath = join(keyDir, STATE_A)
    writeFileSync(statePath, '{invalid-json', 'utf8')
    const temporary = createOrcadSecretStore()
    const ready = await temporary.prepare({
      keyDir,
      userDataPath: '/tmp/orcad-smoke-profile',
      env: {},
      machineIdentity: () => MACHINE_A
    })
    expect(ready).toBe(false)
    expect(temporary.isEncryptionAvailable()).toBe(true)
    expect(readFileSync(statePath, 'utf8')).toBe('{invalid-json')
  })

  it('does not permit temporary-profile plaintext in strict mode', async () => {
    const store = createOrcadSecretStore()
    const ready = await store.prepare({
      keyDir,
      userDataPath: '/tmp/orcad-smoke-profile',
      env: STRICT,
      osKeyring: fakeKeyring(),
      machineIdentity: () => MACHINE_A
    })
    expect(ready).toBe(false)
    expect(store.isEncryptionAvailable()).toBe(true)
    expect(store.describeProtectionGap()).toContain('temporary profiles')
    expect(readdirSync(keyDir)).toEqual([])
  })

  it('agrees on the same key across concurrent strict first starts', async () => {
    const keyring = fakeKeyring()
    const [first, second] = await Promise.all([
      prepare({ env: STRICT, osKeyring: keyring }),
      prepare({ env: STRICT, osKeyring: keyring })
    ])
    expect(first.ready && second.ready).toBe(true)
    expect(keyring.items.size).toBe(1)
    expect(second.store.decryptString(first.store.encryptString('test'))).toBe('test')
  })

  it('seals with a host-bound profile key when no keyring is reachable', async () => {
    const { store, ready } = await prepare()
    expect(ready).toBe(true)
    expect(store.isEncryptionAvailable()).toBe(true)
    const sealed = store.encryptString('lin_api_secret')
    expect(sealed.includes(Buffer.from('lin_api_secret'))).toBe(false)
    expect(classifyUnenvelopedCredential(sealed)).toBe('sealed')
    expect(store.decryptString(sealed)).toBe('lin_api_secret')
    expect(store.describeProtectionGap()).toContain('mixed with this machine ID')

    const statePath = join(keyDir, STATE_A)
    if (process.platform !== 'win32') {
      expect(statSync(statePath).mode & 0o777).toBe(0o600)
    }
    const reopened = (await prepare()).store
    expect(reopened.decryptString(sealed)).toBe('lin_api_secret')
  })

  it('gives another machine sharing the home its own key, leaving this one intact', async () => {
    const sealed = (await prepare()).store.encryptString('lin_api_secret')
    const stateBefore = readFileSync(join(keyDir, STATE_A))

    const { store, ready } = await prepare({ machine: MACHINE_B })
    expect(ready).toBe(true)
    expect(() => store.decryptString(sealed)).toThrow()
    expect(readFileSync(join(keyDir, STATE_A))).toEqual(stateBefore)
    expect((await prepare()).store.decryptString(sealed)).toBe('lin_api_secret')
  })

  it('refuses to seal or unseal when its record was bound to a different machine ID', async () => {
    const sealed = (await prepare()).store.encryptString('lin_api_secret')
    renameSync(join(keyDir, STATE_A), join(keyDir, orcadSecretStateFileName(MACHINE_B)))
    const moved = await prepare({ machine: MACHINE_B })
    expect(moved.ready).toBe(false)
    expect(() => moved.store.encryptString('new')).toThrow(/different machine ID/)
    expect(() => moved.store.decryptString(sealed)).toThrow(/different machine ID/)
    expect(moved.store.isEncryptionAvailable()).toBe(true)
  })

  it('never consults the OS keyring on a fresh host', async () => {
    const keyring = fakeLegacyKeyring({ key: 'unused' })
    const { store, ready } = await prepare({ legacyKeyring: keyring.read })
    expect(ready).toBe(true)
    expect(keyring.reads).toEqual([])
    expect(store.describeProtectionGap()).toContain('private credential directory')
    expect(JSON.parse(readFileSync(join(keyDir, STATE_A), 'utf8')).backend).toBe('host-file')
  })

  it('copies a key an older build kept in the OS keyring into the key file, once', async () => {
    const { encodedKey, sealed } = legacyKeyringHost()
    const keyring = fakeLegacyKeyring({ key: encodedKey })
    const log = vi.fn()
    const { store, ready } = await prepare({
      legacyKeyring: keyring.read,
      log
    })
    expect(ready).toBe(true)
    expect(store.decryptString(sealed)).toBe('lin_api_secret')
    expect(keyring.reads).toEqual(['home-0123456789abcdef'])
    expect(log).toHaveBeenCalledWith(expect.stringContaining('Copied the credential key'))
    const record = JSON.parse(readFileSync(join(keyDir, STATE_A), 'utf8'))
    expect(record).toMatchObject({
      backend: 'host-file',
      key: encodedKey,
      hostBound: false
    })
    if (process.platform !== 'win32') {
      expect(statSync(join(keyDir, STATE_A)).mode & 0o777).toBe(0o600)
    }

    const again = await prepare({ legacyKeyring: keyring.read })
    expect(again.store.decryptString(sealed)).toBe('lin_api_secret')
    expect(keyring.reads).toHaveLength(1)
  })

  it.each([
    ['locked', fakeLegacyKeyring({ failure: 'exited 36' }).read],
    ['timing out', fakeLegacyKeyring({ failure: 'timed out after 5s' }).read],
    [
      'holding a different key',
      fakeLegacyKeyring({ key: randomBytes(32).toString('base64') }).read
    ],
    ['unreachable from this session', null]
  ])(
    'preserves the legacy key and sealed credentials when the keyring is %s',
    async (_label, legacyKeyring) => {
      const { encodedKey, sealed } = legacyKeyringHost()
      const statePath = join(keyDir, STATE_A)
      const recordBefore = readFileSync(statePath)
      const saved = join(keyDir, 'saved.enc')
      writeFileSync(saved, sealed)

      const { store, ready } = await prepare({ legacyKeyring })
      expect(ready).toBe(false)
      expect(store.isEncryptionAvailable()).toBe(true)
      expect(store.describeProtectionGap()).toContain('cannot unseal')
      expect(() => store.decryptString(sealed)).toThrow(/cannot unseal/)
      setSecretStore(store)
      expect(() => writeEncryptedCredential('Linear', saved, 'lin_api_new')).toThrow(
        /cannot unseal/
      )
      expect(readFileSync(statePath)).toEqual(recordBefore)
      expect(readFileSync(saved)).toEqual(sealed)

      const recovered = await prepare({
        legacyKeyring: fakeLegacyKeyring({ key: encodedKey }).read
      })
      expect(recovered.ready).toBe(true)
      expect(recovered.store.decryptString(sealed)).toBe('lin_api_secret')
      expect(JSON.parse(readFileSync(statePath, 'utf8')).backend).toBe('host-file')
    }
  )

  it.skipIf(process.platform === 'win32' || process.getuid?.() === 0)(
    'treats a record it cannot read as unavailable, never as missing',
    async () => {
      const sealed = (await prepare()).store.encryptString('lin_api_secret')
      const statePath = join(keyDir, STATE_A)
      const before = readFileSync(statePath)
      chmodSync(statePath, 0o000)
      try {
        const { store, ready } = await prepare()
        expect(ready).toBe(false)
        expect(() => store.decryptString(sealed)).toThrow(/could not be read/)
      } finally {
        chmodSync(statePath, 0o600)
      }
      expect(readFileSync(statePath)).toEqual(before)
    }
  )

  it('agrees on one key when two servers start against the same home at once', async () => {
    const [first, second] = await Promise.all([prepare(), prepare()])
    expect(first.ready && second.ready).toBe(true)
    expect(second.store.decryptString(first.store.encryptString('a'))).toBe('a')

    rmSync(join(keyDir, STATE_A))
    const { encodedKey, sealed } = legacyKeyringHost()
    const keyring = fakeLegacyKeyring({ key: encodedKey })
    const migrated = await Promise.all([
      prepare({ legacyKeyring: keyring.read }),
      prepare({ legacyKeyring: keyring.read })
    ])
    expect(migrated.map(({ store }) => store.decryptString(sealed))).toEqual([
      'lin_api_secret',
      'lin_api_secret'
    ])
  })

  it('lets the first start migrate while a concurrent one with a locked keyring waits', async () => {
    const { encodedKey, sealed } = legacyKeyringHost()
    let enterMigration = (): void => {}
    const migrating = new Promise<void>((resolveEntered) => {
      enterMigration = resolveEntered
    })
    const slowSuccess: OrcadLegacyKeyringReader = async () => {
      enterMigration()
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 50))
      return { key: encodedKey }
    }
    const fastFailure = fakeLegacyKeyring({ failure: 'exited 36' })
    const firstStart = prepare({ legacyKeyring: slowSuccess })
    // Wait for lock acquisition before racing the second migration.
    await migrating
    const second = await prepare({ legacyKeyring: fastFailure.read })
    const first = await firstStart
    expect(first.store.decryptString(sealed)).toBe('lin_api_secret')
    expect(second.store.decryptString(sealed)).toBe('lin_api_secret')
    expect(fastFailure.reads).toEqual([])
    expect((await prepare()).store.decryptString(second.store.encryptString('n'))).toBe('n')
    expect(readdirSync(keyDir)).toEqual([STATE_A])
  })

  it('takes over a migration lock its crashed holder left behind', async () => {
    const { encodedKey, sealed } = legacyKeyringHost()
    const lock = join(keyDir, `${STATE_A}.lock`)
    mkdirSync(lock)
    utimesSync(lock, new Date(Date.now() - 60_000), new Date(Date.now() - 60_000))
    const { store, ready } = await prepare({
      legacyKeyring: fakeLegacyKeyring({ key: encodedKey }).read
    })
    expect(ready).toBe(true)
    expect(store.decryptString(sealed)).toBe('lin_api_secret')
    expect(readdirSync(keyDir)).toEqual([STATE_A])
  })

  it('never regenerates over an unreadable key record', async () => {
    const statePath = join(keyDir, STATE_A)
    writeFileSync(statePath, '{"version":1,"backend":"host-file"', 'utf8')
    const { store, ready } = await prepare()
    expect(ready).toBe(false)
    expect(() => store.encryptString('x')).toThrow(/not valid/)
    expect(readFileSync(statePath, 'utf8')).toBe('{"version":1,"backend":"host-file"')
  })

  it('records an unbound key when the host has no machine ID', async () => {
    const { store } = await prepare({ machine: null })
    expect(store.describeProtectionGap()).not.toContain('machine ID')
    const sealed = store.encryptString('t')
    expect((await prepare({ machine: null })).store.decryptString(sealed)).toBe('t')
  })

  it('leaves the persistent credential home alone for a temporary profile', async () => {
    const store = createOrcadSecretStore()
    const ready = await store.prepare({
      keyDir,
      userDataPath: '/tmp/orcad-smoke-profile',
      env: {},
      legacyKeyring: null,
      machineIdentity: () => MACHINE_A
    })
    expect(ready).toBe(false)
    expect(store.isEncryptionAvailable()).toBe(false)
    expect(store.describeProtectionGap()).toContain('temporary profile')
    expect(readdirSync(keyDir)).toEqual([])
  })

  it('keeps the explicit plaintext opt-out for shared homes', async () => {
    const { store, ready } = await prepare({
      env: { ORCA_HEADLESS_SECRET_STORE: 'plaintext' }
    })
    expect(ready).toBe(false)
    expect(store.isEncryptionAvailable()).toBe(false)
    expect(store.describeProtectionGap()).toContain('ORCA_HEADLESS_SECRET_STORE=plaintext')
  })

  it('makes integration credential saves seal, and still reads legacy plaintext', async () => {
    const { store } = await prepare()
    setSecretStore(store)
    const legacy = join(keyDir, 'legacy.enc')
    writeFileSync(legacy, 'lin_api_legacy', 'utf8')
    expect(readStoredCredentialToken('Linear', readFileSync(legacy))).toBe('lin_api_legacy')

    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const saved = join(keyDir, 'saved.enc')
    writeEncryptedCredential('Linear', saved, 'lin_api_new')
    expect(warn).not.toHaveBeenCalled()
    expect(readFileSync(saved).includes(Buffer.from('lin_api_new'))).toBe(false)
    expect(readStoredCredentialToken('Linear', readFileSync(saved))).toBe('lin_api_new')
  })

  it('fails a save closed when the key cannot load, keeping the sealed file', async () => {
    const saved = join(keyDir, 'saved.enc')
    setSecretStore((await prepare()).store)
    writeEncryptedCredential('Linear', saved, 'lin_api_original')
    const before = readFileSync(saved)

    renameSync(join(keyDir, STATE_A), join(keyDir, orcadSecretStateFileName(MACHINE_B)))
    setSecretStore((await prepare({ machine: MACHINE_B })).store)
    expect(() => writeEncryptedCredential('Linear', saved, 'lin_api_replacement')).toThrow()
    expect(readFileSync(saved)).toEqual(before)
  })
})
