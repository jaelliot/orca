import { randomBytes } from 'node:crypto'
import { withFileTransactionLock } from '../file-transaction-lock'
import type { OrcadOsKeyring } from './orcad-os-keyring'
import {
  decodeMasterKey,
  keyringAccount,
  publishRecordExclusively,
  readStoredRecord,
  replaceRecord,
  restrictExistingRecord,
  type StoredKeyState
} from './orcad-secret-key-record'
import {
  deriveOrcadSealingKey,
  ORCAD_MASTER_KEY_BYTES,
  orcadSealingKeyCheck
} from './orcad-secret-sealing'

type StrictStoreState =
  | { kind: 'ready'; key: Buffer; gap: null }
  | { kind: 'unavailable'; message: string }

type StrictKeyContext = {
  machineId: string | null
  keyDir: string
  statePath: string
  osKeyring: OrcadOsKeyring | null
  unavailable: (reason: string) => { kind: 'unavailable'; message: string }
}

export async function loadStrictRecord(
  stored: Extract<StoredKeyState, { backend: 'os-keyring-strict' }>,
  context: StrictKeyContext
): Promise<StrictStoreState> {
  const keyring = context.osKeyring
  if (!keyring) {
    return context.unavailable(
      'strict keyring storage requires an accessible OS keyring on this host'
    )
  }
  const found = await keyring.lookup(stored.account)
  if (found.kind !== 'found') {
    return context.unavailable(
      found.kind === 'missing'
        ? `the credential key is missing from ${keyring.label}`
        : `${keyring.label} is unavailable (${found.reason})`
    )
  }
  const master = decodeMasterKey(found.value)
  const binding = stored.hostBound ? context.machineId : ''
  if (!master || binding === null) {
    return context.unavailable('the keyring master key or its machine binding is invalid')
  }
  const key = deriveOrcadSealingKey(master, binding)
  if (orcadSealingKeyCheck(key) !== stored.check) {
    return context.unavailable('the keyring key does not match the saved credential key')
  }
  return { kind: 'ready', key, gap: null }
}

/** Never replace a conflicting keyring item or trust an unverified keyring write. */
async function ensureKeyringKey(
  keyring: OrcadOsKeyring,
  account: string,
  master: Buffer
): Promise<string | null> {
  const encoded = master.toString('base64')
  const before = await keyring.lookup(account)
  if (before.kind === 'unreachable') {
    return `${keyring.label} is unavailable (${before.reason})`
  }
  if (before.kind === 'found') {
    return before.value === encoded ? null : 'a different key already occupies this keyring account'
  }
  await keyring.store(account, encoded)
  const after = await keyring.lookup(account)
  return after.kind === 'found' && after.value === encoded
    ? null
    : 'the keyring did not confirm the stored key; the existing credential record was preserved'
}

/** Move the same verified master key to the keyring without changing saved ciphertext. */
export async function migrateToStrict(
  stored: Exclude<StoredKeyState, { backend: 'os-keyring-strict' }>,
  context: StrictKeyContext
): Promise<StrictStoreState | 'reload'> {
  return withFileTransactionLock(
    context.statePath,
    async (): Promise<StrictStoreState | 'reload'> => {
      const current = readStoredRecord(context.statePath)
      if (
        current.kind !== 'record' ||
        current.stored.backend !== stored.backend ||
        current.stored.check !== stored.check
      ) {
        return 'reload'
      }
      const keyring = context.osKeyring
      if (!keyring) {
        return context.unavailable('strict keyring storage requires an accessible OS keyring')
      }
      const active = current.stored
      let account: string
      let hostBound = false
      if (active.backend === 'host-file') {
        if (!(await restrictExistingRecord(context.statePath))) {
          return context.unavailable('the existing key record could not be restricted to its owner')
        }
        const master = decodeMasterKey(active.key)
        const binding = active.hostBound ? context.machineId : ''
        if (!master || binding === null) {
          return context.unavailable('the file-backed credential key cannot be verified')
        }
        if (orcadSealingKeyCheck(deriveOrcadSealingKey(master, binding)) !== active.check) {
          return context.unavailable('the file-backed credential key does not match its record')
        }
        account = keyringAccount(context.keyDir, context.machineId)
        const error = await ensureKeyringKey(keyring, account, master)
        if (error) {
          return context.unavailable(error)
        }
        hostBound = active.hostBound
      } else {
        account = active.account
        const found = await keyring.lookup(account)
        const master = found.kind === 'found' ? decodeMasterKey(found.value) : null
        if (!master || orcadSealingKeyCheck(deriveOrcadSealingKey(master, '')) !== active.check) {
          return context.unavailable('the legacy keyring key could not be verified')
        }
      }
      const replacement: StoredKeyState = {
        version: 1,
        backend: 'os-keyring-strict',
        account,
        check: active.check,
        hostBound
      }
      const published = replaceRecord(context.statePath, replacement, active)
      if (published === 'changed') {
        return 'reload'
      }
      return published === 'replaced' ? 'reload' : context.unavailable(published)
    },
    { retries: 4 }
  ).catch(() => context.unavailable('the keyring migration could not complete safely'))
}

export async function createStrictRecord(
  context: StrictKeyContext
): Promise<StrictStoreState | 'reload'> {
  return withFileTransactionLock(
    context.statePath,
    async (): Promise<StrictStoreState | 'reload'> => {
      if (readStoredRecord(context.statePath).kind !== 'absent') {
        return 'reload'
      }
      const keyring = context.osKeyring
      if (!keyring) {
        return context.unavailable('strict keyring storage requires an accessible OS keyring')
      }
      const account = keyringAccount(context.keyDir, context.machineId)
      const found = await keyring.lookup(account)
      if (found.kind === 'unreachable') {
        return context.unavailable(`${keyring.label} is unavailable (${found.reason})`)
      }
      const master =
        found.kind === 'found' ? decodeMasterKey(found.value) : randomBytes(ORCAD_MASTER_KEY_BYTES)
      if (!master) {
        return context.unavailable('an existing keyring item has an invalid credential key')
      }
      const error = await ensureKeyringKey(keyring, account, master)
      if (error) {
        return context.unavailable(error)
      }
      const key = deriveOrcadSealingKey(master, '')
      const record: StoredKeyState = {
        version: 1,
        backend: 'os-keyring-strict',
        account,
        check: orcadSealingKeyCheck(key),
        hostBound: false
      }
      const published = publishRecordExclusively(context.statePath, record)
      if (published === 'exists') {
        return 'reload'
      }
      return published === 'published'
        ? { kind: 'ready', key, gap: null }
        : context.unavailable(published)
    },
    { retries: 4 }
  ).catch(() => context.unavailable('the keyring setup could not complete safely'))
}
