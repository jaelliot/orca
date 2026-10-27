import { randomBytes } from 'node:crypto'
import { join } from 'node:path'
import process from 'node:process'
import { withFileTransactionLock } from '../file-transaction-lock'
import { profileStateAccessMachineIdentity } from '../persistence/profile-state/profile-state-access-identity'
import { resolveOrcadOsKeyring, type OrcadOsKeyring } from './orcad-os-keyring'
import { createStrictRecord, loadStrictRecord, migrateToStrict } from './orcad-strict-keyring'
import {
  resolveOrcadLegacyKeyringReader,
  type OrcadLegacyKeyringReader
} from './orcad-legacy-keyring-key'
import {
  decodeMasterKey,
  isTemporaryKeyDir,
  orcadSecretStateFileName,
  publishRecordExclusively,
  readStoredRecord,
  replaceRecord,
  restrictExistingRecord,
  type StoredKeyState
} from './orcad-secret-key-record'
import {
  describeOrcadHostKeyGap,
  describeOrcadDisposableProfile,
  describeOrcadPlaintextOptOut,
  describeOrcadSealingUnavailable,
  ORCAD_PLAINTEXT_SECRETS_ENV
} from './orcad-secret-protection-gap'
import {
  deriveOrcadSealingKey,
  ORCAD_MASTER_KEY_BYTES,
  orcadSealingKeyCheck
} from './orcad-secret-sealing'

export type StoreState =
  | { kind: 'pending' }
  | { kind: 'plaintext'; reason: string }
  | { kind: 'ready'; key: Buffer; gap: string | null }
  | { kind: 'unavailable'; message: string }

export type OrcadSecretStorePrepareOptions = {
  /** Keep the key beside the credentials so their lifetimes match. */
  keyDir: string
  /** Disposable profiles leave persistent keys untouched. */
  userDataPath?: string
  platform?: NodeJS.Platform
  env?: NodeJS.ProcessEnv
  legacyKeyring?: OrcadLegacyKeyringReader | null
  osKeyring?: OrcadOsKeyring | null
  machineIdentity?: () => string | null
  isTemporaryKeyDir?: (keyDir: string) => boolean
}

type Context = {
  machineId: string | null
  keyDir: string
  osKeyring: OrcadOsKeyring | null
  statePath: string
  legacyKeyring: () => OrcadLegacyKeyringReader | null
  log: (message: string) => void
  unavailable: (reason: string) => Extract<StoreState, { kind: 'unavailable' }>
}

export function orcadSecretStatePath(options: OrcadSecretStorePrepareOptions): string {
  const machineId = (options.machineIdentity ?? profileStateAccessMachineIdentity)()
  return join(options.keyDir, orcadSecretStateFileName(machineId))
}

function newFileRecord(machineId: string | null): StoredKeyState {
  const master = randomBytes(ORCAD_MASTER_KEY_BYTES)
  return {
    version: 1,
    backend: 'host-file',
    key: master.toString('base64'),
    hostBound: machineId !== null,
    check: orcadSealingKeyCheck(deriveOrcadSealingKey(master, machineId ?? ''))
  }
}

/** Migrate a readable legacy key once; preserve the existing record if its key cannot be verified. */
async function migrateKeyringRecord(
  stored: Extract<StoredKeyState, { backend: 'os-keyring' }>,
  context: Context
): Promise<StoreState | 'reload'> {
  const reader = context.legacyKeyring()
  const found = reader ? await reader(stored.account) : { failure: 'no OS keyring is reachable' }
  const master = 'key' in found ? decodeMasterKey(found.key) : null
  if (!master || orcadSealingKeyCheck(deriveOrcadSealingKey(master, '')) !== stored.check) {
    const why =
      'failure' in found
        ? `the OS keyring key could not be loaded (${found.failure})`
        : 'the OS keyring key does not match the credential record'
    return context.unavailable(why)
  }
  const record: StoredKeyState = {
    version: 1,
    backend: 'host-file',
    key: master.toString('base64'),
    hostBound: false,
    check: stored.check
  }
  const replaced = replaceRecord(context.statePath, record, stored)
  if (replaced === 'changed') {
    return 'reload'
  }
  if (replaced !== 'replaced') {
    return context.unavailable(replaced)
  }
  context.log(
    '[secrets] Copied the credential key from the OS keyring into the owner-only key file.'
  )
  return 'reload'
}

async function loadStoredRecord(
  stored: Exclude<StoredKeyState, { backend: 'os-keyring-strict' }>,
  context: Context
): Promise<StoreState | 'reload'> {
  if (stored.backend === 'os-keyring') {
    // Serialize concurrent key migrations.
    // Retry beyond the bounded keyring read budget.
    return withFileTransactionLock(
      context.statePath,
      async () => {
        // Another start may have migrated the record while this one waited.
        const current = readStoredRecord(context.statePath)
        return current.kind === 'record' &&
          current.stored.backend === 'os-keyring' &&
          current.stored.check === stored.check
          ? migrateKeyringRecord(current.stored, context)
          : 'reload'
      },
      { retries: 4 }
    ).catch((error: unknown) =>
      context.unavailable(
        `its key record could not be locked against another server (${String(error)})`
      )
    )
  }
  const { unavailable } = context
  if (!(await restrictExistingRecord(context.statePath))) {
    return unavailable(`its key record ${context.statePath} could not be restricted to this user`)
  }
  const master = decodeMasterKey(stored.key)
  const binding = stored.hostBound ? context.machineId : ''
  if (!master || binding === null) {
    return unavailable('this machine no longer reports the machine ID its key is bound to')
  }
  const key = deriveOrcadSealingKey(master, binding)
  if (orcadSealingKeyCheck(key) !== stored.check) {
    return unavailable('its key is bound to a different machine ID')
  }
  return { kind: 'ready', key, gap: describeOrcadHostKeyGap(stored.hostBound) }
}

export async function resolveState(
  options: OrcadSecretStorePrepareOptions,
  log: (message: string) => void
): Promise<StoreState> {
  const platform = options.platform ?? process.platform
  const env = options.env ?? process.env
  const strict = env[ORCAD_PLAINTEXT_SECRETS_ENV] === 'keyring'
  if (env[ORCAD_PLAINTEXT_SECRETS_ENV] === 'plaintext') {
    return { kind: 'plaintext', reason: describeOrcadPlaintextOptOut() }
  }
  const machineId = (options.machineIdentity ?? profileStateAccessMachineIdentity)()
  const statePath = join(options.keyDir, orcadSecretStateFileName(machineId))
  // Disposable runs must not write plaintext over persistent strict credentials.
  if (
    options.userDataPath &&
    (options.isTemporaryKeyDir ?? isTemporaryKeyDir)(options.userDataPath)
  ) {
    const existing = readStoredRecord(statePath)
    if (
      strict ||
      existing.kind === 'unreadable' ||
      (existing.kind === 'record' && existing.stored.backend === 'os-keyring-strict')
    ) {
      return {
        kind: 'unavailable',
        message: describeOrcadSealingUnavailable(
          'temporary profiles cannot use an existing strict credential key',
          statePath
        )
      }
    }
    return { kind: 'plaintext', reason: describeOrcadDisposableProfile() }
  }
  const context: Context = {
    machineId,
    keyDir: options.keyDir,
    osKeyring:
      options.osKeyring === undefined ? resolveOrcadOsKeyring(platform, env) : options.osKeyring,
    statePath,
    legacyKeyring: () =>
      options.legacyKeyring === undefined
        ? resolveOrcadLegacyKeyringReader(platform, env)
        : options.legacyKeyring,
    log,
    unavailable: (reason) => ({
      kind: 'unavailable',
      message: describeOrcadSealingUnavailable(reason, statePath)
    })
  }
  // Reload the winning record after publication races or migration.
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const existing = readStoredRecord(statePath)
    if (existing.kind === 'record') {
      const stored = existing.stored
      const loaded =
        stored.backend === 'os-keyring-strict'
          ? await loadStrictRecord(stored, context)
          : strict
            ? await migrateToStrict(stored, context)
            : await loadStoredRecord(stored, context)
      if (loaded !== 'reload') {
        return loaded
      }
      continue
    }
    if (existing.kind === 'unreadable') {
      return context.unavailable(existing.reason)
    }
    if (strict) {
      const created = await createStrictRecord(context)
      if (created !== 'reload') {
        return created
      }
      continue
    }
    const record = newFileRecord(machineId)
    // A key that never reaches disk would lose every sealed credential on restart.
    const published = publishRecordExclusively(statePath, record)
    if (published === 'published') {
      continue
    }
    if (published !== 'exists') {
      return context.unavailable(published)
    }
  }
  return context.unavailable('another server kept replacing its key record')
}
