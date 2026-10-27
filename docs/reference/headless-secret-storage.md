# Headless credential storage

Orca's Node-based remote runtime (`orcad`) encrypts native integration credentials on the
execution host. The encryption key is separate from the desktop client's credential store.

## Choosing protection

Set `ORCA_HEADLESS_SECRET_STORE` **in the environment of the headless server**, before
starting it. Changing only the desktop client's environment does not affect remote storage.

| Value           | Behavior                                                                                                                                                           |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Unset or `file` | Default. AES-256-GCM credentials use a master key in an owner-only file under `~/.orca`. Anyone who can copy the complete profile or its backups can decrypt them. |
| `keyring`       | Opt-in strict mode. The master key must be available from the host's OS keyring; no file-key or plaintext fallback is allowed.                                     |
| `plaintext`     | Explicitly disables sealing. Only use for isolated, disposable environments that contain no sensitive credentials.                                                 |

On Linux, strict mode requires an accessible D-Bus session and an unlocked Secret Service
provider, such as GNOME Keyring or KWallet, with the `secret-tool` command installed.
A bare SSH or headless service session often has no such session and **will fail closed**.
On macOS, strict mode uses the login Keychain, which may be locked for a server started
over SSH after reboot. Windows does not yet provide a headless OS-keyring backend,
so strict mode refuses to store credentials there.

For a Linux server, check that `command -v secret-tool` succeeds and that the
server process has `DBUS_SESSION_BUS_ADDRESS` set. These checks do **not** prove
the keyring is unlocked; credential operations still require a successful keyring
write and verified readback.

## Migration and recovery

Enabling `keyring` on a server with an existing file-backed key copies the **same**
verified master key into the OS keyring, confirms it can be retrieved, then replaces
the on-disk key record with an OS-keyring reference. The encrypted credential
files do not change. If any step fails, the old key record and ciphertext remain
unchanged; new credential writes are refused for that startup.

An existing legacy `os-keyring` record is likewise checked before conversion to
the strict record format. An older Orca runtime cannot read the strict format and
fails closed instead of silently migrating the key back into a local file.
Once a strict record exists, simply removing `ORCA_HEADLESS_SECRET_STORE=keyring`
does not downgrade it.

**Migration is not key rotation.** Earlier file-backed key copies in backups,
snapshots, or filesystem history may still decrypt the existing credentials.
For protection against historical profile exposure, remove old backup copies
through your own retention policy and rotate affected integration credentials.
Do not delete the active key record or keyring item to force migration.

If the keyring is locked, missing, or unreachable, Orca preserves its encrypted
credentials and refuses new saves. Restore access to the original key and restart
the headless runtime. Deleting the key reference or starting with an unrelated
key does not recover the original ciphertext.

Temporary profiles also refuse plaintext fallback when strict mode is requested.
The explicit `plaintext` opt-out remains an unsafe override and should not be
used with real credentials.
