# Security

If you discover a vulnerability, please email: akai@buiver.jp
We appreciate responsible disclosure. We will respond as soon as possible.

- Scope: BMSC v6 codebase and distributed artifacts
- Preferred language: Japanese or English

## Key management (K_master)

BMSC v6 assumes a 32-byte master key `K_master` per deployment.

- `K_master` SHOULD be stored in a dedicated key file (e.g. `key_cli.bin`)
  that is protected by the operating system (ACLs, key store, etc.).
- On Windows, we recommend storing the key file under a private directory
  (e.g. `%USERPROFILE%\bmsc_keys\`) and restricting access to the user
  account + `SYSTEM` only. See `docs/ops/windows_key_protection.md`.
- A backup of the key file SHOULD be kept offline (e.g. on removable media).
  If `K_master` is lost and no backup exists, data encrypted under that key
  will be unrecoverable by design.
- In v0.1.0, BMSC v6 assumes a single master key per environment.
  Future versions may add explicit key IDs and rotation support.
