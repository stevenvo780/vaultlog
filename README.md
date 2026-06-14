# vaultlog

An encrypted journal for the terminal. `vaultlog` is a CLI + TUI diary where every
entry is stored as ciphertext on disk, unlocked with a single master password, and
optionally backed up to a private Git repository without ever committing plaintext.

The code is open source. Your journal data is not part of this repository and must
live in its own private repository (the tool enforces this with a pre-commit hook).

## Features

- **Terminal TUI** (built on [Textual](https://textual.textualize.io/)) with an
  entry list, status bar, markdown editor, manual lock, and a "panic mode" that
  disguises the screen as ordinary source code.
- **Authenticated encryption**: every entry, the manifest, and the verifier are
  sealed with AES-GCM.
- **Password-based key derivation** with PBKDF2-HMAC-SHA256.
- **Configurable autosave** and idle auto-lock.
- **Integrity verification**: the manifest and every entry are decrypted and checked
  before any backup.
- **Encrypted Git backup** into a *separate* private repo, so disk loss doesn't lose
  your journal while plaintext never leaves your machine.
- **Pre-commit safety hook** that blocks recovery notes, secrets, private keys, and
  any non-ciphertext files from being committed to the vault repo.
- **Reproducible `.deb` packaging** so the `vaultlog` command installs self-contained.

## Encryption architecture

Vaultlog never stores your master password. The password is only ever used to derive
an encryption key in memory.

1. **Key derivation.** On `init`, a random 16-byte salt is generated. The master
   password and salt are run through **PBKDF2-HMAC-SHA256** (390,000 iterations) to
   derive a 32-byte key. The salt and iteration count are stored in `config.json`;
   the password and the derived key are not.
2. **Verifier.** A small known payload is encrypted with the derived key and stored
   in the config. On unlock, vaultlog re-derives the key from the entered password
   and attempts to decrypt the verifier — success means the password is correct.
3. **Per-record encryption.** Each entry and the manifest are serialized to JSON and
   sealed with **AES-256-GCM**. A fresh random 12-byte nonce is generated for every
   encryption; GCM provides both confidentiality and tamper detection.
4. **On-disk layout** (inside the vault directory, default `./.vaultlog/`):
   - `config.json` — version, salt, KDF iterations, encrypted verifier, settings.
     (Contains no plaintext content.)
   - `manifest.enc` — encrypted index of entry metadata.
   - `entries/<id>.enc` — one encrypted file per entry.
5. **Password rotation** re-encrypts the entire vault under a new key in a staging
   directory, verifies it decrypts cleanly, and only then atomically swaps it in,
   keeping timestamped backups of the previous state.

If you lose the master password, the encrypted content **cannot** be recovered.
The recovery note stored on disk deliberately does not contain the password — store
the password in a separate password manager or offline.

## Installation

### From source (development)

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
```

This installs the `vaultlog` command.

### Build a Debian package

```bash
scripts/build_deb.sh
```

The resulting `.deb` (in `dist/`) bundles a self-contained virtual environment under
`/opt/vaultlog/venv`, so the installed command does not depend on the checkout.

## Usage

Initialize a vault (you'll be prompted for the master password):

```bash
vaultlog init
```

Open the TUI editor:

```bash
vaultlog open
```

Common commands:

```bash
vaultlog list
vaultlog new --title "private entry" --body-stdin
vaultlog show private-entry --metadata-only
vaultlog verify
vaultlog backup --init-git
vaultlog backup --remote git@github.com:YOU/YOUR_PRIVATE_VAULT.git --push
vaultlog configure --idle-lock-minutes 3 --autosave-seconds 5
vaultlog change-password
vaultlog doctor --verify
vaultlog scrub-recovery
vaultlog install-git-hook
```

### TUI shortcuts

- `Ctrl+N` new entry
- `Ctrl+R` rename entry
- `Ctrl+S` save
- `Ctrl+B` verify, commit, and push the encrypted vault to its private repo
- `Ctrl+L` lock the session
- `F8` panic mode (camouflage the screen)
- `Ctrl+G` focus the entry list
- `Ctrl+E` focus the editor
- `Ctrl+Q` quit

## Security notes

- The recovery note never stores the master password. If the password is lost, the
  encrypted content is unrecoverable. Git backups protect against disk loss, not a
  forgotten password.
- Avoid `vaultlog new --body "secret text"`: it can leak into shell history or the
  process list. Use `--body-stdin` or the TUI instead.
- `vaultlog show` prints plaintext to the terminal. Use `--metadata-only` to avoid
  leaving content in scrollback.
- Keep your vault data in **its own private Git repo**, never in the code repo. The
  pre-commit hook (`vaultlog install-git-hook`) blocks plaintext, recovery notes,
  secrets, and private keys from being committed.
- Git history of the vault repo retains old ciphertext. If an old password ever
  leaked, rotate the password and consider purging the remote history.

## Development

Run the test suite:

```bash
.venv/bin/python -m unittest discover -s tests
```

## License

MIT
