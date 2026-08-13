# etools

This folder contains 50 independent Rust CLI packages named `x1` through `x50`.
Every package uses Rust edition 2024, declares Rust 1.97.1 as its minimum
supported version, and implements the same interoperable authenticated file
format.

## Minimal use

Build one app from this directory:

~~~powershell
cargo build --release -p x1
~~~

Encrypt or decrypt with exactly a mode, input path, and output path:

~~~powershell
.\target\release\x1.exe E "input file.bin" "encrypted file.age"
.\target\release\x1.exe D "encrypted file.age" "restored file.bin"
~~~

`E` and `D` are intentionally uppercase. The app securely prompts for the
password; encryption asks for confirmation when used in a terminal. When
standard input is piped, one password line is read so the CLI can be automated
without placing a password in process arguments or an environment variable.

All 50 apps use the age v1 passphrase format, so (for example) `x50` can decrypt
a file encrypted by `x1`.

## Safety and integrity

- A per-file random salt and adaptive scrypt work factor protect human
  passphrases.
- Authenticated streaming encryption detects wrong passwords, modified data,
  reordered data, appended data, and truncation, including removal of a whole
  authenticated chunk.
- File data is streamed with bounded memory instead of loading an entire file.
- The requested output is published only after encryption finishes or after
  decryption reaches an authenticated end of file.
- Existing output paths are never overwritten, and input files are never
  changed or deleted.
- Temporary outputs are created beside the requested output and are removed on
  ordinary failure. A machine crash can leave a randomly named `.xN-*.tmp`
  file; during decryption that temporary file can contain plaintext.

Choose a strong, unique passphrase and keep it safe. There is no recovery
mechanism for a forgotten passphrase.

## Verification

Each package contains 18 unit tests plus a real-binary integration test. Across
the workspace that is 950 package-local tests covering exact binary round
trips, empty and multi-chunk files, production scrypt settings, randomized
ciphertexts, wrong passwords, bit flips, truncation at every byte of a small
ciphertext, whole-chunk removal, reordered and duplicated chunks, appended
data, oversized and malformed headers, race-safe non-overwrite behavior,
cleanup, Unicode paths, password input, CLI parsing, process exit status, and
secret-free captured output.

~~~powershell
cargo test --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
~~~

Dependency versions are recorded in the workspace `Cargo.lock`; the direct
cryptography and file-handling dependencies are also pinned exactly in every
package manifest.
