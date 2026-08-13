# etools

This folder contains 50 independent Rust CLI packages named `x1` through `x50`.
Every package uses Rust edition 2024, declares Rust 1.97.1 as its minimum
supported version, and implements the same interoperable authenticated file
format.

## Apps and algorithms

All 50 `src/main.rs` files are byte-for-byte identical, and their manifests
have the same dependencies apart from the package name. Consequently, every
app performs the same algorithm:

**age v1 passphrase encryption: scrypt, HKDF-SHA-256/HMAC-SHA-256, and
ChaCha20-Poly1305 STREAM.**

At encryption time, age generates a random file key and 16-byte salt. Scrypt
(`r = 8`, `p = 1`, and a calibrated `N = 2^log_n` work factor) derives a
wrapping key from the password. ChaCha20-Poly1305 wraps the file key,
HKDF-SHA-256 derives the header and payload keys, and HMAC-SHA-256
authenticates the header. The file payload is then streamed in authenticated
64 KiB ChaCha20-Poly1305 chunks. Chunk counters and a final-chunk flag detect
modification, reordering, duplication, appended data, and truncation.

| App | Algorithm |
| --- | --- |
| [x1](x1/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x2](x2/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x3](x3/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x4](x4/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x5](x5/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x6](x6/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x7](x7/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x8](x8/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x9](x9/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x10](x10/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x11](x11/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x12](x12/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x13](x13/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x14](x14/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x15](x15/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x16](x16/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x17](x17/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x18](x18/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x19](x19/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x20](x20/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x21](x21/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x22](x22/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x23](x23/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x24](x24/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x25](x25/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x26](x26/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x27](x27/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x28](x28/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x29](x29/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x30](x30/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x31](x31/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x32](x32/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x33](x33/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x34](x34/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x35](x35/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x36](x36/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x37](x37/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x38](x38/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x39](x39/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x40](x40/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x41](x41/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x42](x42/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x43](x43/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x44](x44/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x45](x45/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x46](x46/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x47](x47/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x48](x48/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x49](x49/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |
| [x50](x50/README.md) | age v1 passphrase: scrypt + HKDF/HMAC-SHA-256 + ChaCha20-Poly1305 STREAM |

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
