# x8

`x8` is a password-based file encryptor and decryptor. It reads one regular file and writes the encrypted or recovered bytes to a different path; the input is never changed.

## Algorithm and processing

Cryptography is provided by the exactly pinned `age` 0.12.1 crate. The on-disk format is the binary (unarmored) age v1 passphrase format:

- An age `scrypt` recipient derives a 32-byte wrapping key with scrypt (RFC 7914, `r = 8`, `p = 1`, adaptive `N = 2^log_n`). Encryption generates a fresh 16-byte salt and random file key; age calibrates `log_n` toward about one second of work on the current machine. ChaCha20-Poly1305 wraps the file key.
- HKDF-SHA-256 derives the header MAC key and payload key, and HMAC-SHA-256 authenticates the age header. The age STREAM construction then encrypts and authenticates 64 KiB chunks with ChaCha20-Poly1305, using a per-chunk counter to protect ordering and a final-chunk flag to protect against truncation.

Encryption validates the paths, streams the input into a temporary age file, finishes authentication, flushes and syncs it, then publishes it with a race-safe no-clobber operation. Decryption first limits the age header to 64 KiB, requires exactly the passphrase/scrypt recipient form, authenticates and decrypts the full stream into a temporary file, and publishes the result only after authenticated EOF.

The app encrypts file contents only. It does not compress, archive, preserve filename or metadata, or produce ASCII armor. Re-encrypting the same bytes and password produces different ciphertext.

## Build and use

The package uses Rust edition 2024 and requires Rust 1.97.1 or newer. From the workspace root:

```powershell
cargo build --release --locked -p x8
.\target\release\x8.exe E "input.bin" "input.bin.age"
.\target\release\x8.exe D "input.bin.age" "restored.bin"
```

On Unix-like systems, run `./target/release/x8` instead. The CLI accepts exactly three arguments: uppercase `E` or `D`, an input path, and an output path. File data cannot be supplied through standard input or written to standard output.

At a terminal, the password is read without echo; encryption asks for confirmation. With redirected standard input, the app reads one password line and does not ask for confirmation. A trailing LF or CRLF is removed, but leading and trailing spaces are retained. Passwords must be nonempty and at most 4096 UTF-8 bytes.

## Safety behavior

- The input must resolve to a regular file. Input and output paths must differ, and an existing output is never overwritten—even if it appears while processing.
- Temporary output is created beside the requested destination and removed on ordinary failure. A process or machine crash can leave a dot-prefixed `.x8-*.tmp` file; during decryption, that temporary file can contain plaintext.
- Wrong passwords, damaged or malformed data, excessive scrypt work factors, and unsupported files all fail without publishing the requested output. They share a generic decryption error so the CLI does not distinguish their cause.
- Output data is synced before success; the containing directory is also synced on Unix. Use a strong unique password: forgotten passwords cannot be recovered.

## Compatibility

`x8` interoperates with `x1` through `x50` and with tools that read or write unarmored age v1 passphrase/scrypt files, subject to the 64 KiB header limit and the `age` crate's accepted scrypt work-factor cap. It deliberately rejects recipient-only age files (such as X25519, SSH, or plugin recipients) and does not decode ASCII-armored age text. Empty files, arbitrary binary bytes, and OS-supported Unicode paths are handled.
