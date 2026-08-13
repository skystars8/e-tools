# x32

`x32` is a password-based file encryptor and decryptor. It streams the exact bytes of one regular input file into a separate output file; it does not compress data, store filenames or timestamps, or change/delete the input.

## Algorithm and processing

- **Format:** binary (unarmored) age v1, produced by the pinned `age` 0.12.1 crate, with exactly one passphrase-based `scrypt` recipient stanza.
- **Passphrase protection:** RFC 7914 scrypt uses `r = 8`, `p = 1`, a fresh 16-byte salt, and an adaptive `N` chosen to take about one second on the encrypting machine. Its 256-bit result protects a random file key with ChaCha20-Poly1305.
- **Header and payload protection:** age v1 derives the header MAC key and payload key with HKDF-SHA-256, authenticates the header with HMAC-SHA-256, and uses the STREAM construction with ChaCha20-Poly1305 over authenticated 64 KiB chunks. Fresh randomness makes repeated encryption of the same bytes and password produce different ciphertext.

For encryption, the app validates the paths, opens the input as a regular file, and streams it through the age encryptor into a temporary file beside the requested output. It finishes authentication, flushes and syncs the file, then publishes it with a no-clobber operation.

For decryption, it first limits the parsed age header to 64 KiB and requires a valid scrypt/passphrase file. Plaintext is streamed into a temporary file; the requested output is published only after the complete authenticated stream reaches a valid end.

## Build and use

Rust 1.97.1 or newer is required. From the workspace root:

```console
cargo build --release -p x32
cargo run --release -p x32 -- E "plain.bin" "plain.bin.age"
cargo run --release -p x32 -- D "plain.bin.age" "restored.bin"
cargo test --locked -p x32
```

`E` and `D` must be uppercase, and exactly two paths must follow. At a terminal, the password is hidden and encryption asks for confirmation. With redirected standard input, the app reads one password line without confirmation; it removes the line ending but preserves other spaces. Passwords must be nonempty UTF-8 and at most 4096 bytes.

## Safety behavior

- Input and output paths must differ, the input must be a regular file, and an existing output is never overwritten—even if it appears during processing.
- Wrong passwords, malformed data, changed/reordered/appended chunks, and truncation fail without publishing the requested output. These cases intentionally share one nonspecific error.
- Temporary files are removed on ordinary failure. A crash can leave a dot-prefixed `.x32-*.tmp` file beside the destination; during decryption that file can contain plaintext and should be protected or removed.
- File data is synced before commit; on Unix the output directory is synced too. Choose a strong passphrase: there is no password recovery.

## Compatibility and limits

- Files interoperate with implementations of the binary age v1 scrypt passphrase format, including `age`/`rage` passphrase mode. The filename extension is not significant.
- ASCII-armored age text and public-key/SSH/plugin recipient files are not accepted. Inputs with headers over 64 KiB or scrypt work factors above the pinned age crate's defensive limit are also rejected.
- Empty files and arbitrary binary contents are supported. File metadata is not preserved; choose the output path and metadata separately.
