# x46

x46 is a standalone Rust CLI for password-based file encryption and
decryption. It implements the same interoperable format and behavior as the
other x1-x50 packages.

## Algorithm

**age v1 passphrase encryption: scrypt, HKDF-SHA-256/HMAC-SHA-256, and
ChaCha20-Poly1305 STREAM.**

Encryption generates a random file key and a 16-byte salt. The age library
calibrates scrypt's N = 2^log_n work factor to take about one second on the
current machine (with r = 8 and p = 1), then uses the passphrase-derived key to
wrap the file key with ChaCha20-Poly1305. HKDF-SHA-256 derives the header and
payload keys, and HMAC-SHA-256 authenticates the age header.

The payload is encrypted online in authenticated 64 KiB chunks with
ChaCha20-Poly1305. A counter and final-chunk flag bind every chunk to its
position and detect reordering, duplication, appended data, or truncation.
Decryption reverses this process and accepts only age v1 scrypt/passphrase
files.

## Build and use

Run these commands from the workspace root:

~~~powershell
cargo build --release -p x46
.\target\release\x46.exe E "input.bin" "encrypted.age"
.\target\release\x46.exe D "encrypted.age" "restored.bin"
~~~

E and D are uppercase. The password is read securely from the terminal;
encryption asks for confirmation. Piped input may provide one password line.

## File-safety behavior

- Input must be a regular file, and input and output paths must differ.
- Existing outputs are never overwritten.
- Data is streamed with bounded memory through 64 KiB buffers.
- A temporary file beside the destination is committed only after the complete
  authenticated stream succeeds.
- Ordinary failures remove the temporary file. A machine crash can leave a
  .x46-*.tmp file; during decryption, that file can contain plaintext.
- Decryption rejects malformed or non-passphrase age files and caps the parsed
  header at 64 KiB.

x46 files are compatible with x1 through x50 and other implementations of the
age v1 passphrase format. Run its tests with cargo test -p x46 --locked.

[Workspace overview](../README.md)
