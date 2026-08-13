# x19

`x19` encrypts or decrypts one regular file with a human-supplied passphrase.
It streams the file instead of loading it all into memory and leaves the input
unchanged.

## Algorithm and processing

The output is the binary (not ASCII-armored) **age v1 passphrase format**, made
with the pinned `age` 0.12.1 crate. The format uses a random 16-byte salt and
scrypt (RFC 7914, `r = 8`, `p = 1`, runtime-calibrated `N = 2^log_n`) to protect
a random file key. Age authenticates its header with HMAC-SHA-256, derives the
payload key with HKDF-SHA-256, and encrypts the payload as a 64 KiB-chunk STREAM
using ChaCha20-Poly1305. Re-encrypting the same bytes and passphrase therefore
produces different ciphertext.

Encryption writes the age header and authenticated payload to a temporary file
beside the requested output, finishes the stream, syncs it, and commits it only
if the output name is still unused. Decryption limits the header to 64 KiB,
requires exactly one scrypt recipient stanza, authenticates the complete stream
into a temporary file, and publishes plaintext only after authenticated EOF.

## Build and use

From the workspace root (Rust 1.97.1 or newer):

```powershell
cargo build --release -p x19
.\target\release\x19.exe E "input.bin" "input.bin.age"
.\target\release\x19.exe D "input.bin.age" "restored.bin"
```

`E` and `D` must be uppercase, and exactly an input and output path are
required. On a terminal, the password is hidden; encryption asks for it twice.
With redirected standard input, the app reads one password line without
confirmation and removes its LF or CRLF ending. Empty passwords and passwords
over 4096 UTF-8 bytes are rejected; leading and trailing spaces are preserved.

## Safety and compatibility

- Input and output paths must differ, input must be a regular file, and an
  existing output is never overwritten, including if it appears during work.
- Wrong passwords, damaged/reordered/appended/truncated data, malformed files,
  and unauthenticated endings do not publish plaintext. These cases share a
  generic error, so the CLI does not distinguish their causes.
- Temporary files are removed on ordinary failure. A crash can leave a
  dot-prefixed `.x19-*.tmp` file beside the destination; during decryption it
  may contain
  plaintext and should be handled accordingly.
- There is no password recovery. Use a strong, unique passphrase.

Conforming age tools can decrypt files produced here. This app accepts only
binary age v1 files with one passphrase/scrypt stanza, within its header and
scrypt work limits; it rejects ASCII armor, key-recipient or mixed-recipient
files, and unsupported formats. File extensions are not significant.
