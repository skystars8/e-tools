use age::secrecy::{ExposeSecret, SecretString};
use std::{
    env,
    error::Error,
    ffi::{OsStr, OsString},
    fmt,
    fs::File,
    io::{self, BufRead, BufReader, BufWriter, IsTerminal, Read, Seek, SeekFrom, Write},
    iter,
    path::{Path, PathBuf},
    process::ExitCode,
};

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const BUFFER_SIZE: usize = 64 * 1024;
const MAX_AGE_HEADER_BYTES: usize = 64 * 1024;
const MAX_PASSWORD_BYTES: usize = 4096;

type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Clone, Eq, PartialEq)]
struct AppError(String);

impl AppError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for AppError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Encrypt,
    Decrypt,
}

#[derive(Debug, Eq, PartialEq)]
struct Command {
    mode: Mode,
    input: PathBuf,
    output: PathBuf,
}

fn main() -> ExitCode {
    match run_cli() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{APP_NAME}: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_cli() -> AppResult<()> {
    let command = parse_args(env::args_os().skip(1))?;
    let password = read_password(command.mode)?;

    match command.mode {
        Mode::Encrypt => encrypt_file(&command.input, &command.output, password),
        Mode::Decrypt => decrypt_file(&command.input, &command.output, password),
    }
}

fn usage() -> String {
    format!("Usage: {APP_NAME} E <input> <output>\n       {APP_NAME} D <input> <output>")
}

fn parse_args(args: impl IntoIterator<Item = OsString>) -> AppResult<Command> {
    let args: Vec<OsString> = args.into_iter().collect();
    if args.len() != 3 {
        return Err(AppError::new(usage()));
    }

    let mode = if args[0] == OsStr::new("E") {
        Mode::Encrypt
    } else if args[0] == OsStr::new("D") {
        Mode::Decrypt
    } else {
        return Err(AppError::new(format!(
            "mode must be uppercase E or D\n{}",
            usage()
        )));
    };

    Ok(Command {
        mode,
        input: PathBuf::from(&args[1]),
        output: PathBuf::from(&args[2]),
    })
}

fn read_password(mode: Mode) -> AppResult<SecretString> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        let password = {
            let password = rpassword::prompt_password("Password: ")
                .map_err(|error| AppError::new(format!("could not read password: {error}")))?;
            SecretString::from(password)
        };
        validate_password(password.expose_secret())?;

        if mode == Mode::Encrypt {
            let confirmation = {
                let confirmation = rpassword::prompt_password("Confirm password: ")
                    .map_err(|error| AppError::new(format!("could not read password: {error}")))?;
                SecretString::from(confirmation)
            };
            if password.expose_secret() != confirmation.expose_secret() {
                return Err(AppError::new("passwords do not match"));
            }
        }
        Ok(password)
    } else {
        Ok(SecretString::from(read_password_line(&mut stdin.lock())?))
    }
}

fn read_password_line(reader: &mut impl BufRead) -> AppResult<String> {
    let mut password = String::new();
    let bytes_read = reader
        .take((MAX_PASSWORD_BYTES + 3) as u64)
        .read_line(&mut password)
        .map_err(|error| AppError::new(format!("could not read password: {error}")))?;
    if bytes_read == 0 {
        return Err(AppError::new("no password was provided"));
    }

    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
    validate_password(&password)?;
    Ok(password)
}

fn validate_password(password: &str) -> AppResult<()> {
    if password.is_empty() {
        return Err(AppError::new("password must not be empty"));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(AppError::new(format!(
            "password must be at most {MAX_PASSWORD_BYTES} bytes"
        )));
    }
    Ok(())
}

fn encrypt_file(input: &Path, output: &Path, password: SecretString) -> AppResult<()> {
    encrypt_file_with_work_factor(input, output, password, None)
}

fn encrypt_file_with_work_factor(
    input: &Path,
    output: &Path,
    password: SecretString,
    work_factor: Option<u8>,
) -> AppResult<()> {
    validate_paths(input, output)?;
    let input_file = open_regular_file(input)?;
    let mut input_reader = BufReader::with_capacity(BUFFER_SIZE, input_file);
    let mut temporary = create_temporary_output(output)?;

    {
        let output_writer = BufWriter::with_capacity(BUFFER_SIZE, temporary.as_file_mut());
        let encryptor = match work_factor {
            Some(log_n) => {
                let mut recipient = age::scrypt::Recipient::new(password);
                recipient.set_work_factor(log_n);
                age::Encryptor::with_recipients(iter::once(&recipient as &dyn age::Recipient))
                    .map_err(|_| AppError::new("encryption could not be initialized"))?
            }
            None => age::Encryptor::with_user_passphrase(password),
        };
        let mut encrypted_writer = encryptor
            .wrap_output(output_writer)
            .map_err(|_| AppError::new("encryption could not be initialized"))?;

        io::copy(&mut input_reader, &mut encrypted_writer)
            .map_err(|error| AppError::new(format!("encryption failed: {error}")))?;
        let mut output_writer = encrypted_writer
            .finish()
            .map_err(|error| AppError::new(format!("encryption failed: {error}")))?;
        output_writer
            .flush()
            .map_err(|error| AppError::new(format!("could not flush output: {error}")))?;
    }

    commit_output(temporary, output)
}

fn decrypt_file(input: &Path, output: &Path, password: SecretString) -> AppResult<()> {
    validate_paths(input, output)?;
    let mut input_file = open_regular_file(input)?;
    enforce_age_header_limit(&mut input_file)?;
    let input_reader = BufReader::with_capacity(BUFFER_SIZE, input_file);
    let decryptor = age::Decryptor::new_buffered(input_reader).map_err(|_| integrity_error())?;
    if !decryptor.is_scrypt() {
        return Err(integrity_error());
    }

    let identity = age::scrypt::Identity::new(password);
    let mut decrypted_reader = decryptor
        .decrypt(iter::once(&identity as &dyn age::Identity))
        .map_err(|_| integrity_error())?;
    let mut temporary = create_temporary_output(output)?;

    {
        let mut output_writer = BufWriter::with_capacity(BUFFER_SIZE, temporary.as_file_mut());
        io::copy(&mut decrypted_reader, &mut output_writer).map_err(|_| integrity_error())?;
        output_writer
            .flush()
            .map_err(|error| AppError::new(format!("could not flush output: {error}")))?;
    }

    commit_output(temporary, output)
}

fn integrity_error() -> AppError {
    AppError::new("decryption failed: wrong password, damaged data, or unsupported file")
}

fn enforce_age_header_limit(input: &mut File) -> AppResult<()> {
    {
        let limited = input.take((MAX_AGE_HEADER_BYTES + 1) as u64);
        let mut reader = BufReader::with_capacity(8 * 1024, limited);
        let mut total = 0;
        let mut line = Vec::new();

        loop {
            line.clear();
            let bytes_read = reader
                .read_until(b'\n', &mut line)
                .map_err(|_| integrity_error())?;
            total += bytes_read;

            if total > MAX_AGE_HEADER_BYTES || bytes_read == 0 {
                return Err(integrity_error());
            }
            if line.starts_with(b"--- ") && line.ends_with(b"\n") {
                break;
            }
        }
    }

    input
        .seek(SeekFrom::Start(0))
        .map_err(|_| integrity_error())?;
    Ok(())
}

fn validate_paths(input: &Path, output: &Path) -> AppResult<()> {
    if input == output {
        return Err(AppError::new("input and output must be different files"));
    }

    match output.try_exists() {
        Ok(true) => Err(AppError::new(format!(
            "output already exists: {}",
            output.display()
        ))),
        Ok(false) => Ok(()),
        Err(error) => Err(AppError::new(format!(
            "could not inspect output '{}': {error}",
            output.display()
        ))),
    }
}

fn open_regular_file(path: &Path) -> AppResult<File> {
    let file = File::open(path).map_err(|error| {
        AppError::new(format!(
            "could not open input '{}': {error}",
            path.display()
        ))
    })?;
    let metadata = file.metadata().map_err(|error| {
        AppError::new(format!(
            "could not inspect input '{}': {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(AppError::new(format!(
            "input is not a regular file: {}",
            path.display()
        )));
    }
    Ok(file)
}

fn output_parent(output: &Path) -> &Path {
    output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn create_temporary_output(output: &Path) -> AppResult<tempfile::NamedTempFile> {
    tempfile::Builder::new()
        .prefix(&format!(".{APP_NAME}-"))
        .suffix(".tmp")
        .tempfile_in(output_parent(output))
        .map_err(|error| {
            AppError::new(format!(
                "could not create temporary output beside '{}': {error}",
                output.display()
            ))
        })
}

fn commit_output(temporary: tempfile::NamedTempFile, output: &Path) -> AppResult<()> {
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| AppError::new(format!("could not sync output data: {error}")))?;

    let committed = temporary.persist_noclobber(output).map_err(|error| {
        AppError::new(format!(
            "could not create output '{}': {}",
            output.display(),
            error.error
        ))
    })?;
    committed
        .sync_all()
        .map_err(|error| AppError::new(format!("could not sync output data: {error}")))?;
    sync_output_directory(output_parent(output))
}

#[cfg(unix)]
fn sync_output_directory(directory: &Path) -> AppResult<()> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            AppError::new(format!(
                "output was created, but its directory could not be synced: {error}"
            ))
        })
}

#[cfg(not(unix))]
fn sync_output_directory(_directory: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsString, fs, io::Cursor};
    use tempfile::TempDir;

    const TEST_LOG_N: u8 = 4;
    const PASSWORD: &str = "correct horse battery staple";

    fn secret(value: &str) -> SecretString {
        SecretString::from(value.to_owned())
    }

    fn deterministic_bytes(length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| ((index.wrapping_mul(31) ^ (index / 251)) & 0xff) as u8)
            .collect()
    }

    fn encrypt_fast(input: &Path, output: &Path, password: &str) -> AppResult<()> {
        encrypt_file_with_work_factor(input, output, secret(password), Some(TEST_LOG_N))
    }

    fn round_trip_in(directory: &Path, name: &str, data: &[u8], password: &str) {
        let input = directory.join(format!("{name}.input"));
        let encrypted = directory.join(format!("{name}.age"));
        let output = directory.join(format!("{name}.output"));
        fs::write(&input, data).unwrap();
        encrypt_fast(&input, &encrypted, password).unwrap();
        decrypt_file(&encrypted, &output, secret(password)).unwrap();
        assert_eq!(fs::read(output).unwrap(), data);
        assert_eq!(fs::read(input).unwrap(), data);
    }

    #[test]
    fn round_trips_empty_binary_and_stream_boundaries() {
        let directory = TempDir::new().unwrap();
        for (index, length) in [
            0,
            1,
            255,
            BUFFER_SIZE - 1,
            BUFFER_SIZE,
            BUFFER_SIZE + 1,
            2 * BUFFER_SIZE,
            2 * BUFFER_SIZE + 1,
            1024 * 1024,
        ]
        .into_iter()
        .enumerate()
        {
            round_trip_in(
                directory.path(),
                &format!("case-{index}"),
                &deterministic_bytes(length),
                PASSWORD,
            );
        }
    }

    #[test]
    fn supports_unicode_paths_and_passwords_without_trimming_spaces() {
        let directory = TempDir::new().unwrap();
        let data = b"spaces, unicode, and binary: \0\xff";
        round_trip_in(directory.path(), "snowman ☃ file", data, "  päss phrase  ");
    }

    #[test]
    fn encryption_is_randomized() {
        let directory = TempDir::new().unwrap();
        let input = directory.path().join("input");
        let first = directory.path().join("first.age");
        let second = directory.path().join("second.age");
        fs::write(&input, deterministic_bytes(4096)).unwrap();
        encrypt_fast(&input, &first, PASSWORD).unwrap();
        encrypt_fast(&input, &second, PASSWORD).unwrap();
        assert_ne!(fs::read(first).unwrap(), fs::read(second).unwrap());
    }

    #[test]
    fn wrong_password_never_publishes_plaintext() {
        let directory = TempDir::new().unwrap();
        let input = directory.path().join("input");
        let encrypted = directory.path().join("encrypted");
        let output = directory.path().join("output");
        fs::write(&input, b"secret data").unwrap();
        encrypt_fast(&input, &encrypted, PASSWORD).unwrap();

        let error = decrypt_file(&encrypted, &output, secret("wrong password")).unwrap_err();
        assert_eq!(error, integrity_error());
        assert!(!output.exists());
        assert_eq!(fs::read(input).unwrap(), b"secret data");
    }

    #[test]
    fn bit_flips_in_header_payload_and_tag_are_detected() {
        let directory = TempDir::new().unwrap();
        let input = directory.path().join("input");
        let encrypted = directory.path().join("encrypted");
        fs::write(&input, deterministic_bytes(BUFFER_SIZE + 333)).unwrap();
        encrypt_fast(&input, &encrypted, PASSWORD).unwrap();
        let original = fs::read(&encrypted).unwrap();

        let positions = [
            0,
            original.len() / 4,
            original.len() / 2,
            original.len() - 1,
        ];
        for (index, position) in positions.into_iter().enumerate() {
            let damaged = directory.path().join(format!("damaged-{index}"));
            let output = directory.path().join(format!("output-{index}"));
            let mut bytes = original.clone();
            bytes[position] ^= 0x80;
            fs::write(&damaged, bytes).unwrap();
            assert!(decrypt_file(&damaged, &output, secret(PASSWORD)).is_err());
            assert!(!output.exists());
        }
    }

    #[test]
    fn all_truncations_of_a_small_ciphertext_are_detected() {
        let directory = TempDir::new().unwrap();
        let input = directory.path().join("input");
        let encrypted = directory.path().join("encrypted");
        fs::write(&input, b"short authenticated message").unwrap();
        encrypt_fast(&input, &encrypted, PASSWORD).unwrap();
        let original = fs::read(&encrypted).unwrap();

        for length in 0..original.len() {
            let damaged = directory.path().join("truncated");
            let output = directory.path().join("output");
            fs::write(&damaged, &original[..length]).unwrap();
            assert!(decrypt_file(&damaged, &output, secret(PASSWORD)).is_err());
            assert!(!output.exists());
        }
    }

    #[test]
    fn removing_a_complete_authenticated_chunk_is_detected() {
        let directory = TempDir::new().unwrap();
        let input = directory.path().join("input");
        let encrypted = directory.path().join("encrypted");
        let damaged = directory.path().join("damaged");
        let output = directory.path().join("output");
        fs::write(&input, deterministic_bytes(2 * BUFFER_SIZE)).unwrap();
        encrypt_fast(&input, &encrypted, PASSWORD).unwrap();
        let bytes = fs::read(encrypted).unwrap();
        fs::write(&damaged, &bytes[..bytes.len() - (BUFFER_SIZE + 16)]).unwrap();

        assert!(decrypt_file(&damaged, &output, secret(PASSWORD)).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn appended_data_is_detected() {
        let directory = TempDir::new().unwrap();
        let input = directory.path().join("input");
        let encrypted = directory.path().join("encrypted");
        let damaged = directory.path().join("damaged");
        let output = directory.path().join("output");
        fs::write(&input, deterministic_bytes(1024)).unwrap();
        encrypt_fast(&input, &encrypted, PASSWORD).unwrap();
        let mut bytes = fs::read(encrypted).unwrap();
        bytes.extend_from_slice(b"unauthenticated suffix");
        fs::write(&damaged, bytes).unwrap();

        assert!(decrypt_file(&damaged, &output, secret(PASSWORD)).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn existing_outputs_are_never_overwritten() {
        let directory = TempDir::new().unwrap();
        let input = directory.path().join("input");
        let encrypted = directory.path().join("encrypted");
        let recovered = directory.path().join("recovered");
        fs::write(&input, b"source remains intact").unwrap();
        fs::write(&encrypted, b"encryption sentinel").unwrap();
        assert!(encrypt_fast(&input, &encrypted, PASSWORD).is_err());
        assert_eq!(fs::read(&encrypted).unwrap(), b"encryption sentinel");
        assert_eq!(fs::read(&input).unwrap(), b"source remains intact");

        fs::remove_file(&encrypted).unwrap();
        encrypt_fast(&input, &encrypted, PASSWORD).unwrap();
        fs::write(&recovered, b"decryption sentinel").unwrap();
        assert!(decrypt_file(&encrypted, &recovered, secret(PASSWORD)).is_err());
        assert_eq!(fs::read(recovered).unwrap(), b"decryption sentinel");
        assert_eq!(fs::read(input).unwrap(), b"source remains intact");
    }

    #[test]
    fn same_input_and_output_is_rejected_without_changes() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("same");
        fs::write(&path, b"do not change").unwrap();
        let error = encrypt_fast(&path, &path, PASSWORD).unwrap_err();
        assert_eq!(
            error,
            AppError::new("input and output must be different files")
        );
        assert_eq!(fs::read(path).unwrap(), b"do not change");
    }

    #[test]
    fn malformed_and_non_passphrase_files_are_rejected() {
        let directory = TempDir::new().unwrap();
        for (index, malformed) in [Vec::new(), b"not an age file".to_vec()]
            .into_iter()
            .enumerate()
        {
            let input = directory.path().join(format!("malformed-{index}"));
            let output = directory.path().join(format!("output-{index}"));
            fs::write(&input, malformed).unwrap();
            assert!(decrypt_file(&input, &output, secret(PASSWORD)).is_err());
            assert!(!output.exists());
        }

        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        let encrypted = age::encrypt(&recipient, b"not passphrase encrypted").unwrap();
        let input = directory.path().join("recipient-encrypted");
        let output = directory.path().join("recipient-output");
        fs::write(&input, encrypted).unwrap();
        assert!(decrypt_file(&input, &output, secret(PASSWORD)).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn oversized_headers_are_rejected_without_publishing_output() {
        let directory = TempDir::new().unwrap();
        let input = directory.path().join("oversized-header");
        let output = directory.path().join("output");
        let mut bytes = b"age-encryption.org/v1\n-> scrypt ".to_vec();
        bytes.extend(vec![b'A'; MAX_AGE_HEADER_BYTES + 1]);
        fs::write(&input, bytes).unwrap();

        assert_eq!(
            decrypt_file(&input, &output, secret(PASSWORD)).unwrap_err(),
            integrity_error()
        );
        assert!(!output.exists());
    }

    #[test]
    fn reordered_and_duplicated_chunks_are_detected() {
        let directory = TempDir::new().unwrap();
        let input = directory.path().join("input");
        let encrypted = directory.path().join("encrypted");
        fs::write(&input, deterministic_bytes(3 * BUFFER_SIZE + 123)).unwrap();
        encrypt_fast(&input, &encrypted, PASSWORD).unwrap();
        let original = fs::read(&encrypted).unwrap();

        let footer = original
            .windows(5)
            .position(|window| window == b"\n--- ")
            .unwrap();
        let payload = footer
            + 1
            + original[footer + 1..]
                .iter()
                .position(|byte| *byte == b'\n')
                .unwrap()
            + 1;
        let first_chunk = payload + 16;
        let record_size = BUFFER_SIZE + 16;

        let mut reordered = original.clone();
        reordered[first_chunk..first_chunk + 2 * record_size].rotate_left(record_size);
        let reordered_path = directory.path().join("reordered");
        let reordered_output = directory.path().join("reordered-output");
        fs::write(&reordered_path, reordered).unwrap();
        assert!(decrypt_file(&reordered_path, &reordered_output, secret(PASSWORD)).is_err());
        assert!(!reordered_output.exists());

        let mut duplicated = original;
        let first_record = duplicated[first_chunk..first_chunk + record_size].to_vec();
        duplicated[first_chunk + record_size..first_chunk + 2 * record_size]
            .copy_from_slice(&first_record);
        let duplicated_path = directory.path().join("duplicated");
        let duplicated_output = directory.path().join("duplicated-output");
        fs::write(&duplicated_path, duplicated).unwrap();
        assert!(decrypt_file(&duplicated_path, &duplicated_output, secret(PASSWORD)).is_err());
        assert!(!duplicated_output.exists());
    }

    #[test]
    fn commit_never_clobbers_an_output_created_during_processing() {
        let directory = TempDir::new().unwrap();
        let output = directory.path().join("output");
        let mut temporary = create_temporary_output(&output).unwrap();
        temporary.write_all(b"new data").unwrap();
        fs::write(&output, b"race winner").unwrap();

        assert!(commit_output(temporary, &output).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"race winner");
        let leftovers: Vec<_> = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with(&format!(".{APP_NAME}-")))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temporary files remain: {leftovers:?}"
        );
    }

    #[test]
    fn failures_remove_temporary_output_files() {
        let directory = TempDir::new().unwrap();
        let input = directory.path().join("input");
        let encrypted = directory.path().join("encrypted");
        let output = directory.path().join("output");
        fs::write(&input, b"secret").unwrap();
        encrypt_fast(&input, &encrypted, PASSWORD).unwrap();
        let mut damaged = fs::read(&encrypted).unwrap();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        fs::write(&encrypted, damaged).unwrap();
        assert!(decrypt_file(&encrypted, &output, secret(PASSWORD)).is_err());
        assert!(!output.exists());

        let leftovers: Vec<_> = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with(&format!(".{APP_NAME}-")))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temporary files remain: {leftovers:?}"
        );
    }

    #[test]
    fn parser_accepts_only_the_minimal_uppercase_contract() {
        let command = parse_args([
            OsString::from("E"),
            OsString::from("input file"),
            OsString::from("output file"),
        ])
        .unwrap();
        assert_eq!(command.mode, Mode::Encrypt);
        assert_eq!(command.input, Path::new("input file"));
        assert_eq!(command.output, Path::new("output file"));

        assert!(
            parse_args([
                OsString::from("D"),
                OsString::from("in"),
                OsString::from("out")
            ])
            .is_ok()
        );
        for invalid in ["e", "d", "X", "encrypt", ""] {
            assert!(
                parse_args([
                    OsString::from(invalid),
                    OsString::from("in"),
                    OsString::from("out"),
                ])
                .is_err()
            );
        }
        assert!(parse_args(Vec::<OsString>::new()).is_err());
        assert!(parse_args([OsString::from("E"), OsString::from("in")]).is_err());
        assert!(
            parse_args([
                OsString::from("E"),
                OsString::from("in"),
                OsString::from("out"),
                OsString::from("extra"),
            ])
            .is_err()
        );
    }

    #[test]
    fn piped_password_reader_handles_crlf_and_preserves_spaces() {
        let mut crlf = Cursor::new(b"  pass phrase  \r\nignored\n");
        assert_eq!(read_password_line(&mut crlf).unwrap(), "  pass phrase  ");

        let mut empty = Cursor::new(b"\n");
        assert!(read_password_line(&mut empty).is_err());

        let mut missing = Cursor::new(Vec::<u8>::new());
        assert!(read_password_line(&mut missing).is_err());

        let mut too_long = Cursor::new(format!("{}\n", "x".repeat(MAX_PASSWORD_BYTES + 1)));
        assert!(read_password_line(&mut too_long).is_err());
    }

    #[test]
    fn directories_are_not_accepted_as_input_files() {
        let directory = TempDir::new().unwrap();
        let output = directory.path().join("output");
        assert!(encrypt_fast(directory.path(), &output, PASSWORD).is_err());
        assert!(!output.exists());
    }
}
