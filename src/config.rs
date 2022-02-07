// This file is part of Tomb Drive
//
// Copyright 2022 Martin Furman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Provides configuration parsing and management functionality, including
//! the command line argument parser, verbosity level configuration, and
//! the [`Config`] struct that holds the configuration of the running instance.

use std::sync::atomic::{self, Ordering};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::ptr;

use clap::{App, Arg, ArgGroup, ArgMatches};
use log::{debug, error, trace};
use termion::input::TermRead;

// ================= //
//     Constants     //
// ================= //

const DECRYPT: &str = "decrypt";
const ENCRYPT: &str = "encrypt";
const FORCE: &str = "force";
const FOREGROUND: &str = "foreground";
const MOUNT: &str = "mount";
const OPERATION: &str = "operation";
const PASSFILE: &str = "passfile";
const SINGLE_THREADED: &str = "single-threaded";
const SOURCE: &str = "source";
const TARGET: &str = "target";
const VERBOSE: &str = "verbose";

// ================= //
//     OPERATION     //
// ================= //

/// Tomb Drive is capable of both encrypting and decrypting (as it would
/// be pretty useless otherwise). [`Operation`] holds which of these
/// should be performed.
#[derive(Clone, Copy)]
#[derive(Debug)]
#[derive(PartialEq, Eq)]
pub enum Operation {
    /// Decrypt a single file, or mount a decrypted (plaintext)
    /// representation of a directory as a filesystem
    Decrypt,
    /// Encrypt a single file, or mount an encrypted (ciphertext)
    /// representation of a directory as a filesystem
    Encrypt,
}

// ================== //
//     PASSPHRASE     //
// ================== //

/// [`Passphrase`] wraps a vector of bytes and makes sure it's zeroed out
/// when the memory is released.
#[derive(Debug)]
pub struct Passphrase {
    raw: Vec<u8>,
}

impl From<Vec<u8>> for Passphrase {
    /// Move a vector of bytes into a newly created [`Passphrase`].
    #[inline]
    fn from(raw: Vec<u8>) -> Self {
        trace!("Creating a new passphrase");
        Self { raw }
    }
}

impl AsRef<[u8]> for Passphrase {
    /// Return a borrowed reference to the passphrase.
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.raw.as_ref()
    }
}

impl Drop for Passphrase {
    /// Make sure the values are zeroed out before releasing the memory.
    fn drop(&mut self) {
        trace!("Dropping passphrase");
        let zero = b'\0';
        for b in self.raw.iter_mut() {
            unsafe { ptr::write_volatile(b, zero) };
        }
        atomic::compiler_fence(Ordering::SeqCst);
    }
}

// ============== //
//     CONFIG     //
// ============== //

/// [`Config`] holds the configuration of the running instance, such as
/// whether the instance should mount a virtual filesystem or process a single
/// file, as well as the details about the execution, such as whether the
/// process should be demonised or run in the foreground, etc.
///
/// Calling `new()` will parse command line arguments and return a struct that
/// can then be queried via its accessor functions.
#[derive(Debug)]
pub struct Config {
    // For details of individual fields,
    // see accessor functions documentation below.
    force: bool,
    foreground: bool,
    mount: bool,
    operation: Operation,
    passphrase: Passphrase,
    single_threaded: bool,
    source: PathBuf,
    target: PathBuf,
}

impl Config {
    /// Create a new [`Config`] by parsing command line arguments.
    ///
    /// If the passphrase is specified via the passfile argument, the file will
    /// be opened to load the passphrase.
    ///
    /// If the passfile argument is not specified, the passphrase will be
    /// requested interactively.
    pub fn new() -> Self {
        let args = parse_arguments();

        let logger_env = match args.occurrences_of(VERBOSE) {
            1 => env_logger::Env::default().filter("debug"),
            2 => env_logger::Env::default().filter("trace"),
            _ => env_logger::Env::default().default_filter_or("info"),
        };
        env_logger::Builder::from_env(logger_env).init();
        debug!("Verbosity set to: {}", log::max_level());

        let force = args.is_present(FORCE);
        let foreground = args.is_present(FOREGROUND);
        let mount = args.is_present(MOUNT);
        let single_threaded = args.is_present(SINGLE_THREADED);

        // operation

        let operation = if args.is_present(DECRYPT) {
            Operation::Decrypt
        } else if args.is_present(ENCRYPT) {
            Operation::Encrypt
        } else {
            unreachable!()
        };

        // source

        let source_arg = args.value_of(SOURCE)
                             .expect("Missing <source> argument");
        let source = match fs::canonicalize(source_arg) {
            Ok(source_path) if mount => source_directory(source_path),
            Ok(source_path) /* !mount */ => source_file(source_path),
            Err(err) => {
                error!("Source: {}", err);
                process::exit(libc::EINVAL);
            },
        };

        // target

        let target_arg = args.value_of(TARGET)
                             .expect("Missing <target> argument");
        let target_path = PathBuf::from(target_arg);
        let target = if mount {
            target_directory(&source, target_path)
        } else {
            target_file(&source, target_path, force)
        };

        // passphrase

        let passphrase_raw = match args.value_of(PASSFILE) {
            Some(path) => passphrase_from_file(path),
            None => passphrase_from_input(operation),
        };
        let passphrase = Passphrase { raw: passphrase_raw };

        // return

        debug!(concat!("Loaded the following configuration:\n",
                       " - force: {}\n",
                       " - foreground: {}\n",
                       " - mount: {}\n",
                       " - passphrase: **hidden**\n",
                       " - single_threaded: {}\n",
                       " - source: {:?}\n",
                       " - target: {:?}"),
               force,
               foreground,
               mount,
               single_threaded,
               source,
               target);

        Self {
            force,
            foreground,
            mount,
            operation,
            passphrase,
            single_threaded,
            source,
            target,
        }
    }

    // Accessor Functions

    /// If the target file exists, overwrite it.
    #[inline]
    pub fn force(&self) -> bool { self.force }

    /// Run as a foreground process, do not daemonize.
    #[inline]
    pub fn foreground(&self) -> bool { self.foreground }

    /// Mount a virtual filesystem instead of processing a single file.
    #[inline]
    pub fn mount(&self) -> bool { self.mount }

    /// [`Operation::Encrypt`] will transform plaintext into ciphertext,
    /// while [`Operation::Decrypt`] will transform ciphertext into plaintext.
    #[inline]
    pub fn operation(&self) -> Operation { self.operation }

    /// Return a reference to the passphrase.
    #[inline]
    pub fn passphrase(&self) -> &Passphrase { &self.passphrase }

    /// Mount the filesystem synchronously rather than asynchronously.
    #[inline]
    pub fn single_threaded(&self) -> bool { self.single_threaded }

    /// Get [`Path`] to the source file/directory.
    #[inline]
    pub fn source(&self) -> &Path { self.source.as_path() }

    /// Get [`Path`] to the target file/directory.
    #[inline]
    pub fn target(&self) -> &Path { self.target.as_path() }
}

// ======================== //
//     Helper Functions     //
// ======================== //

/// Parse command line arguments.
fn parse_arguments() -> ArgMatches {
    App::new(clap::crate_name!())
        .about(clap::crate_description!())
        .version(clap::crate_version!())
        .after_help(concat!("If <passfile> is not provided, ",
                            "the passphrase will be requested interactively"))
        .arg(Arg::new(ENCRYPT)
            .short('e')
            .long("encrypt")
            .help("Encrypt a single file / mount an encrypted representation of a folder")
            .display_order(0)
        )
        .arg(Arg::new(DECRYPT)
            .short('d')
            .long("decrypt")
            .help("Decrypt a single file / mount a decrypted representation of a folder")
            .display_order(1)
        )
        .group(ArgGroup::new(OPERATION)
            .arg(ENCRYPT)
            .arg(DECRYPT)
            .required(true)
        )
        .arg(Arg::new(MOUNT)
            .short('m')
            .long("mount")
            .help("Instead of the default single-file mode, operate in the filesystem mode")
            .display_order(2)
        )
        .arg(Arg::new(PASSFILE)
            .short('p')
            .long("passfile")
            .takes_value(true)
            .help("Path to a file whose contents will be read and used as a passphrase")
            .display_order(3)
        )
        .arg(Arg::new(FORCE)
            .short('f')
            .long("force")
            .help("Overwrite the <target> if it already exists (single-file mode only)")
            .display_order(4)
        )
        .arg(Arg::new(FOREGROUND)
            .short('F')
            .long("foreground")
            .help("Run in foreground, do not daemonize (filesystem mode only)")
            .display_order(5)
        )
        .arg(Arg::new(SINGLE_THREADED)
            .short('s')
            .long("single-threaded")
            .help("Run single-threaded")
            .display_order(6)
        )
        .arg(Arg::new(VERBOSE)
            .short('v')
            .long("verbose")
            .multiple_occurrences(true)
            .help("Show debugging information (use twice for more detail)")
            .display_order(7)
        )
        .arg(Arg::new(SOURCE)
            .help("The file to be processed / the source folder for the filesystem")
            .required(true)
        )
        .arg(Arg::new(TARGET)
            .help("The output file / the mountpoint for the filesystem")
            .required(true)
        )
        .get_matches()
}

/// Load the passphrase from a file at `path`.
fn passphrase_from_file(path: &str) -> Vec<u8> {
    trace!("Loading passphrase from: {}",  path);
    match File::open(path) {
        Ok(mut file) => {
            let mut raw = Vec::new();
            if let Err(err) = file.read_to_end(&mut raw) {
                error!("Could not read passfile: {}", err);
                process::exit(libc::EIO);
            }
            raw
        },
        Err(err) => {
            error!("Could not open passfile: {}", err);
            process::exit(libc::EIO);
        },
    }
}

/// Interactively ask user to enter the passphrase (used when passfile
/// is not provided).
///
/// This will ask for passphrase confirmation when `operation` is set to
/// [`Operation::Encrypt`] (i.e. it will ask for a passphrase twice).
fn passphrase_from_input(operation: Operation) -> Vec<u8> {

    match read_passphrase("Passphrase: ") {
        Some(passphrase) => {
            if passphrase.is_empty() {
                error!("Passphrase must not be empty");
                process::exit(libc::EINVAL);
            }

            if operation == Operation::Encrypt {
                let repeat = read_passphrase("Repeat passphrase: ");
                if repeat.is_none() {
                    error!("No repeated passphrase provided");
                    overwrite_passphrase_memory(passphrase);
                    process::exit(libc::EINVAL);
                }
                let repeat = repeat.unwrap();
                if passphrase != repeat {
                    overwrite_passphrase_memory(passphrase);
                    overwrite_passphrase_memory(repeat);
                    error!("Repeated passphrase does not match");
                    process::exit(libc::EINVAL);
                }
                overwrite_passphrase_memory(repeat);
            }
            let mut pass_vec = vec![0u8; passphrase.len()];
            pass_vec.copy_from_slice(passphrase.as_bytes());
            overwrite_passphrase_memory(passphrase);
            pass_vec
        },
        None => {
            error!("No passphrase provided");
            process::exit(libc::EINVAL);
        },
    }
}

/// Overwrite the passphrase with a dummy character
/// so that it does not linger around in memory.
fn overwrite_passphrase_memory(mut passphrase: String) {
    const DUMMY: u8 = b'*';
    unsafe {
        for b in passphrase.as_bytes_mut() {
            ptr::write_volatile(b, DUMMY);
        }
    }
    atomic::compiler_fence(Ordering::SeqCst);
}

/// Read passphrase from the standard input.
fn read_passphrase(prompt: &str) -> Option<String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdin = stdin.lock();
    let mut stdout = stdout.lock();

    stdout.write_all(prompt.as_bytes()).unwrap();
    stdout.flush().unwrap();

    let passphrase = stdin.read_passwd(&mut stdout)
                          .expect("Failed to read the passphrase");
    stdout.write_all(b"\n").unwrap();

    passphrase
}

/// Make sure that the source directory exists.
fn source_directory(source_path: PathBuf) -> PathBuf {
    if source_path.is_dir() {
        source_path
    } else {
        error!("Source directory does not exist");
        process::exit(libc::ENOTDIR);
    }
}

/// Make sure that hte source file exists.
fn source_file(source_path: PathBuf) -> PathBuf {
    if source_path.is_file() {
        source_path
    } else {
        error!("Source file does not exist");
        process::exit(libc::ENOENT);
    }
}

/// Make sure that the target directory exists.
fn target_directory(source: &PathBuf, target_path: PathBuf) -> PathBuf {
    if target_path.is_dir() {
        let canonical_target_path = match target_path.canonicalize() {
            Ok(path) => path,
            Err(err) => {
                error!("Target directory error: {}", err);
                process::exit(libc::EIO);
            },
        };
        if canonical_target_path == *source {
            error!("Source and target cannot be the same directory");
            process::exit(libc::EINVAL);
        }
        if canonical_target_path.starts_with(source) {
            error!("Target cannot be under the source directory");
            process::exit(libc::EINVAL);
        }
        if source.starts_with(&canonical_target_path) {
            error!("Source cannot be under the target directory");
            process::exit(libc::EINVAL);
        }
        canonical_target_path
    } else {
        error!("Target directory does not exist");
        process::exit(libc::ENOTDIR);
    }
}

/// Make sure that the target file exists.
///
/// If the target points to a directory, the path will be retargetted
/// to a file of the same name as the source file in the target directory.
fn target_file(source: &PathBuf, mut target_path: PathBuf, force: bool) -> PathBuf {
    if target_path.is_dir() {
        let source_file_name = source.file_name().unwrap();
        trace!("Target is a directory, will target file '{:?}' instead.",
               source_file_name);
        target_path.push(source_file_name);
    }
    if target_path.is_file() {
        let canonical_target_path = match target_path.canonicalize() {
            Ok(path) => path,
            Err(err) => {
                error!("Target file error: {}", err);
                process::exit(libc::EIO);
            }
        };
        if canonical_target_path == *source {
            error!("Source and target cannot be the same file");
            process::exit(libc::EINVAL);
        }
        if !force {
            error!("Target file exists (use '-f' to overwrite')");
            process::exit(libc::EINVAL);
        }
        target_path
    } else if target_path.is_dir() {
        // if target_path + source.file_name() is still a directory
        error!("Target file points to a directory: {}",
               target_path.to_string_lossy());
        process::exit(libc::EISDIR);
    } else {
        target_path
    }
}
