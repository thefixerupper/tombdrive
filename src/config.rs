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

use std::fs::{ self, File };
use std::io::{ self, Read, Write };
use std::path::{ Path, PathBuf };
use std::process;

use clap::{ App, Arg, ArgGroup, ArgMatches };
use log::error;
use termion::input::TermRead;

// ================= //
//     OPERATION     //
// ================= //

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Operation {
    Decrypt,
    Encrypt,
}

// ================== //
//     PASSPHRASE     //
// ================== //

#[derive(Debug)]
pub struct Passphrase {
    raw: Vec<u8>,
}

impl From<Vec<u8>> for Passphrase {
    fn from(raw: Vec<u8>) -> Self {
        Self { raw }
    }
}

impl AsRef<[u8]> for Passphrase {
    fn as_ref(&self) -> &[u8] {
        self.raw.as_ref()
    }
}

impl Drop for Passphrase {
    fn drop(&mut self) {
        for b in self.raw.iter_mut() {
            *b = 0;
        }
    }
}

// ============== //
//     CONFIG     //
// ============== //

#[derive(Debug)]
pub struct Config {
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
    const DECRYPT: &'static str = "decrypt";
    const ENCRYPT: &'static str = "encrypt";
    const FORCE: &'static str = "force";
    const FOREGROUND: &'static str = "foreground";
    const MOUNT: &'static str = "mount";
    const OPERATION: &'static str = "operation";
    const PASSFILE: &'static str = "passfile";
    const SINGLE_THREADED: &'static str = "single-threaded";
    const SOURCE: &'static str = "source";
    const TARGET: &'static str = "target";
    const VERBOSE: &'static str = "verbose";

    pub fn new() -> Self {
        let args = Self::parse_arguments();

        let logger_env = match args.occurrences_of(Self::VERBOSE) {
            1 => env_logger::Env::default().filter("debug"),
            2 => env_logger::Env::default().filter("trace"),
            _ => env_logger::Env::default().default_filter_or("info"),
        };
        env_logger::Builder::from_env(logger_env).init();

        let force = args.is_present(Self::FORCE);
        let foreground = args.is_present(Self::FOREGROUND);
        let mount = args.is_present(Self::MOUNT);
        let single_threaded = args.is_present(Self::SINGLE_THREADED);

        // operation

        let operation = if args.is_present(Self::DECRYPT) {
            Operation::Decrypt
        } else if args.is_present(Self::ENCRYPT) {
            Operation::Encrypt
        } else {
            unreachable!()
        };

        // source

        let source_arg = args.value_of(Self::SOURCE)
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

        let target_arg = args.value_of(Self::TARGET)
                             .expect("Missing <target> argument");
        let target_path = PathBuf::from(target_arg);
        let target = if mount {
            target_directory(&source, target_path)
        } else {
            target_file(&source, target_path, force)
        };

        // passphrase

        let passphrase_raw = match args.value_of(Self::PASSFILE) {
            Some(path) => passphrase_from_file(path),
            None => passphrase_from_input(operation),
        };
        let passphrase = Passphrase { raw: passphrase_raw };

        // return

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

    pub fn force(&self) -> bool {
        self.force
    }

    pub fn foreground(&self) -> bool {
        self.foreground
    }

    pub fn mount(&self) -> bool {
        self.mount
    }

    pub fn operation(&self) -> Operation {
        self.operation
    }

    pub fn passphrase(&self) -> &Passphrase {
        &self.passphrase
    }

    pub fn single_threaded(&self) -> bool {
        self.single_threaded
    }

    pub fn source(&self) -> &Path {
        self.source.as_path()
    }

    pub fn target(&self) -> &Path {
        self.target.as_path()
    }

    fn parse_arguments() -> ArgMatches {
        App::new(clap::crate_name!())
            .about(clap::crate_description!())
            .version(clap::crate_version!())
            .after_help(concat!("If <passfile> is not provided, ",
                                "the passphrase will be requested interactively"))
            .arg(Arg::new(Self::ENCRYPT)
                .short('e')
                .long("encrypt")
                .help("Encrypt a single file / mount an encrypted representation of a folder")
                .display_order(0)
            )
            .arg(Arg::new(Self::DECRYPT)
                .short('d')
                .long("decrypt")
                .help("Decrypt a single file / mount a decrypted representation of a folder")
                .display_order(1)
            )
            .group(ArgGroup::new(Self::OPERATION)
                .arg(Self::ENCRYPT)
                .arg(Self::DECRYPT)
                .required(true)
            )
            .arg(Arg::new(Self::MOUNT)
                .short('m')
                .long("mount")
                .help("Instead of the default single-file mode, operate in the filesystem mode")
                .display_order(2)
            )
            .arg(Arg::new(Self::PASSFILE)
                .short('p')
                .long("passfile")
                .takes_value(true)
                .help("Path to a file whose contents will be read and used as a passphrase")
                .display_order(3)
            )
            .arg(Arg::new(Self::FORCE)
                .short('f')
                .long("force")
                .help("Overwrite the <target> if it already exists (single-file mode only)")
                .display_order(4)
            )
            .arg(Arg::new(Self::FOREGROUND)
                .short('F')
                .long("foreground")
                .help("Run in foreground, do not daemonize (filesystem mode only)")
                .display_order(5)
            )
            .arg(Arg::new(Self::SINGLE_THREADED)
                .short('s')
                .long("single-threaded")
                .help("Run single-threaded")
                .display_order(6)
            )
            .arg(Arg::new(Self::VERBOSE)
                .short('v')
                .long("verbose")
                .multiple_occurrences(true)
                .help("Show debugging information (use twice for more detail)")
                .display_order(7)
            )
            .arg(Arg::new(Self::SOURCE)
                .help("The file to be processed / the source folder for the filesystem")
                .required(true)
            )
            .arg(Arg::new(Self::TARGET)
                .help("The output file / the mountpoint for the filesystem")
                .required(true)
            )
            .get_matches()
    }
}

// ======================== //
//     helper functions     //
// ======================== //

fn passphrase_from_file(path: &str) -> Vec<u8> {
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

fn passphrase_from_input(operation: Operation) -> Vec<u8> {
    let passphrase = read_passphrase("Passphrase: ");
    match passphrase {
        Some(pass) => {
            if pass.is_empty() {
                error!("Passphrase must not be empty");
                process::exit(libc::EINVAL);
            }

            if operation == Operation::Encrypt {
                let repeat = read_passphrase("Repeat passphrase: ");
                if repeat.is_none() {
                    error!("No repeated passphrase provided");
                    process::exit(libc::EINVAL);
                }
                if pass != repeat.unwrap() {
                    error!("Repeated passphrase does not match");
                    process::exit(libc::EINVAL);
                }
            }
            let mut pass_vec = vec![0u8; pass.len()];
            pass_vec.copy_from_slice(pass.as_bytes());
            pass_vec
        },
        None => {
            error!("No passphrase provided");
            process::exit(libc::EINVAL);
        },
    }
}

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

fn source_directory(source_path: PathBuf) -> PathBuf {
    if source_path.is_dir() {
        source_path
    } else {
        error!("Source directory does not exist");
        process::exit(libc::ENOTDIR);
    }
}

fn source_file(source_path: PathBuf) -> PathBuf {
    if source_path.is_file() {
        source_path
    } else {
        error!("Source file does not exist");
        process::exit(libc::ENOENT);
    }
}

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

fn target_file(source: &PathBuf, mut target_path: PathBuf, force: bool) -> PathBuf {
    if target_path.is_dir() {
        target_path.push(source.file_name().unwrap());
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
