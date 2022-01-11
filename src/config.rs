// This file is part of Tombdrive
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


//!
//! Provides the [`Config`] struct where the runtime configuration is stored.
//!


use std::fs::File;
use std::io::{ self, Read, Write };

use clap::ArgMatches;
use termion::input::TermRead;


///
/// Runtime mode covers two main modes of operation:
///
///   - single file mode with [`Mode::Encrypt`] and [`Mode::Decrypt`],
///     where a single file is encrypted or decrypted
///
///   - filesystem mode with [`Mode::Mount`], where an encrypted
///     representation of the source folder is mounted onto a mountpoint
///     encrypting files on demand as they are accessed
///
#[derive(Debug, PartialEq)]
pub enum Mode {
    Encrypt,
    Decrypt,
    Mount,
}


///
/// Runtime configuration, mostly parsed from the command line arguments,
/// and/or interaction with the user before any proper execution starts.
///
#[derive(Debug)]
pub struct Config {
    pub mode: Mode,
    pub source: String,
    pub target: String,
    pub passphrase: Vec<u8>,
    pub force: bool,
    pub foreground: bool,
}

impl Config {
    ///
    /// Creates a new instance of [`Config`], asking for passphrase
    /// if it was not provided via `passfile` (or reading passfile fails).
    ///
    pub fn new(parsed_args: ArgMatches) -> Result<Config, &'static str> {
        let mode = if parsed_args.is_present("encrypt") {
            Mode::Encrypt
        } else if parsed_args.is_present("decrypt") {
            Mode::Decrypt
        } else {
            Mode::Mount
        };

        // These two should never panic as the argument parser should not
        // let us get this far with them missing.
        let source = String::from(parsed_args.value_of("source")
                                             .expect("Missing source argument"));
        let target = String::from(parsed_args.value_of("target")
                                             .expect("Missing target argument"));

        let passphrase = if parsed_args.is_present("passfile") {
            let passfile = parsed_args.value_of("passfile").unwrap();
            match Self::passphrase_from_passfile(passfile) {
                Ok(pass) => {
                    pass
                },
                Err(_) => {
                    // Any more specific error could reveal secrets in logs
                    return Err("Failed to load the passfile");
                },
            }
        } else {
            match Self::passphrase_from_input(&mode) {
                Ok(pass) => {
                    pass
                },
                Err(err) => {
                    return Err(err);
                }
            }
        };

        let force = parsed_args.is_present("force");
        let foreground = parsed_args.is_present("foreground");

        Ok(Config { mode, source, target, passphrase, force, foreground })
    }

    ///
    /// Loads the passphrase from a file.
    ///
    fn passphrase_from_passfile(path: &str) -> io::Result<Vec<u8>> {
        let mut file = File::open(path)?;
        let info = file.metadata()?;
        let mut passphrase: Vec<u8> = Vec::with_capacity(info.len() as usize);
        file.read_to_end(&mut passphrase)?;
        Ok(passphrase)
    }

    ///
    /// Loads the passphrase from the standard input.
    ///
    fn passphrase_from_input(mode: &Mode) -> Result<Vec<u8>, &'static str> {
        let passphrase = Self::read_passphrase("Passphrase: ");
        match passphrase {
            Some(pass) => {
                if pass.is_empty() {
                    return Err("Passphrase must not be empty");
                }

                if *mode == Mode::Encrypt {
                    let repeat = Self::read_passphrase("Repeat passphrase: ");
                    if repeat.is_none() {
                        return Err("No repeated passphrase provided");
                    }
                    if pass != repeat.unwrap() {
                        return Err("Repeated passphrase does not match");
                    }
                }
                let mut pass_vec = vec![0u8; pass.len()];
                pass_vec.copy_from_slice(pass.as_bytes());
                return Ok(pass_vec)
            },
            None => {
                return Err("No passphrase provided")
            },
        }
    }

    ///
    /// Prompts user for a passphrase.
    ///
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
}
