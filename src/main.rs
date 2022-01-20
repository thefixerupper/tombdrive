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
//! The entry module of the crate: Parses arguments, loads the configuration,
//! and then hands over control to either [`single`] or [`filesystem`]
//! modules to take care of the rest.
//!

mod buffer;
mod config;
mod crypto;
mod filesystem;
mod fuse;
mod single;

use std::env::{ self, Args };
use std::process::exit;

use clap::{ self, App, Arg, ArgGroup, ArgMatches };

use crate::config::{ Config, Mode };
use crate::filesystem::Filesystem;
use crate::single::process_file;


// Possible exit codes
#[repr(u8)]
enum Exit {
    Success = 0,
    ConfigurationFailure = 1,
    FilesystemFailure = 2,
    SingleFileFailure = 3,
}

///
/// Define and parse command line arguments.
///
fn parse_arguments(args: Args) -> ArgMatches {
    App::new(clap::crate_name!())
        .about(clap::crate_description!())
        .version(clap::crate_version!())
        .after_help(concat!("If <passfile> is not provided, ",
                            "the passphrase will be requested interactively"))
        .arg(Arg::new("encrypt")
            .short('e')
            .long("encrypt")
            .help("Encrypt a single file / mount an encrypted representation of a folder")
            .display_order(0)
        )
        .arg(Arg::new("decrypt")
            .short('d')
            .long("decrypt")
            .help("Decrypt a single file / mount a decrypted representation of a folder")
            .display_order(1)
        )
        .group(ArgGroup::new("mode")
            .arg("encrypt")
            .arg("decrypt")
            .required(true)
        )
        .arg(Arg::new("mount")
            .short('m')
            .long("mount")
            .help("Instead of the default single-file mode, operate in the filesystem mode")
            .display_order(2)
        )
        .arg(Arg::new("passfile")
            .short('p')
            .long("passfile")
            .takes_value(true)
            .help("Path to a file whose contents will be read and used as a passphrase")
            .display_order(3)
        )
        .arg(Arg::new("force")
            .short('f')
            .long("force")
            .help("Overwrite the <target> if it already exists (single-file mode only)")
            .display_order(4)
        )
        .arg(Arg::new("foreground")
            .short('F')
            .long("foreground")
            .help("Run in foreground, do not daemonize (filesystem mode only)")
            .display_order(5)
        )
        .arg(Arg::new("source")
            .help("The file to be processed / the source folder for the filesystem")
            .required(true)
        )
        .arg(Arg::new("target")
            .help("The output file / the mountpoint for the filesystem")
            .required(true)
        )
        .get_matches_from(args)
}


///
/// This is where it all begins.
///
fn main() {
    let args = env::args();
    let parsed_args = parse_arguments(args);
    let configuration = Config::new(parsed_args);
    match configuration {
        Ok(config) => {
            if config.mode == Mode::Filesystem {
                let filesystem = Filesystem::new(config);
                if let Err(err) = filesystem {
                    eprintln!("{}", err);
                    exit(Exit::FilesystemFailure as i32);
                }
                let mut filesystem = filesystem.unwrap();
                if let Err(err) = filesystem.mount() {
                    eprintln!("{}", err);
                    exit(Exit::FilesystemFailure as i32);
                }
            } else {
                if let Err(message) = process_file(config) {
                    eprintln!("{}", message);
                    exit(Exit::SingleFileFailure as i32);
                }
            }
        },
        Err(message) => {
            eprintln!("{}", message);
            exit(Exit::ConfigurationFailure as i32);
        },
    }
    exit(Exit::Success as i32);
}
