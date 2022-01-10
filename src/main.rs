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
//! Main crate module: It parses arguments, loads the passphrase,
//! and then hands over control to either [`single`] or [`filesystem`]
//! modules to take care of the rest.
//!

mod buffer;
mod crypto;

use clap::{App, Arg, ArgGroup, ArgMatches };

///
/// Define and parse command line arguments.
///
fn parse_arguments() -> ArgMatches {
    App::new("tombdrive")
        .about("A simple cryptographic toolkit with a reverse-encryption filesystem")
        .version("0.0.2-alpha")
        .after_help(concat!("If passfile is not provided, ",
                            "the passphrase will be requested interactively"))
        .arg(Arg::new("encrypt")
            .short('e')
            .long("encrypt")
            .help("Encrypt a single file")
        )
        .arg(Arg::new("decrypt")
            .short('d')
            .long("decrypt")
            .help("Decrypt a single file")
        )
        .arg(Arg::new("mount")
            .short('m')
            .long("mount")
            .help("Mount a reverse-encrypted <source> folder onto a <target> mountpoint")
        )
        .group(ArgGroup::new("mode")
            .arg("encrypt")
            .arg("decrypt")
            .arg("mount")
            .required(true)
        )
        .arg(Arg::new("passfile")
            .short('p')
            .long("passfile")
            .takes_value(true)
            .help("Path to a file containing the passphrase")
        )
        .arg(Arg::new("force")
            .short('f')
            .long("force")
            .help("Overwrite the <target> if it already exists (single file mode only)")
        )
        .arg(Arg::new("foreground")
            .short('F')
            .long("foreground")
            .help("Run in foreground and do not daemonize (filesystem mode only)")
        )
        .arg(Arg::new("source")
            .help("The file to be processed / the source folder for the filesystem")
            .required(true)
        )
        .arg(Arg::new("target")
            .help("The output file / the mountpoint for the filesystem")
            .required(true)
        )
        .term_width(79)
        .get_matches()
}


fn main() {
    let args = parse_arguments();
}
