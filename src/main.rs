// SPDX-License-Identifier: Apache-2.0
//
// TombDrive: A cryptographic toolkit
// Copyright 2022-2023 Martin Furman
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

//! Tomb Drive is a simple cryptographic toolkit that allows you to encrypt and
//! decrypt single files, as well as to mount an encrypted / decrypted
//! representation of a directory as a virtual filesystem using FUSE.

mod buffer;
mod config;
mod crypto;
mod drive;
mod single;

use std::process;

use log::{info, error};

use config::Config;
use drive::Drive;

// ============ //
//     MAIN     //
// ============ //

fn main() {
    // this also initialises logging
    let config = Config::new();

    if config.mount() {
        let drive = match Drive::new(config) {
            Ok(drive) => drive,
            Err(err) => {
                error!("Could not create a new drive: {}", err);
                process::exit(1);
            },
        };
        if let Err(err) = drive.mount() {
            error!("Could not mount Tomb Drive: {}", err);
            process::exit(1);
        }
        info!("Tomb Drive has been unmounted");
    } else {
        if let Err(err) = single::process_file(config) {
            error!("Could not process a single file: {}", err);
            process::exit(1);
        }
        info!("The file has been processed");
    }
}
