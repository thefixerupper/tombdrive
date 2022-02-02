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

mod buffer;
mod config;
mod crypto;
mod drive;
mod single;

use std::process;

use config::Config;
use drive::Drive;

fn main() {
    let config = Config::new();

    if config.mount() {
        let drive = Drive::new(config).unwrap();
        drive.mount();
    } else {
        if let Err(message) = single::process_file(config) {
            eprintln!("{}", message);
            process::exit(1);
        }
    }
}
