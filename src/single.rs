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
//! Provides functionality to operate on a single file.
//!

use std::fs::{ self, File, Metadata, OpenOptions };
use std::io::{ BufWriter, ErrorKind, Read, Write };

use crate::buffer::Buffer;
use crate::config::{ Config, Mode };
use crate::crypto::{ EncryptionReader, DecryptionReader };


/// The size of the encryption reader buffer (encryption buffer reads the
/// entire file to calculate the hash, so bigger buffer can be more useful)
const ENC_BUFFER_LEN: usize = 16 * 1024 * 1024;

/// The size of decryption buffer
const DEC_BUFFER_LEN: usize = 8 * 1024;

/// The maximum size of individual chunk read while copying from
/// EncryptionReader/DecryptionReader into the target file
const COPY_BUFFER_LEN: usize = 4 * 1024;


///
/// Encrypt or decrypt a single file according to `config`.
///
pub fn process_file(config: Config) -> Result<(), String> {
    let source_file = match File::open(&config.source) {
        Ok(file) => file,
        Err(err) => return Err(format!("Source error: {}", err)),
    };

    let metadata = match source_file.metadata() {
        Ok(data) => data,
        Err(err) => return Err(format!("Source error: {}", err)),
    };

    if config.force {
        if let Err(err) = fs::remove_file(&config.target) {
            match err.kind() {
                ErrorKind::NotFound => (),
                _ => return Err(format!("Target error: {}", err)),
            }
        }
    }

    let target_file = match OpenOptions::new().write(true)
                                              .create_new(true)
                                              .open(&config.target) {
        Ok(file) => file,
        Err(err) => return Err(format!("Target error: {}", err)),
    };

    match config.mode {
        Mode::Encrypt => encrypt_file(source_file, metadata,
                                      target_file, &config.passphrase),
        Mode::Decrypt => decrypt_file(source_file, metadata,
                                      target_file, &config.passphrase),
        _ => Err(String::from("Unsupported mode"))
    }
}


///
/// Set up buffers and cryptographic reader for encryption and then
/// copy the data over into the target file.
///
fn encrypt_file(source: File, meta: Metadata, target: File, passphrase: &[u8])
                -> Result<(), String> {
    let capacity = (meta.len() as usize).min(ENC_BUFFER_LEN);
    let source_buffer = match Buffer::with_capacity(capacity, source) {
        Ok(buf) => buf,
        Err(err) => return Err(format!("Encryption buffer error: {}", err)),
    };
    let source_reader = match EncryptionReader::new(source_buffer, passphrase){
        Ok(reader) => reader,
        Err(err) => return Err(format!("Encryption reader error: {}", err)),
    };
    let target_writer = BufWriter::new(target);

    copy_file(source_reader, target_writer)
}


///
/// Set up buffers and cryptographic reader for decryption and then
/// copy the data over into the target file.
///
fn decrypt_file(source: File, meta: Metadata, target: File, passphrase: &[u8])
                -> Result<(), String> {
    let capacity = (meta.len() as usize).min(DEC_BUFFER_LEN);
    let source_buffer = match Buffer::with_capacity(capacity, source) {
        Ok(buf) => buf,
        Err(err) => return Err(format!("Decryption buffer error: {}", err)),
    };
    let source_reader = match DecryptionReader::new(source_buffer, passphrase){
        Ok(reader) => reader,
        Err(err) => return Err(format!("Decryption reader error: {}", err)),
    };
    let target_writer = BufWriter::new(target);

    copy_file(source_reader, target_writer)
}


///
/// Do the actual copying between source and target buffered reader/writer.
///
fn copy_file(mut source: impl Read, mut target: impl Write) -> Result<(), String> {
    let mut buffer = vec![0u8; COPY_BUFFER_LEN];
    loop {
        let copied = match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(len) => len,
            Err(err) => if err.kind() == ErrorKind::Interrupted {
                continue;
            } else {
                return Err(format!("Copying error: {}", err));
            },
        };
        if let Err(err) = target.write_all(&buffer[..copied]) {
            return Err(format!("Writing error: {}", err));
        }
    }
    Ok(())
}
