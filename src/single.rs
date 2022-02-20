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

//! Provides functionality to operate on a single file.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, BufWriter, ErrorKind, Read, Write};

use log::{debug, error, trace};

use crate::buffer::Buffer;
use crate::config::{ Config, Operation, Passphrase };
use crate::crypto::{ EncryptionReader, DecryptionReader };

// ================= //
//     Constants     //
// ================= //

/// The size of the encryption reader buffer (encryption buffer reads the
/// entire file to calculate the hash, so bigger buffer can be more useful)
const ENC_BUFFER_LEN: usize = 16 * 1024 * 1024;

/// The size of decryption buffer
const DEC_BUFFER_LEN: usize = 8 * 1024;

/// The maximum size of individual chunk read while copying from
/// EncryptionReader/DecryptionReader into the target file
const COPY_BUFFER_LEN: usize = 4 * 1024;

// ================== //
//     Public API     //
// ================== //

/// Encrypt or decrypt a single file according to `config`.
pub fn process_file(config: Config) -> io::Result<()> {
    debug!("Processing a single file");

    trace!("Opening the source file {:?}", config.source());
    let source_file = File::open(config.source())?;

    trace!("Querying source file metadata");
    let metadata = source_file.metadata()?;

    if config.force() {
        if let Err(err) = fs::remove_file(config.target()) {
            if err.kind() != ErrorKind::NotFound {
                error!("Target file error");
                return Err(err);
            }
        }
    }

    trace!("Opening the target file: {:?}", config.target());
    let target_file = OpenOptions::new().write(true)
                                        .create_new(true)
                                        .open(config.target())?;

    // special case: empty files are encrypted/decrypted into empty files
    // and that's what we already have
    if metadata.len() == 0 {
        debug!("Nothing to do as the source file size is zero");
        return Ok(());
    }

    match config.operation() {
        Operation::Encrypt => encrypt_file(source_file, metadata,
                                           target_file, config.passphrase()),
        Operation::Decrypt => decrypt_file(source_file, metadata,
                                           target_file, config.passphrase()),
    }
}

// ======================== //
//     Helper Functions     //
// ======================== //

/// Set up buffers and cryptographic reader for encryption and then
/// copy the data over into the target file.
fn encrypt_file(
    source: File,
    meta: Metadata,
    target: File,
    passphrase: &Passphrase
) -> io::Result<()> {
    debug!("Encrypting a single file");
    let capacity = (meta.len() as usize).min(ENC_BUFFER_LEN);
    let source_buffer = Buffer::with_capacity(capacity, source)?;
    let mut source_reader = EncryptionReader::new(source_buffer, passphrase)?;
    let mut target_writer = BufWriter::new(target);

    copy_file(&mut source_reader, &mut target_writer)
}

/// Set up buffers and cryptographic reader for decryption and then
/// copy the data over into the target file.
fn decrypt_file(
    source: File,
    meta: Metadata,
    target: File,
    passphrase: &Passphrase
) -> io::Result<()> {
    debug!("Decrypting a single file");
    let capacity = (meta.len() as usize).min(DEC_BUFFER_LEN);
    let source_buffer = Buffer::with_capacity(capacity, source)?;
    let mut source_reader = DecryptionReader::new(source_buffer, passphrase)?;
    let mut target_writer = BufWriter::new(target);

    copy_file(&mut source_reader, &mut target_writer)
}

/// Do the actual copying between source and target buffered reader/writer.
fn copy_file(source: &mut impl Read, target: &mut impl Write) -> io::Result<()> {
    debug!("Copying data from source to target");
    let mut buffer = vec![0u8; COPY_BUFFER_LEN];
    loop {
        trace!("Reading data from source");
        let copied = match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(len) => len,
            Err(err) => if err.kind() == ErrorKind::Interrupted {
                continue;
            } else {
                return Err(err);
            },
        };
        trace!("Writing data to into target");
        target.write_all(&buffer[..copied])?;
    }
    trace!("Flushing target");
    target.flush()?;
    Ok(())
}

// ============= //
//     Tests     //
// ============= //

#[cfg(test)]
mod tests {
    use super::*;

    use io::Cursor;

    const SAMPLE_TEXT: &[u8] = concat!(
        "This is your last chance. After this, there is no turning back. ",
        "You take the blue pill - the story ends, you wake up in your bed ",
        "and believe whatever you want to believe. You take the red pill - ",
        "you stay in Wonderland and I show you how deep the rabbit-hole goes."
    ).as_bytes();

    #[test]
    fn test_fn_copy_file() {
        let mut src = Cursor::new(SAMPLE_TEXT.to_vec());
        let mut tgt = Cursor::new(Vec::<u8>::new());
        copy_file(&mut src, &mut tgt).unwrap();
        assert_eq!(src, tgt);
    }

}
