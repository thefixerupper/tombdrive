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
//! Provides [`EncryptionReader<T>`] and [`DecryptionReader<T>`] types used
//! to translate from and to the encrypted container format.
//!
//! They transparently encrypt/decrypt data (as well as any associated
//! attributes) from the backing stream.
//!

use std::io::{ self, ErrorKind, Read, Seek };

use aes::{Aes128Ctr, BLOCK_SIZE as BLOCK_LEN};
use aes::cipher::{NewCipher, StreamCipher};
use aes::cipher::generic_array::GenericArray;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::{Digest, Sha256};

use crate::buffer::Buffer;


/// The number of bytes in the counter attribute
const COUNTER_LEN: usize = BLOCK_LEN;

/// The number of bytes in the salt attribute
const SALT_LEN: usize = 16;

/// The number of bytes in the entire header
const HEADER_LEN: usize = COUNTER_LEN + SALT_LEN;

/// The number of bytes in a key
const KEY_LEN: usize = 16;

/// The number of derivation rounds
const KEY_ROUNDS: u32 = 10_000;

// The maximum number of bytes to work on per encryption/decryption iteration
const MAX_BYTES_PER_READ: usize = 4096;


///
/// After the [`MAGIC_NUMBER`], each non-zero-size encrypted stream holds
/// a couple of numerical attributes encrypted as big-endian bytes.
/// [`Attributes`] hold the ones that we need to keep around while
/// operating on the stream.
///
#[derive(Debug)]
struct Attributes {
    /// The counter used to encrypt the first block of data
    pub counter: u128,
    /// The salt used for key derivation
    pub salt: [u8; SALT_LEN],
}

impl Attributes {
    ///
    /// Creates a new [`Attributes`] struct based on the provided `stream`.
    ///
    pub fn from<T: Read + Seek>(stream: &mut Buffer<T>) -> io::Result<Attributes> {
        stream.seek_from_start(0)?;
        let mut hasher = Sha256::new();

        let mut buffer = [0u8; 32];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => {
                    break;
                }
                Ok(n) => {
                    let buffer_slice = &buffer[..n];
                    hasher.update(buffer_slice);
                }
                Err(error) => {
                    if error.kind() != ErrorKind::Interrupted {
                        return Err(error);
                    }
                }
            }
        }
        let hash = hasher.finalize();

        let mut counter_bytes = [0u8; COUNTER_LEN];
        let mut salt = [0u8; SALT_LEN];

        counter_bytes.copy_from_slice(&hash[..COUNTER_LEN]);
        salt.copy_from_slice(&hash[COUNTER_LEN..]);

        let counter = u128::from_be_bytes(counter_bytes);

        Ok(Attributes { counter, salt })
    }
}


///
/// The [`EncryptionReader<T>`] creates a translation layer where plaintext
/// data from the backing stream gets encrypted on the fly as it is being read.
///
#[derive(Debug)]
pub struct EncryptionReader<T: Read + Seek> {
    attributes: Attributes,
    cursor: usize,
    header: [u8; HEADER_LEN],
    key: [u8; KEY_LEN],
    stream: Buffer<T>,
}

impl<T: Read + Seek> EncryptionReader<T> {
    ///
    /// Create a new [`EncryptionReader<T>`] that encrypts a plaintext
    /// `stream` using `passphrase`.
    ///
    /// This function will return an [`io::Error`] if the `stream` is empty.
    ///
    /// The encrypted data is then readable by [`DecryptionReader`].
    ///
    pub fn new(mut stream: Buffer<T>, passphrase: &str)
               -> io::Result<EncryptionReader<T>> {
        let total_len = stream.len();
        if total_len == 0 {
            return Err(io::Error::new(ErrorKind::Other, "Empty stream"));
        }

        let attributes = Attributes::from(&mut stream)?;
        stream.seek_from_start(0)?;

        let key = derive_key(passphrase, &attributes.salt);

        let mut header = [0u8; HEADER_LEN];

        let (start, end) = (0usize, SALT_LEN);
        header[start..end].copy_from_slice(&attributes.salt);

        let (start, end) = (end, end + COUNTER_LEN);
        header[start..end].copy_from_slice(&attributes.counter.to_be_bytes());

        Ok(EncryptionReader { attributes, cursor: 0, header, key, stream })
    }

    ///
    /// Returns total encrypted length.
    ///
    pub fn len(&self) -> usize {
        self.stream.len() + HEADER_LEN
    }

    ///
    /// Seek to a new cursor position.
    ///
    pub fn seek_from_start(&mut self, offset: usize) {
        self.cursor = offset;
       // the actual stream seeking happens in the read method when needed
    }
}

impl<T: Read + Seek> Read for EncryptionReader<T> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        // if no `out` or we're past the end of file, return 0
        if out.len() == 0 || self.cursor >= self.len() {
            return Ok(0);
        }

        // if we're in the header area, read at most to the end of the header
        if self.cursor < HEADER_LEN {
            let header_remaining = HEADER_LEN - self.cursor;
            let bytes_to_copy = header_remaining.min(out.len());

            let header_slice_end = self.cursor + bytes_to_copy;
            let header_slice = &self.header[self.cursor..header_slice_end];

            out[..bytes_to_copy].copy_from_slice(header_slice);

            self.cursor = header_slice_end;
            return Ok(bytes_to_copy);
        }

        let stream_cursor = self.cursor - HEADER_LEN;
        let bytes_copied = xor_stream(0, stream_cursor, self.attributes.counter,
                                      &self.key, &mut self.stream, out)?;
        self.cursor += bytes_copied;
        Ok(bytes_copied)
    }
}


///
/// The [`DecryptionReader<T>`] creates a translation layer where encrypted
/// data from the backing stream gets decrypted on the fly as it is being read.
///
#[derive(Debug)]
pub struct DecryptionReader<T: Read + Seek> {
    attributes: Attributes,
    cursor: usize,
    key: [u8; KEY_LEN],
    stream: Buffer<T>,
}

impl<T: Read + Seek> DecryptionReader<T> {
    ///
    /// Create a new [`DecryptionReader<T>`] that decrypts an encrypted
    /// `stream` using `passphrase`.
    ///
    /// This function will return an [`io::Error`] if the `stream` is empty or
    /// if the `stream` does not look like it was encrypted using
    /// [`EncryptionReader<T>`].
    ///
    pub fn new(mut stream: Buffer<T>, passphrase: &str)
               -> io::Result<DecryptionReader<T>> {
        let total_len = stream.len();
        if total_len == 0 {
            return Err(io::Error::new(ErrorKind::Other, "Empty stream"));
        }
        if total_len < HEADER_LEN {
            return Err(io::Error::new(ErrorKind::InvalidData, "Stream too short"));
        }

        let mut salt = [0u8; SALT_LEN];
        let mut counter_bytes = [0u8; COUNTER_LEN];

        stream.seek_from_start(0)?;
        stream.read_exact(&mut salt)?;
        stream.read_exact(&mut counter_bytes)?;

        let counter = u128::from_be_bytes(counter_bytes);
        let attributes = Attributes { counter, salt };
        let key = derive_key(passphrase, &salt);

        Ok(DecryptionReader { attributes, cursor: 0, key, stream })
    }

    ///
    /// Returns total decrypted length.
    ///
    pub fn len(&self) -> usize {
        self.stream.len() - HEADER_LEN
    }

    ///
    /// Seek to a new cursor position.
    ///
    pub fn seek_from_start(&mut self, offset: usize) {
        self.cursor = offset;
        // the actual stream seeking happens in the read method when needed
    }
}

impl<T: Read + Seek> Read for DecryptionReader<T> {
    fn read(&mut self, out: &mut[u8]) -> io::Result<usize> {
        // if no `out` or we are past the length of file, return 0
        if out.len() == 0 || self.cursor >= self.len() {
            return Ok(0);
        }

        let stream_cursor = self.cursor + HEADER_LEN;
        let bytes_copied = xor_stream(HEADER_LEN, stream_cursor,
                                      self.attributes.counter,
                                      &self.key, &mut self.stream, out)?;
        self.cursor += bytes_copied;
        Ok(bytes_copied)
    }
}


///
/// Align `cursor` to block boundaries.
///
fn align_to_block(cursor: usize) -> usize {
    assert_eq!(HEADER_LEN % BLOCK_LEN, 0, "Header must be block-aligned");

    if cursor % BLOCK_LEN == 0 {
        return cursor;
    }

    cursor - (cursor % BLOCK_LEN)
}

///
/// Returns a tuple of key and a passphrase hash (a small section at the head
/// of an encrypted file used to quickly, and not perfectly, check if the
/// provided passphrase is wrong).
///
fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let mut hash = [0u8; KEY_LEN];
    pbkdf2::<Hmac<Sha256>>(passphrase.as_bytes(), salt, KEY_ROUNDS, &mut hash);
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&hash[..KEY_LEN]);
    key
}


fn xor_stream<T: Read + Seek>(base_offset: usize, cursor: usize,
                              base_counter: u128,  key: &[u8],
                              stream: &mut Buffer<T>, out: &mut [u8])
                              -> io::Result<usize> {
    // align the position in the stream
    let aligned_cursor = align_to_block(cursor);
    let first_block_offset = cursor - aligned_cursor;

    stream.seek_from_start(aligned_cursor)?;

    // counter
    let block_number = (aligned_cursor - base_offset) / BLOCK_LEN;
    let counter = base_counter.wrapping_add(block_number as u128);
    let counter_bytes = counter.to_be_bytes();

    // cipher
    let key_ga = GenericArray::from_slice(key);
    let counter_ga = GenericArray::from_slice(&counter_bytes);
    let mut cipher = Aes128Ctr::new(key_ga, counter_ga);

    // number of bytes remaining in the stream
    let bytes_remaining = stream.len() - aligned_cursor;

    // if the stream position is not block-aligned, encrypt just one block
    if first_block_offset != 0 {
        let mut block = [0u8; BLOCK_LEN];
        let bytes_to_read = bytes_remaining.min(BLOCK_LEN)
                                           .min(first_block_offset + out.len());

        stream.read_exact(&mut block[..bytes_to_read])?;
        cipher.apply_keystream(&mut block);

        let bytes_to_copy = bytes_to_read - first_block_offset;
        let block_slice_end = first_block_offset + bytes_to_copy;
        let block_slice = &block[first_block_offset..block_slice_end];
        out[..bytes_to_copy].copy_from_slice(block_slice);

        return Ok(bytes_to_copy);
    }

    // We're block aligned and can use `out` directly to store the read
    // data, and then encrypt it in place.

    let bytes_to_copy = bytes_remaining.min(MAX_BYTES_PER_READ)
                                       .min(out.len());

    let out_slice = &mut out[..bytes_to_copy];
    stream.read_exact(out_slice)?;
    cipher.apply_keystream(out_slice);

    Ok(bytes_to_copy)
}


#[cfg(test)]
pub mod tests {
    use io::Cursor;

    use super::*;

    const PLAINTEXT: &[u8] = concat!(
        "It was a bright cold day in April, and the clocks were striking ",
        "thirteen. Winston Smith, his chin nuzzled into his breast in an ",
        "effort to escape the vile wind, slipped quickly through the glass ",
        "doors of Victory Mansions, though not quickly enough to prevent a ",
        "swirl of gritty dust from entering along with him."
    ).as_bytes();

    const PASSPHRASE: &str = "1984";

    fn encrypt(plaintext: &[u8], passphrase: &str) -> Vec<u8> {
        let plain_file = Cursor::new(plaintext);
        let plain_stream = Buffer::with_capacity(plaintext.len() + HEADER_LEN,
                                                 plain_file).unwrap();
        let mut enc_reader = EncryptionReader::new(plain_stream, passphrase)
                             .unwrap();
        let mut ciphertext: Vec<u8> = Vec::with_capacity(enc_reader.len());
        enc_reader.read_to_end(&mut ciphertext).unwrap();
        ciphertext
    }

    fn decrypt(ciphertext: &[u8], passphrase: &str) -> Vec<u8> {
        let cipher_file = Cursor::new(&ciphertext);
        let cipher_stream = Buffer::with_capacity(ciphertext.len() - HEADER_LEN,
                                                  cipher_file).unwrap();
        let mut dec_reader = DecryptionReader::new(cipher_stream, passphrase)
                             .unwrap();
        let mut plaintext: Vec<u8> = Vec::with_capacity(PLAINTEXT.len());
        dec_reader.read_to_end(&mut plaintext).unwrap();
        plaintext
    }

    ///
    /// Test if encrypting the entire stream and then decrypting the entire
    /// restores the original contents.
    ///
    #[test]
    fn encryption_round_trip() {
        let ciphertext = encrypt(PLAINTEXT, PASSPHRASE);
        let plaintext = decrypt(&ciphertext, PASSPHRASE);
        assert_eq!(&plaintext[..], PLAINTEXT);
    }

    ///
    /// Test the parity between extracting just a small part of the stream,
    /// and the entire content.
    ///
    #[test]
    fn partial_encryption() {
        let ciphertext = encrypt(PLAINTEXT, PASSPHRASE);

        let plain_file = Cursor::new(PLAINTEXT);
        let plain_stream = Buffer::with_capacity(PLAINTEXT.len() + HEADER_LEN,
                                                 plain_file).unwrap();
        let mut enc_reader = EncryptionReader::new(plain_stream, PASSPHRASE)
                             .unwrap();

        // test equality when looking at corresponding sections
        let inputs = [(15, 43), (100, 20), (128,1), (64, 32)];
        for i in inputs {
            let mut part = vec![0u8; i.1];
            enc_reader.seek_from_start(i.0);
            enc_reader.read_exact(&mut part).unwrap();
            assert_eq!(&part[..], &ciphertext[i.0..(i.0 + i.1)]);
        }

        // sanity check of expected non-equality
        for i in inputs {
            let mut part = vec![0u8; i.1];
            enc_reader.seek_from_start(i.0 + 1); // <- this should break it
            enc_reader.read_exact(&mut part).unwrap();
            assert_ne!(&part[..], &ciphertext[i.0..(i.0 + i.1)]);
        }
    }
}
