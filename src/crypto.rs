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

use std::io::{ self, ErrorKind, Read, Seek, SeekFrom };

use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::{Digest, Sha256};

use crate::buffer::Buffer;

/// The size of each individual block used by the cipher
const BLOCK_LEN: usize = 16;

/// The number of bytes in the [`MAGIC_NUMBER`]
const MAGIC_NUMBER_LEN: usize = 4;

/// Magic bytes that are added to the beginning of every encrypted stream
const MAGIC_NUMBER: &[u8; MAGIC_NUMBER_LEN] = b"Tomb";

/// The number of bytes used by [`DecryptionReader<T>`] to quickly check
/// for invalid passphrases
const PASSPHRASE_HASH_LEN: usize = 4;

/// The number of bytes in the counter attribute
const COUNTER_LEN: usize = BLOCK_LEN;

/// The number of bytes in the salt attribute
const SALT_LEN: usize = 16;

/// The number of bytes representing the size of the plaintext
const SIZE_LEN: usize = 8;

/// The number of bytes in the entire header (magic number + attributes)
const HEADER_LEN: usize = MAGIC_NUMBER_LEN + COUNTER_LEN + SALT_LEN + SIZE_LEN;

/// The number of bytes in a key
const KEY_LEN: usize = 32;

/// The number of derivation rounds
const KEY_ROUNDS: u32 = 1_000_000;


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
    /// The size of the plaintext data (i.e. unencrypted stream)
    pub size: usize,
}

impl Attributes {
    ///
    /// Creates a new [`Attributes`] struct based on the provided `stream`.
    ///
    pub fn from<T: Read + Seek>(stream: &mut Buffer<T>) -> io::Result<Attributes> {
        stream.seek_from_start(0)?;
        let mut hasher = Sha256::new();

        let mut buffer = [0u8; 32];
        let mut size = 0usize;
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => {
                    break;
                }
                Ok(n) => {
                    hasher.update(buffer);
                    size += n;
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

        Ok(Attributes { counter, salt, size })
    }
}


///
/// The [`EncryptionReader<T>`] creates a translation layer where plaintext
/// data from the backing stream gets encrypted on the fly as it is being read.
///
#[derive(Debug)]
pub struct EncryptionReader<T: Read + Seek> {
    attributes: Attributes,
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

        let (key, passphrase_hash) = derive_key(passphrase, &attributes.salt);

        let mut header = [0u8; HEADER_LEN];

        let (start, end) = (0usize, MAGIC_NUMBER_LEN);
        header[start..end].copy_from_slice(MAGIC_NUMBER);

        let (start, end) = (end, end + PASSPHRASE_HASH_LEN);
        header[start..end].copy_from_slice(&passphrase_hash);

        let (start, end) = (end, end + SIZE_LEN);
        header[start..end].copy_from_slice(&(attributes.size as u64).to_be_bytes());

        let (start, end) = (end, end + SALT_LEN);
        header[start..end].copy_from_slice(&attributes.salt);

        let (start, end) = (end, end + COUNTER_LEN);
        header[start..end].copy_from_slice(&attributes.counter.to_be_bytes());

        Ok(EncryptionReader { attributes, header, key, stream })
    }

    pub fn len(self) -> usize {
        self.attributes.size + HEADER_LEN
    }
}


///
/// The [`DecryptionReader<T>`] creates a translation layer where encrypted
/// data from the backing stream gets decrypted on the fly as it is being read.
///
#[derive(Debug)]
pub struct DecryptionReader<T: Read + Seek> {
    attributes: Attributes,
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

        let mut magic_number = [0u8; MAGIC_NUMBER_LEN];
        let mut passphrase_hash = [0u8; PASSPHRASE_HASH_LEN];
        let mut size_bytes = [0u8; SIZE_LEN];
        let mut salt = [0u8; SALT_LEN];
        let mut counter_bytes = [0u8; COUNTER_LEN];

        stream.seek_from_start(0)?;
        stream.read_exact(&mut magic_number)?;
        stream.read_exact(&mut passphrase_hash)?;
        stream.read_exact(&mut size_bytes)?;
        stream.read_exact(&mut salt)?;
        stream.read_exact(&mut counter_bytes)?;

        if magic_number != *MAGIC_NUMBER {
            return Err(io::Error::new(ErrorKind::InvalidData, "Wrong magic number"));
        }

        let size = u64::from_be_bytes(size_bytes) as usize;
        if size + HEADER_LEN != total_len {
            return Err(io::Error::new(ErrorKind::InvalidData, "Wrong stream size"));
        }

        let counter = u128::from_be_bytes(counter_bytes);
        let attributes = Attributes { counter, salt, size };

        let (key, passphrase_hash_check) = derive_key(passphrase, &salt);

        if passphrase_hash != passphrase_hash_check {
            return Err(io::Error::new(ErrorKind::Other, "Wrong passphrase"));
        }

        Ok(DecryptionReader { attributes, key, stream })
    }
}


///
/// Returns a tuple of key and a passphrase hash (a small section at the head
/// of an encrypted file used to quickly, and not perfectly, check if the
/// provided passphrase is wrong).
///
fn derive_key(passphrase: &str, salt: &[u8])
-> ([u8; KEY_LEN], [u8; PASSPHRASE_HASH_LEN]) {
    let mut hash = [0u8; KEY_LEN + PASSPHRASE_HASH_LEN];
    pbkdf2::<Hmac<Sha256>>(passphrase.as_bytes(), salt, KEY_ROUNDS, &mut hash);

    let mut key = [0u8; KEY_LEN];
    let mut pass_hash = [0u8; PASSPHRASE_HASH_LEN];

    key.copy_from_slice(&hash[..KEY_LEN]);
    pass_hash.copy_from_slice(&hash[KEY_LEN..]);

    (key, pass_hash)
}
