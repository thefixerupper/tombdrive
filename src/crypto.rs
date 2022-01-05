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
//! Provides [`CryptoReader<T>`] and [`CryptoWriter<T>`] types used to access
//! encrypted streams (i.e. encrypted files).
//!
//! These types behave akin to [`BufReader<R>`] and [`BufWriter<W>`]
//! (and actually use the two for buffered access).
//!
//! They transparently read-and-decrypt/encrypt-and-write data (as well as any
//! associated attributes) from/to the backing type.
//!

use std::io::{ self, BufReader, BufWriter, ErrorKind,
               Read, Seek, SeekFrom, Write };


/// The number of bytes in the [`MAGIC_NUMBER`]
const MAGIC_NUMBER_LEN: usize = 8;

/// Magic bytes that are added to the beginning of every encrypted stream
const MAGIC_NUMBER: &[u8; MAGIC_NUMBER_LEN] = b"TombDrv:";

/// The number of bytes in the counter attribute
const COUNTER_LEN: usize = 16;

/// The number of bytes in the salt attribute
const SALT_LEN: usize = 16;

/// The number of bytes representing the size of a plaintext stream
const SIZE_LEN: usize = 8;

/// The number of bytes in the entire header (magic number + attributes)
/// cast into `u64` to match the `seek()` return type and the size attribute
const HEADER_LEN: u64 = (MAGIC_NUMBER_LEN + COUNTER_LEN +
                         SALT_LEN + SIZE_LEN) as u64;


/// After the [`MAGIC_NUMBER`], each non-zero-size encrypted stream holds
/// a couple of numerical attributes encrypted as big-endian bytes
#[derive(Debug)]
struct Attributes {
    /// The counter used to encrypt the first block of data
    counter: u128,
    /// The salt used for key derivation
    salt: u128,
    /// The size of the plaintext data (i.e. unencrypted stream)
    size: u64,
}


///
/// The [`CryptoReader<T>`] creates a translation layer where the encrypted
/// data from the backing stream gets decrypted on the fly as it is being read.
///
#[derive(Debug)]
pub struct CryptoReader<T: Read + Seek> {
    reader: BufReader<T>,
    attributes: Attributes,
    total_len: u64,
}

impl<T: Read + Seek> CryptoReader<T> {
    ///
    /// Create a new buffered [`CryptoReader<T>`].
    ///
    /// This function will return a [`io::Error`] if the `stream` is empty or
    /// if the `stream` does not look like it was encrypted
    /// by [`CryptoWriter<T>`].
    ///
    pub fn new(mut stream: T) -> io::Result<CryptoReader<T>> {
        let total_len = stream.seek(SeekFrom::End(0))?;
        if total_len == 0 {
            return Err(io::Error::new(ErrorKind::Other, "Empty stream"));
        }
        if total_len < HEADER_LEN {
            return Err(io::Error::new(ErrorKind::InvalidData, "Stream too short"));
        }
        let mut reader = BufReader::new(stream);

        let mut magic_number = [0u8; MAGIC_NUMBER_LEN];
        let mut size_bytes = [0u8; SIZE_LEN];
        let mut salt_bytes = [0u8; SALT_LEN];
        let mut counter_bytes = [0u8; COUNTER_LEN];

        reader.seek(SeekFrom::Start(0))?;
        reader.read_exact(&mut magic_number)?;
        reader.read_exact(&mut size_bytes)?;
        reader.read_exact(&mut salt_bytes)?;
        reader.read_exact(&mut counter_bytes)?;

        if magic_number != *MAGIC_NUMBER {
            return Err(io::Error::new(ErrorKind::InvalidData, "Wrong magic number"));
        }

        let size = u64::from_be_bytes(size_bytes);
        if size + HEADER_LEN != total_len {
            return Err(io::Error::new(ErrorKind::Other, "Wrong stream size"));
        }

        let salt = u128::from_be_bytes(salt_bytes);
        let counter = u128::from_be_bytes(counter_bytes);

        let attributes = Attributes { counter, salt, size };
        Ok(CryptoReader { reader, attributes, total_len })
    }
}
