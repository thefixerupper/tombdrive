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
//! Provides [`Buffer`] that simplifies [`BufReader`]'s seeking interface.
//!

use std::io::{ self, BufReader, ErrorKind, Read, Seek, SeekFrom };

///
/// A thin shim on top of [`BufReader`] that preserves buffer when seeking
/// via [`Seek`] functions.
///
#[derive(Debug)]
pub struct Buffer<T: Read + Seek> {
    cursor: u64,
    reader: BufReader<T>,
    len: u64,
}

impl<T: Read + Seek> Buffer<T> {
    ///
    /// Return the length of the underlying stream (as last checked).
    ///
    pub fn len(self) -> u64 {
        self.len
    }

    ///
    /// Recalculate the length of the stream that the `Buffer` operates on.
    ///
    pub fn reset(&mut self) -> io::Result<u64> {
        let current = self.reader.stream_position()?;
        self.len = self.reader.seek(SeekFrom::End(0))?;
        self.reader.seek(SeekFrom::Start(current))?;
        Ok(self.len)
    }


    ///
    /// Create a new [`Buffer`] from the supplied `stream` with `capacity`
    /// specified in bytes.
    ///
    /// The length of the `stream` is assumed not to change until
    /// [`reset`] is called, at which point the buffered data gets
    /// cleared.
    ///
    /// [`reset`]: Buffer::reset
    ///
    pub fn with_capacity(capacity: usize, stream: T) -> io::Result<Buffer<T>> {
        let reader = BufReader::with_capacity(capacity, stream);
        let mut buffer = Buffer { cursor: 0, reader, len: 0 };
        buffer.reset()?;
        Ok(buffer)
    }
}

impl<T: Read + Seek> Read for Buffer<T> {
    ///
    /// Read some data from the underlying stream. For more details see
    /// [`BufReader`].
    ///
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buffer)
    }
}

impl<T: Read + Seek> Seek for Buffer<T> {
    ///
    /// Seek to a new cursor position, preserving the buffer if possible.
    ///
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let (base, offset): (u64, i64) = match position {
            SeekFrom::Start(pos) => {
                if pos > i64::MAX as u64 {
                    return Err(io::Error::new(ErrorKind::InvalidInput,
                                              "Out of bounds seeking (1)"))
                } else {
                    (0, pos as i64)
                }
            }
            SeekFrom::Current(pos) => {
                (self.cursor, pos)
            }
            SeekFrom::End(pos) => {
                (self.len, pos)
            }
        };
        let new_cursor = if offset < 0 {
            base.checked_sub((-offset) as u64)
        } else {
            base.checked_add(offset as u64)
        };
        let new_cursor = match new_cursor {
            Some(val) => val,
            None => return Err(io::Error::new(ErrorKind::InvalidInput,
                                              "Out of bounds seeking (2)")),
        };
        if new_cursor > i64::MAX as u64 {
            return Err(io::Error::new(ErrorKind::InvalidInput,
                                      "Out of bounds seeking (3)"));
        }
        let new_offset = new_cursor as i64 - self.cursor as i64;
        self.reader.seek_relative(new_offset)?;
        Ok(new_cursor)
    }
}
