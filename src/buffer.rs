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
    cursor: usize,
    reader: BufReader<T>,
    len: usize,
}

impl<T: Read + Seek> Buffer<T> {
    ///
    /// Return the length of the underlying stream (as last checked).
    ///
    pub fn len(&self) -> usize {
        self.len
    }

    ///
    /// Recalculate the length of the stream that the `Buffer` operates on.
    ///
    pub fn reset(&mut self) -> io::Result<usize> {
        let current = self.reader.stream_position()?;
        let len = self.reader.seek(SeekFrom::End(0))? as usize;
        if len > i64::MAX as usize {
            return Err(io::Error::new(ErrorKind::Other, "File too large"));
        }
        self.len = len;
        self.reader.seek(SeekFrom::Start(current))?;
        Ok(self.len)
    }

    ///
    /// Seek to a new cursor position, preserving the buffer if possible.
    ///
    pub fn seek_from_start(&mut self, offset: usize) -> io::Result<()> {

        if offset > i64::MAX as usize {
            return Err(io::Error::new(ErrorKind::InvalidInput,
                                      "Offset out of bounds"));
        }

        let rel_offset = offset as i64 - dbg!(self.cursor) as i64;
        self.reader.seek_relative(dbg!(rel_offset))?;
        self.cursor = offset;
        Ok(())
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
    /// [`Read`].
    ///
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let bytes_read = self.reader.read(buffer)?;
        self.cursor += bytes_read;
        Ok(bytes_read)
    }
}
