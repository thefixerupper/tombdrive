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

//! Provides [`Buffer`] which improves the IO performance of the underlying
//! [`BufReader`] by preserving its internal buffer whenever possible.

use std::io::{self, BufReader, ErrorKind, Read, Seek, SeekFrom};
use log::{debug, trace};

// ============== //
//     BUFFER     //
// ============== //

/// [`Buffer`] is a thin shim on top of [`BufReader`] which provides
/// seeking with better preservation of the internal buffer.
///
/// To create a new instance, call `Buffer::with_capacity()`.
///
/// Reading from `Buffer` is facilitated via the [`Read`] trait.
#[derive(Debug)]
pub struct Buffer<T>
where
    T: Read + Seek,
{
    /// Position of the cursor in the buffer (used for relative seeking)
    cursor: usize,
    /// The underlying `BufReader` that actually does all the buffering
    reader: BufReader<T>,
    /// The size of the buffer (as of the last time the buffer was reset)
    len: usize,
}

impl<T> Buffer<T>
where
    T: Read + Seek,
{
    /// Return the stored length of the buffer.
    ///
    /// The length will not be automatically recalculated if the length
    /// of the underlying stream changes. To recalculate the length, you must
    /// call the `reset()` function.
    #[inline]
    pub fn len(&self) -> usize { self.len }

    /// Recalculate the length of the stream that the `Buffer` operates on
    /// and returns it wrapped in an [`io::Result`].
    ///
    /// Note: This clears the internal buffer.
    pub fn reset(&mut self) -> io::Result<usize> {
        let current = self.reader.stream_position()?;
        let len: usize = self.reader.seek(SeekFrom::End(0))?
                                    .try_into().unwrap();
        if len > i64::MAX.try_into().unwrap() {
            return Err(io::Error::new(ErrorKind::Other, "File too large"));
        }
        self.len = len;
        self.reader.seek(SeekFrom::Start(current))?;
        debug!("Setting new buffer length: {}", len);
        Ok(self.len)
    }

    /// Seek to a new cursor position, preserving the buffer if possible.
    pub fn seek_from_start(&mut self, offset: usize) -> io::Result<()> {
        trace!("Seeking to offset: {}", offset);
        if offset > i64::MAX.try_into().unwrap() {
            return Err(io::Error::new(ErrorKind::InvalidInput,
                                      "Offset out of bounds"));
        }
        let rel_offset = TryInto::<i64>::try_into(offset).unwrap()
            - TryInto::<i64>::try_into(self.cursor).unwrap();
        self.reader.seek_relative(rel_offset)?;
        self.cursor = offset;
        Ok(())
    }

    /// Create a new [`Buffer`] built on top of the provided `stream`
    /// and preallocate the specified `capacity`.
    pub fn with_capacity(capacity: usize, stream: T) -> io::Result<Buffer<T>> {
        trace!("Creating a new buffer with capacity: {}", capacity);
        let reader = BufReader::with_capacity(capacity, stream);
        let mut buffer = Buffer { cursor: 0, reader, len: 0 };
        buffer.reset()?;
        Ok(buffer)
    }
}

impl<T> Read for Buffer<T>
where
    T: Read + Seek,
{
    /// Read some bytes into the specified `buffer`, returning how many
    /// bytes were read.
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let bytes_read = self.reader.read(buffer)?;
        debug!("Read {} bytes from the buffer, starting at: {}",
               bytes_read, self.cursor);
        self.cursor += bytes_read;
        Ok(bytes_read)
    }
}
