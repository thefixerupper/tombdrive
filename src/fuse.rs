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

use std::io::{ self, ErrorKind };

use clap;
use fuser::{ self, MountOption, ReplyDirectory, ReplyEmpty, ReplyOpen, Request };

use crate::filesystem::Filesystem;

struct Wrapper<'a> {
    inner: &'a mut Filesystem,
}

impl<'a> fuser::Filesystem for Wrapper<'a> {
    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: fuser::ReplyAttr) {
        println!("getattr");
    }

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &std::ffi::OsStr, reply: fuser::ReplyEntry) {
        println!("lookup {:?}", name);
    }

    fn opendir(
        &mut self, _: &Request<'_>,
        inode: u64,
        _flags: i32,
        reply: ReplyOpen
    ) {
        match self.inner.open_dir(inode) {
            Ok(handle) => reply.opened(handle, 0),
            Err(err) => match err.kind() {
                _ => reply.error(libc::ENOENT),
            },
        }
    }

    fn readdir(
        &mut self, _: &Request<'_>,
        inode: u64,
        handle: u64,
        offset: i64,
        mut reply: ReplyDirectory
    ) {
        match self.inner.read_dir(inode, handle, offset, &mut reply) {
            Ok(_) => reply.ok(),
            Err(_) => reply.error(libc::EINVAL),
        }
    }

    fn releasedir(
        &mut self, _: &Request<'_>,
        inode: u64,
        handle: u64,
        _flags: i32,
        reply: ReplyEmpty
    ) {
        match self.inner.release_dir(inode, handle) {
            Ok(_) => reply.ok(),
            Err(_) => reply.error(libc::EBADF),
        }
    }
}

pub fn mount(filesystem: &mut Filesystem) -> io::Result<()> {
    let options = [
        MountOption::Async,
        MountOption::FSName(clap::crate_name!().to_string()),
        MountOption::NoAtime,
        MountOption::NoDev,
        MountOption::NoExec,
        MountOption::RO,
    ];

    let mountpoint = filesystem.target().to_path_buf();
    let wrapper = Wrapper { inner: filesystem };

    fuser::mount2(wrapper, mountpoint, &options)
}
