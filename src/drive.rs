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

use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read};
use std::os::linux::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, SystemTime};

use fuser::{self, FileAttr, FileType, Filesystem, MountOption, ReplyAttr,
            ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen,
            Request};
use libc;
use log::{debug, error, info, trace};

use crate::buffer::Buffer;
use crate::config::{Config, Operation};
use crate::crypto::{self, DecryptionReader, EncryptionReader};

// ==================== //
//     Type Aliases     //
// ==================== //

type InodeID = u64;
type Mode = u32;
type LinkCount = u64;
type OwnerID = u32;
type GroupID = u32;
type Size = u64;
type BlockSize = u64;
type Time = i64;
type HandleID = u64;
type InodeLock = RwLock<Inode>;

// ================== //
//     PERMISSION     //
// ================== //

#[repr(u32)]
#[derive(Clone, Copy)]
#[derive(Debug)]
#[derive(PartialEq, Eq)]
enum Permission {
    SetUserID = libc::S_ISUID,
    SetGroupID = libc::S_ISGID,
    Sticky = libc::S_ISVTX,
    OwnerRead = libc::S_IRUSR,
    OwnerWrite = libc::S_IWUSR,
    OwnerExecute = libc::S_IXUSR,
    GroupRead = libc::S_IRGRP,
    GroupWrite = libc::S_IWGRP,
    GroupExecute = libc::S_IXGRP,
    OthersRead = libc::S_IROTH,
    OthersWrite = libc::S_IWOTH,
    OthersExecute = libc::S_IXOTH,
}

// ================ //
//     METADATA     //
// ================ //

#[derive(Debug)]
struct Metadata {
    id: InodeID,
    inner: fs::Metadata,
}

impl Metadata {
    pub fn file_type(&self) -> FileType {
        match self.mode() & libc::S_IFMT {
            libc::S_IFBLK => FileType::BlockDevice,
            libc::S_IFCHR => FileType::CharDevice,
            libc::S_IFDIR => FileType::Directory,
            libc::S_IFIFO => FileType::NamedPipe,
            libc::S_IFREG => FileType::RegularFile,
            libc::S_IFSOCK => FileType::Socket,
            libc::S_IFLNK => FileType::Symlink,
            _ => unreachable!(),
        }
    }

    #[inline]
    pub fn id(&self) -> InodeID { self.id }

    #[inline]
    pub fn set_id(&mut self, id: InodeID) { self.id = id }

    #[inline]
    pub fn size(&self) -> Size { self.inner.st_size() }

    #[inline]
    pub fn accessed(&self) -> Time { self.inner.st_atime() }

    #[inline]
    pub fn modified(&self) -> Time { self.inner.st_mtime() }

    #[inline]
    pub fn changed(&self) -> Time { self.inner.st_ctime() }

    #[inline]
    pub fn created(&self) -> Time { self.inner.st_mtime() }

    #[inline]
    pub fn mode(&self) -> Mode { self.inner.st_mode() }

    #[inline]
    pub fn link_count(&self) -> LinkCount { self.inner.st_nlink() }

    #[inline]
    pub fn owner_id(&self) -> OwnerID { self.inner.st_uid() }

    #[inline]
    pub fn group_id(&self) -> GroupID { self.inner.st_gid() }

    #[inline]
    pub fn block_size(&self) -> BlockSize { self.inner.st_blksize() }

    #[inline]
    pub fn has_permission(&self, permission: Permission) -> bool {
        0 < permission as u32 & self.mode()
    }

    pub fn to_file_attr(&self, operation: Operation) -> FileAttr {
        let size = if self.file_type() == FileType::RegularFile {
            let header = crypto::HEADER_LEN.try_into().unwrap();
            match operation {
                Operation::Encrypt if self.size() == 0 => { 0 },
                Operation::Encrypt => {
                    self.size().checked_add(header).unwrap()
                },
                Operation::Decrypt if self.size() > header => {
                    self.size() - header
                },
                Operation::Decrypt => { 0 },
            }
        } else {
            self.size()
        };

        #[inline]
        fn to_system_time(t: Time) -> SystemTime {
            const E: SystemTime = SystemTime::UNIX_EPOCH;
            E + Duration::from_secs(t.try_into().unwrap())
        }

        FileAttr {
            ino: self.id(),
            size,
            blocks: 0,
            atime: to_system_time(self.accessed()),
            mtime: to_system_time(self.modified()),
            ctime: to_system_time(self.changed()),
            crtime: to_system_time(self.created()),
            kind: self.file_type(),
            perm: self.mode() as u16,
            nlink: self.link_count().try_into().unwrap(),
            uid: self.owner_id(),
            gid: self.group_id(),
            rdev: 0,
            blksize: self.block_size().try_into().unwrap(),
            flags: 0,
        }
    }
}

impl TryFrom<&Path> for Metadata {
    type Error = io::Error;

    fn try_from(path: &Path) -> io::Result<Self> {
        let metadata = path.symlink_metadata()?;
        Ok(Self {
            id: metadata.st_ino(),
            inner: metadata,
        })
    }
}

// ============= //
//     INODE     //
// ============= //

#[derive(Debug)]
struct Inode {
    children: HashMap<OsString, Arc<InodeLock>>,
    inodes: Weak<RwLock<Inodes>>,
    metadata: Metadata,
    path: PathBuf,
    parent: Weak<InodeLock>,
}

impl Inode {
    fn refresh(&mut self) -> io::Result<()> {
        let id = self.metadata.id();
        self.metadata = self.path.as_path().try_into()?;
        self.metadata.set_id(id);

        match self.metadata.file_type() {
            FileType::Directory => self.load_children(),
            _ => Ok(self.children.clear()),
        }
    }

    fn load_children(&mut self) -> io::Result<()> {
        let mut remaining_names: HashSet<_> = self.children.keys()
                                                           .cloned()
                                                           .collect();

        let children = self.path.read_dir()?;
        for child in children {
            let child = child?;
            let child_name = child.file_name();
            let child_metadata: Metadata = child.path().as_path().try_into()?;

            if let Some(current_inode) = self.children.get(&child_name) {
                let current_inode = current_inode.read().unwrap();
                let current_file_type = current_inode.metadata.file_type();
                drop(current_inode);

                if current_file_type == child_metadata.file_type() {
                    remaining_names.remove(&child_name);
                    continue;
                } else {
                    self.remove_child(child_name);
                }
            }
            self.add_child(child, child_metadata);
        }

        for child_name in remaining_names.into_iter() {
            self.remove_child(child_name);
        }
        Ok(())
    }

    fn add_child(&mut self, child: fs::DirEntry, mut metadata: Metadata) {
        let inodes_arc = match Weak::upgrade(&self.inodes) {
            Some(inodes_arc) => inodes_arc,
            None => return,
        };
        let mut inodes = inodes_arc.write().unwrap();
        let id = if let Some(id) = inodes.recycling.pop() {
            id
        } else {
            Inodes::ROOT_ID + inodes.entries.len() as InodeID
        };
        let self_inode = inodes.entries.get(&self.metadata.id()).unwrap();
        let self_inode = Arc::downgrade(self_inode);

        metadata.set_id(id);
        let inode_arc = Arc::new(RwLock::new(Inode {
            children: HashMap::new(),
            inodes: Weak::clone(&self.inodes),
            metadata,
            path: child.path(),
            parent: self_inode,
        }));

        inodes.entries.insert(id, Arc::clone(&inode_arc));
        self.children.insert(child.file_name(), inode_arc);
    }

    fn remove_child(&mut self, child_name: OsString) {
        let inode_arc = self.children.get(&child_name).unwrap();
        let inode = inode_arc.read().unwrap();
        let id = inode.metadata.id();
        drop(inode);

        let inodes_arc = match Weak::upgrade(&self.inodes) {
            Some(inodes_arc) => inodes_arc,
            None => return,
        };
        let mut inodes = inodes_arc.write().unwrap();
        inodes.entries.remove(&id);
        drop(inodes);

        self.children.remove(&child_name);
    }
}

impl Drop for Inode {
    fn drop(&mut self) {
        trace!("Dropping inode: {}", self.metadata.id());
        if let Some(lock) = Weak::upgrade(&self.inodes) {
            let mut inodes = lock.write().unwrap();
            inodes.recycling.push(self.metadata.id());
        }
    }
}

// ============== //
//     INODES     //
// ============== //

#[derive(Debug)]
struct Inodes {
    entries: HashMap<InodeID, Arc<InodeLock>>,
    recycling: Vec<InodeID>,
    root: Arc<InodeLock>,
}

impl Inodes {
    const ROOT_ID: InodeID = 1;

    fn new(mut root: Inode) -> Self {
        root.metadata.set_id(Self::ROOT_ID);
        let arc_root = Arc::new(RwLock::new(root));
        Self {
            entries: HashMap::from([(Self::ROOT_ID, Arc::clone(&arc_root))]),
            recycling: Vec::new(),
            root: arc_root,
        }
    }
}

// ======================= //
//     HANDLE CONTENTS     //
// ======================= //

#[derive(Debug)]
enum HandleContents {
    Directory(Vec<Arc<RwLock<Inode>>>),
    CiphertextFile(Mutex<DecryptionReader<fs::File>>),
    PlaintextFile(Mutex<EncryptionReader<fs::File>>),
    NoContents,
}

// ============== //
//     HANDLE     //
// ============== //

#[derive(Debug)]
struct Handle {
    contents: HandleContents,
    inode: Arc<InodeLock>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        trace!("Dropping handle");
    }
}

// =============== //
//     HANDLES     //
// =============== //

#[derive(Debug)]
struct Handles {
    entries: HashMap<HandleID, Arc<Handle>>,
    recycling: Vec<HandleID>,
}

impl Handles {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            recycling: Vec::new(),
        }
    }

    fn create(
        &mut self,
        inode: &Arc<RwLock<Inode>>,
        config: &Config,
    ) -> io::Result<HandleID> {
        let operation = config.operation();
        let passphrase = config.passphrase();

        let handle_id = match self.recycling.pop() {
            Some(id) => id,
            None => self.entries.len() as HandleID,
        };

        let inode_arc = Arc::clone(inode);
        let contents = {
            let header = crypto::HEADER_LEN.try_into().unwrap();
            let inode = inode_arc.read().unwrap();
            match inode.metadata.file_type() {
                FileType::Directory => {
                    HandleContents::Directory(inode.children.iter()
                                                            .map(|(_, c)| Arc::clone(c))
                                                            .collect())
                },
                FileType::RegularFile if operation == Operation::Decrypt
                                      && inode.metadata.size() > header => {
                    let file = fs::File::open(&inode.path)?;
                    let buffer = Buffer::with_capacity(crypto::HEADER_LEN, file)?;
                    let reader = DecryptionReader::new(buffer, passphrase)?;
                    HandleContents::CiphertextFile(Mutex::new(reader))
                },
                FileType::RegularFile if operation == Operation::Encrypt
                                      && inode.metadata.size() > 0 => {
                    let file = fs::File::open(&inode.path)?;
                    let buffer = Buffer::with_capacity(0, file)?;
                    let reader = EncryptionReader::new(buffer, passphrase)?;
                    HandleContents::PlaintextFile(Mutex::new(reader))
                },
                _ => {
                    HandleContents::NoContents
                },
            }
        };

        let handle = Handle {
            contents,
            inode: inode_arc,
        };

        self.entries.insert(handle_id, Arc::new(handle));

        Ok(handle_id)
    }

    fn get(&self, id: HandleID) -> Option<Arc<Handle>> {
        if let Some(handle) = self.entries.get(&id) {
            Some(Arc::clone(handle))
        } else {
            None
        }
    }

    fn remove(&mut self, id: HandleID) {
        self.entries.remove(&id);
        self.recycling.push(id);
    }
}

// ============= //
//     DRIVE     //
// ============= //

#[derive(Debug)]
pub struct Drive {
    config: Config,
    handles: RwLock<Handles>,
    inodes: Arc<RwLock<Inodes>>,
}

impl Drive {
    pub fn new(config: Config) -> io::Result<Self> {
        debug!("Creating a new drive");

        let source = config.source().to_owned();
        let root_metadata = source.as_path().try_into()?;
        let root_inode = Inode {
            children: HashMap::new(),
            inodes: Weak::new(),
            metadata: root_metadata,
            path: source,
            parent: Weak::new(),
        };
        let inodes_arc = Arc::new(RwLock::new(Inodes::new(root_inode)));
        {
            let inodes = inodes_arc.write().unwrap();
            inodes.root.write().unwrap().inodes = Arc::downgrade(&inodes_arc);
        }

        Ok(Self {
            config,
            handles: RwLock::new(Handles::new()),
            inodes: inodes_arc,
        })
    }

    pub fn mount(self) -> io::Result<()> {
        let mut options = vec![
            MountOption::FSName(clap::crate_name!().to_string()),
            MountOption::RO,
        ];

        if self.config.single_threaded() {
            options.push(MountOption::Sync);
        }

        if !self.config.foreground() {
            loop {
                let pid = unsafe { libc::fork() };
                if pid == - 1 {
                    let err = io::Error::last_os_error();
                    if let Some(code) = err.raw_os_error() {
                        if code == libc::EAGAIN {
                            continue;
                        } else {
                            error!("Could not fork");
                            process::exit(code);
                        }
                    }
                    error!("Could not fork (unknown error)");
                    process::exit(-1);
                }
                if pid > 0 {
                    info!("Creating a background process");
                    process::exit(0); // foreground process exits
                }
                if pid == 0 {
                    break;
                }
            }
        }

        let target = self.config.target().to_owned();
        fuser::mount2(self, target, &options)
    }
}

impl Filesystem for Drive {
    fn opendir(
        &mut self,
        _: &Request<'_>,
        inode_id: InodeID,
        _flags: i32,
        reply: ReplyOpen
    ) {
        let inodes = self.inodes.read().unwrap();
        if let Some(inode_arc) = inodes.entries.get(&inode_id) {
            let inode_arc = Arc::clone(inode_arc);
            let mut inode = inode_arc.write().unwrap();
            drop(inodes);
            if let Err(_) = inode.refresh() {
                reply.error(libc::EACCES);
                return;
            }
            drop(inode);
            let mut handles = self.handles.write().unwrap();
            if let Ok(handle_id) = handles.create(&inode_arc, &self.config) {
                reply.opened(handle_id, 0);
            } else {
                reply.error(libc::EACCES);
            };
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn readdir(
        &mut self,
        _: &Request<'_>,
        inode_id: InodeID,
        handle_id: HandleID,
        offset: i64,
        mut reply: ReplyDirectory
    ) {
        let offset = offset as usize;

        let handles = self.handles.read().unwrap();
        if let Some(handle) = handles.get(handle_id) {
            let inode = handle.inode.read().unwrap();
            let inode_check = inode.metadata.id() == inode_id;

            if !inode_check {
                reply.error(libc::EINVAL);
                return;
            }

            if let HandleContents::Directory(children) = &handle.contents {
                let parent_inode_arc = Weak::upgrade(&inode.parent);
                let parent_inode_arc = if parent_inode_arc.is_some() {
                    parent_inode_arc.unwrap()
                } else {
                    Arc::clone(&handle.inode)
                };
                let dot_files = [&handle.inode, &parent_inode_arc];
                let children_iter = dot_files.into_iter().chain(children.iter());

                for (idx, child_arc) in children_iter.enumerate() {
                    if idx < offset {
                        continue;
                    }
                    let child = child_arc.read().unwrap();
                    let mut child_name = child.path.file_name().unwrap();
                    let mut child_name_string;
                    if idx == 0 {
                        child_name_string = OsString::from(".");
                        child_name = child_name_string.as_os_str();
                    }
                    if idx == 1 {
                        child_name_string = OsString::from("..");
                        child_name = child_name_string.as_os_str();
                    }
                    if reply.add(child.metadata.id(),
                                 (idx + 1) as i64,
                                 child.metadata.file_type(),
                                 child_name) {
                        reply.ok();
                        return;
                    }
                }
                reply.ok();

            } else {
                reply.error(libc::EACCES);
            }
        } else {
            reply.error(libc::EINVAL);
        }
    }

    fn releasedir(
        &mut self,
        _: &Request<'_>,
        inode_id: InodeID,
        handle_id: HandleID,
        _flags: i32,
        reply: ReplyEmpty
    ) {
        let mut handles = self.handles.write().unwrap();
        if let Some(handle) = handles.get(handle_id) {
            let inode = handle.inode.read().unwrap();
            let inode_check = inode.metadata.id() == inode_id;
            drop(inode);

            if !inode_check {
                reply.error(libc::EINVAL);
            } else {
                handles.remove(handle_id);
                reply.ok();
            }
        } else {
            reply.error(libc::EINVAL);
        }
    }

    fn open(
        &mut self,
        _: &Request<'_>,
        inode_id: InodeID,
        _flags: i32,
        reply: ReplyOpen
    ) {
        let inodes = self.inodes.read().unwrap();
        if let Some(inode_arc) = inodes.entries.get(&inode_id) {
            let inode_arc = Arc::clone(inode_arc);
            drop(inodes);
            let mut handles = self.handles.write().unwrap();
            if let Ok(handle_id) = handles.create(&inode_arc, &self.config) {
                reply.opened(handle_id, 0);
            } else {
                reply.error(libc::EACCES);
            }
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn read(
        &mut self,
        _: &Request<'_>,
        inode_id: InodeID,
        handle_id: HandleID,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData
    ) {
        assert!(offset >= 0);
        let offset = offset as usize;

        let handles = self.handles.read().unwrap();
        if let Some(handle) = handles.get(handle_id) {
            let inode = handle.inode.read().unwrap();
            let inode_check = inode.metadata.id() == inode_id;

            if !inode_check {
                reply.error(libc::EINVAL);
                return;
            }

            if let HandleContents::NoContents = &handle.contents {
                reply.data(&[]);
                return;
            }

            // TODO
            // Reduce code duplication

            let result = match &handle.contents {
                HandleContents::CiphertextFile(mutex) => {
                    let mut reader = mutex.lock().unwrap();
                    reader.seek_from_start(offset);

                    let remaining_len = reader.len()
                                              .saturating_sub(offset)
                                              .try_into()
                                              .unwrap();
                    let buffer_len = size.min(remaining_len);
                    let mut buffer = vec![0; buffer_len.try_into().unwrap()];

                    reader.read_exact(&mut buffer[..]).and(Ok(buffer))
                },
                HandleContents::PlaintextFile(mutex) => {
                    let mut reader = mutex.lock().unwrap();
                    reader.seek_from_start(offset);

                    let remaining_len = reader.len()
                                              .saturating_sub(offset)
                                              .try_into()
                                              .unwrap();
                    let buffer_len = size.min(remaining_len);
                    let mut buffer = vec![0; buffer_len.try_into().unwrap()];

                    reader.read_exact(&mut buffer[..]).and(Ok(buffer))
                },
                _ => unreachable!(),
            };

            match result {
                Ok(buffer) => {
                    reply.data(&buffer);
                    return;
                },
                Err(err) => {
                    error!("{}", err);
                    reply.error(libc::EIO);
                    return;
                },
            }
        }
    }

    fn release(
        &mut self,
        _: &Request<'_>,
        inode_id: InodeID,
        handle_id: HandleID,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty
    ) {
        let mut handles = self.handles.write().unwrap();
        if let Some(handle) = handles.get(handle_id) {
            let inode = handle.inode.read().unwrap();
            let inode_check = inode.metadata.id() == inode_id;
            drop(inode);

            if !inode_check {
                reply.error(libc::EINVAL);
            } else {
                handles.remove(handle_id);
                reply.ok();
            }
        } else {
            reply.error(libc::EINVAL);
        }
    }

    fn lookup(
        &mut self,
        _: &Request<'_>,
        parent_id: InodeID,
        name: &OsStr,
        reply: ReplyEntry
    ) {
        let inodes = self.inodes.write().unwrap();
        if let Some(parent_inode_arc) = inodes.entries.get(&parent_id) {
            let parent_inode_arc = Arc::clone(parent_inode_arc);
            drop(inodes);
            let mut parent_inode = parent_inode_arc.write().unwrap();
            if let Err(_) = parent_inode.refresh() {
                reply.error(libc::EACCES);
                return;
            }
            if let Some(child_inode_arc) = parent_inode.children.get(name) {
                let child_inode = child_inode_arc.read().unwrap();
                let operation = self.config.operation();
                let child_attr = child_inode.metadata.to_file_attr(operation);
                reply.entry(&Duration::from_secs(1), &child_attr, 0);
            } else {
                reply.error(libc::ENOENT);
            }
        }
    }

    fn getattr(
        &mut self,
        _: &Request<'_>,
        inode_id: InodeID,
        reply: ReplyAttr
    ) {
        let inodes = self.inodes.read().unwrap();
        if let Some(inode_arc) = inodes.entries.get(&inode_id) {
            let inode = inode_arc.read().unwrap();
            reply.attr(&Duration::from_secs(1),
                       &inode.metadata.to_file_attr(self.config.operation()))
        } else {
            reply.error(libc::ENOENT);
        }
    }
}
