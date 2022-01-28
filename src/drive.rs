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

use std::collections::{ HashMap, HashSet };
use std::ffi::{ CString, OsStr, OsString };
use std::fs;
use std::io;
use std::mem::{ self, MaybeUninit };
use std::path::PathBuf;
use std::sync::{ Arc, Mutex, RwLock, Weak };
use std::time::{ Duration, SystemTime };

use fuser::{ self, Filesystem, MountOption };
use libc;

use crate::config::Config;

// ==================== //
//     Type Aliases     //
// ==================== //

type InodeID = libc::ino_t;
type LinkCount = libc::nlink_t;
type OwnerID = libc::uid_t;
type GroupID = libc::gid_t;
type Size = libc::off_t;
type Time = libc::time_t;
type HandleID = u64;

// ================= //
//     FILE TYPE     //
// ================= //

#[derive(Copy, Clone, Debug, PartialEq)]
enum FileType {
    BlockDevice,
    CharDevice,
    Directory,
    NamedPipe,
    RegularFile,
    Socket,
    Symlink,
}

// ================== //
//     PERMISSION     //
// ================== //

#[repr(u32)]
#[derive(Copy, Clone, Debug)]
enum Permission {
    SetUserID     = libc::S_ISUID,
    SetGroupID    = libc::S_ISGID,
    Sticky        = libc::S_ISVTX,
    OwnerRead     = libc::S_IRUSR,
    OwnerWrite    = libc::S_IWUSR,
    OwnerExecute  = libc::S_IXUSR,
    GroupRead     = libc::S_IRGRP,
    GroupWrite    = libc::S_IWGRP,
    GroupExecute  = libc::S_IXGRP,
    OthersRead    = libc::S_IROTH,
    OthersWrite   = libc::S_IWOTH,
    OthersExecute = libc::S_IXOTH,
}

// ================ //
//     METADATA     //
// ================ //

/// Metadata
#[derive(Debug)]
struct Metadata {
    id: InodeID,
    mode: u32,
    link_count: LinkCount,
    owner_id: OwnerID,
    group_id: GroupID,
    size: Size,
    access_time: Time,
    modification_time: Time,
    change_time: Time,
}

impl Metadata {
    pub fn inode(&self) -> InodeID { self.id }

    pub fn file_type(&self) -> FileType {
        match self.mode & libc::S_IFMT {
            libc::S_IFBLK  => FileType::BlockDevice,
            libc::S_IFCHR  => FileType::CharDevice,
            libc::S_IFDIR  => FileType::Directory,
            libc::S_IFIFO  => FileType::NamedPipe,
            libc::S_IFREG  => FileType::RegularFile,
            libc::S_IFSOCK => FileType::Socket,
            libc::S_IFLNK  => FileType::Symlink,
            _ => unreachable!(),
        }
    }

    pub fn has_permission(&self, permission: Permission) -> bool {
        0 < permission as u32 & self.mode
    }

    pub fn owner(&self) -> OwnerID { self.owner_id }
    pub fn group(&self) -> GroupID { self.group_id }

    pub fn size(&self) -> Size { self.size }

    pub fn increase_size(&mut self, by: Size) {
        self.size += by;
    }

    pub fn decrease_size(&mut self, by: Size) {
        self.size -= by;
    }

    pub fn to_fuser_file_type(&self) -> fuser::FileType {
        match self.file_type() {
            FileType::BlockDevice => fuser::FileType::BlockDevice,
            FileType::CharDevice => fuser::FileType::CharDevice,
            FileType::Directory => fuser::FileType::Directory,
            FileType::NamedPipe => fuser::FileType::NamedPipe,
            FileType::RegularFile => fuser::FileType::RegularFile,
            FileType::Socket => fuser::FileType::Socket,
            FileType::Symlink => fuser::FileType::Symlink,
        }
    }

    pub fn to_file_attr(&self) -> fuser::FileAttr {
        const E: SystemTime = SystemTime::UNIX_EPOCH;
        fuser::FileAttr {
            ino: self.id,
            size: self.size as u64,
            blocks: 0,
            atime: E + Duration::from_secs(self.access_time as u64),
            mtime: E + Duration::from_secs(self.modification_time as u64),
            ctime: E + Duration::from_secs(self.change_time as u64),
            crtime: E + Duration::from_secs(self.modification_time as u64),
            kind: self.to_fuser_file_type(),
            perm: self.mode as u16,
            nlink: self.link_count as u32,
            uid: self.owner_id,
            gid: self.group_id,
            rdev: 0,
            blksize: 0,
            flags: 0,
        }
    }
}

impl TryFrom<&OsStr> for Metadata {
    type Error = ();

    fn try_from(path: &OsStr) -> Result<Self, ()> {
        println!("Metadata::try_from()");
        let c_path = CString::new(path.to_str().unwrap()).unwrap();
        let mut stat = MaybeUninit::uninit();
        if unsafe { libc::stat(c_path.as_ptr(), stat.as_mut_ptr()) } == -1 {
            return Err(());
        }
        let stat = unsafe { stat.assume_init() };

        Ok(Self {
            id: stat.st_ino,
            mode: stat.st_mode,
            link_count: stat.st_nlink,
            owner_id: stat.st_uid,
            group_id: stat.st_gid,
            size: stat.st_size,
            access_time: stat.st_atime,
            modification_time: stat.st_mtime,
            change_time: stat.st_mtime,
        })
    }
}

// ============= //
//     INODE     //
// ============= //

#[derive(Debug)]
struct Inode {
    children: HashMap<OsString, Arc<RwLock<Inode>>>,
    inodes: Weak<RwLock<Inodes>>,
    metadata: Metadata,
    path: PathBuf,
    parent: Weak<RwLock<Inode>>,
}

impl Inode {
    fn refresh(&mut self) -> Result<(), ()> {
        println!("Inode::refresh()");
        let id = self.metadata.id;
        self.metadata = Metadata::try_from(self.path.as_os_str())?;
        self.metadata.id = id;

        match self.metadata.file_type() {
            FileType::Directory => self.load_children(),
            _ => Ok(self.children.clear()),
        }
    }

    fn load_children(&mut self) -> Result<(), ()> {
        println!("Inode::load_children()");
        let mut remaining_names: HashSet<_> = self.children.keys()
                                                           .cloned()
                                                           .collect();

        if let Ok(children) = self.path.read_dir() {
            for child in children {
                if child.is_err() {
                    return Err(());
                }

                let child = child.unwrap();
                let child_name = child.file_name();
                let child_metadata = Metadata::try_from(child.path().as_os_str())?;

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
        } else {
            Err(())
        }
    }

    fn add_child(&mut self, child: fs::DirEntry, mut metadata: Metadata) {
        println!("Inode::add_child()");
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
        let self_inode = inodes.entries.get(&self.metadata.id).unwrap();
        let self_inode = Arc::downgrade(self_inode);

        metadata.id = id;
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
        println!("Inode::remove_child()");
        let inode_arc = self.children.get(&child_name).unwrap();
        let inode = inode_arc.read().unwrap();
        let id = inode.metadata.id;
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
        println!("Inode::drop()");
        if let Some(lock) = Weak::upgrade(&self.inodes) {
            let mut inodes = lock.write().unwrap();
            inodes.recycling.push(self.metadata.id);
        }
    }
}

// ============== //
//     INODES     //
// ============== //

#[derive(Debug)]
struct Inodes {
    entries: HashMap<InodeID, Arc<RwLock<Inode>>>,
    recycling: Vec<InodeID>,
    root: Arc<RwLock<Inode>>,
}

impl Inodes {
    const ROOT_ID: InodeID = 1;

    fn new(mut root: Inode) -> Self {
        println!("Inodes::new()");
        root.metadata.id = Self::ROOT_ID;
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
    NoContents,
}

// ============== //
//     HANDLE     //
// ============== //

#[derive(Debug)]
struct Handle {
    contents: HandleContents,
    handles: Weak<RwLock<Handles>>,
    id: HandleID,
    inode: Arc<RwLock<Inode>>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        println!("Handle::drop()");
    }
}

// =============== //
//     HANDLES     //
// =============== //

#[derive(Debug)]
struct Handles {
    entries: HashMap<HandleID, Arc<Handle>>,
    handles: Weak<RwLock<Handles>>,
    recycling: Vec<HandleID>,
}

impl Handles {
    fn new() -> Self {
        println!("Handles::new()");
        Self {
            entries: HashMap::new(),
            handles: Weak::new(),
            recycling: Vec::new(),
        }
    }

    fn create(&mut self, inode: &Arc<RwLock<Inode>>) -> HandleID {
        println!("Handles::create()");
        let handle_id = match self.recycling.pop() {
            Some(id) => id,
            None => self.entries.len() as HandleID,
        };

        let inode_arc = Arc::clone(inode);
        let contents = {
            let inode = inode_arc.read().unwrap();
            match inode.metadata.file_type() {
                FileType::Directory => {
                    HandleContents::Directory(inode.children.iter()
                                                            .map(|(_, c)| Arc::clone(c))
                                                            .collect())
                },
                _ => {
                    HandleContents::NoContents
                },
            }
        };

        let handles = Weak::upgrade(&self.handles).unwrap();

        let handle = Handle {
            contents,
            handles: Arc::downgrade(&handles),
            id: handle_id,
            inode: inode_arc,
        };

        self.entries.insert(handle_id, Arc::new(handle));

        handle_id
    }

    fn get(&self, id: HandleID) -> Option<Arc<Handle>> {
        println!("Handles::get()");
        if let Some(handle) = self.entries.get(&id) {
            Some(Arc::clone(handle))
        } else {
            None
        }
    }

    fn remove(&mut self, id: HandleID) {
        println!("Handles::remove()");
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
    handles: Arc<RwLock<Handles>>,
    inodes: Arc<RwLock<Inodes>>,
}

impl Drive {
    pub fn new(config: Config) -> Result<Self, ()> {
        println!("Drive::new()");
        let handles_arc = Arc::new(RwLock::new(Handles::new()));
        {
            let mut handles = handles_arc.write().unwrap();
            handles.handles = Arc::downgrade(&handles_arc);
        }

        let root_metadata = Metadata::try_from(config.source.as_os_str())?;
        let root_inode = Inode {
            children: HashMap::new(),
            inodes: Weak::new(),
            metadata: root_metadata,
            path: config.source.clone(),
            parent: Weak::new(),
        };
        let inodes_arc = Arc::new(RwLock::new(Inodes::new(root_inode)));
        {
            let inodes = inodes_arc.write().unwrap();
            inodes.root.write().unwrap().inodes = Arc::downgrade(&inodes_arc);
        }

        Ok(Self {
            config,
            handles: handles_arc,
            inodes: inodes_arc,
        })
    }

    pub fn mount(self) -> io::Result<()> {
        println!("Drive::mount()");
        let options = [
            MountOption::FSName(clap::crate_name!().to_string()),
            MountOption::RO,
        ];
        let target = self.config.target.clone();
        fuser::mount2(self, target, &options)
    }
}

impl Filesystem for Drive {
    fn opendir(
        &mut self,
        _: &fuser::Request<'_>,
        inode_id: InodeID,
        _flags: i32,
        reply: fuser::ReplyOpen
    ) {
        println!("Drive::opendir()");
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
            let handle_id = handles.create(&inode_arc);
            reply.opened(handle_id, 0);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn readdir(
        &mut self,
        _: &fuser::Request<'_>,
        inode_id: InodeID,
        handle_id: HandleID,
        offset: i64,
        mut reply: fuser::ReplyDirectory
    ) {
        println!("Drive::readdir()");
        let offset = dbg!(offset) as usize;

        let handles = self.handles.write().unwrap();
        if let Some(handle) = handles.get(handle_id) {
            let inode = handle.inode.read().unwrap();
            let inode_check = inode.metadata.id == inode_id;

            if !inode_check {
                reply.error(libc::EINVAL);

            } else if let HandleContents::Directory(children) = &handle.contents {
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
                    dbg!(&child_name);
                    if reply.add(dbg!(child.metadata.id),
                                 dbg!((idx + 1) as i64),
                                 child.metadata.to_fuser_file_type(),
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
        _: &fuser::Request<'_>,
        inode_id: InodeID,
        handle_id: HandleID,
        _flags: i32,
        reply: fuser::ReplyEmpty
    ) {
        println!("Drive::releasedir()");
        let mut handles = self.handles.write().unwrap();
        if let Some(handle) = handles.get(handle_id) {
            let inode = handle.inode.read().unwrap();
            let inode_check = inode.metadata.id == inode_id;
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
        _: &fuser::Request<'_>,
        parent_id: InodeID,
        name: &OsStr,
        reply: fuser::ReplyEntry
    ) {
        println!("Drive::lookup()");
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
                let child_attr = child_inode.metadata.to_file_attr();
                reply.entry(&Duration::from_secs(1), &child_attr, 0);
            } else {
                reply.error(libc::ENOENT);
            }
        }
    }

    fn getattr(
        &mut self,
        _: &fuser::Request<'_>,
        inode_id: InodeID,
        reply: fuser::ReplyAttr
    ) {
        println!("Drive::getattr()");
        let inodes = self.inodes.read().unwrap();
        if let Some(inode_arc) = inodes.entries.get(&inode_id) {
            let inode = inode_arc.read().unwrap();
            reply.attr(&Duration::from_secs(1), &inode.metadata.to_file_attr())
        } else {
            reply.error(libc::ENOENT);
        }
    }
}
