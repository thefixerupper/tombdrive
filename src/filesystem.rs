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

use std::collections::{ HashMap, HashSet, LinkedList };
use std::ffi::{ OsString };
use std::fs::{ self, DirEntry, File };
use std::io::{ self, ErrorKind };
use std::path::{ Path, PathBuf };
use std::sync::{ Mutex, MutexGuard, RwLock, RwLockWriteGuard };

use fuser::{ self, FUSE_ROOT_ID as ROOT_INODE };
use libc;

use crate::config::{ Config, Operation };
use crate::crypto::{ self, DecryptionReader, EncryptionReader };
use crate::fuse;

type FileHandle = u64;
type Inode = u64;
type Passphrase = Vec<u8>;


#[derive(Clone, Copy, Debug)]
enum Kind {
    File,
    Directory,
    Symlink,
}

impl From<fs::FileType> for Kind {
    fn from(fs_kind: fs::FileType) -> Self {
        if fs_kind.is_dir() {
            Self::Directory
        } else if fs_kind.is_symlink() {
            Self::Symlink
        } else {
            Self::File
        }
    }
}

impl Into<fuser::FileType> for Kind {
    fn into(self) -> fuser::FileType {
        match self {
            Self::Directory => fuser::FileType::Directory,
            Self::File => fuser::FileType::RegularFile,
            Self::Symlink => fuser::FileType::Symlink,
        }
    }
}


#[derive(Debug)]
enum FileHandleEntry {
    Directory(Inode, Vec<Inode>),
    EmptyFile(Inode),
    PlaintextFile(Inode, EncryptionReader<File>),
    CiphertextFile(Inode, DecryptionReader<File>),
}

#[derive(Debug)]
struct InodeEntry {
    name: OsString,
    kind: Kind,
    children: HashSet<Inode>,
    parent: Inode,
}

#[derive(Debug)]
pub struct Filesystem {
    source: PathBuf,
    target: PathBuf,
    operation: Operation,
    passphrase: Passphrase,
    inodes: RwLock<HashMap<Inode, InodeEntry>>,
    inodes_recycling: Mutex<Vec<Inode>>,
    handles: RwLock<HashMap<FileHandle, FileHandleEntry>>,
    handles_recycling: Mutex<Vec<FileHandle>>,
}

impl Filesystem {
    //
    // GENERIC FUNCTIONS
    //

    /// Create a new filesystem that uses `passphrase` to do `operation`
    /// in order to mount a representation of `source` onto `target`.
    pub fn new(config: Config) -> io::Result<Filesystem> {
        let source = fs::canonicalize(config.source)?;
        if !source.is_dir() {
            return Err(io::Error::new(ErrorKind::InvalidInput,
                                     "Source is not a directory"));
        }

        let target = fs::canonicalize(config.target)?;
        if !target.is_dir() {
            return Err(io::Error::new(ErrorKind::InvalidInput,
                                      "Target is not a directory"));
        }

        let root_entry = InodeEntry {
            name: OsString::new(),
            kind: Kind::Directory,
            children: HashSet::new(),
            parent: 0,
        };

        Ok(Self {
            source,
            target,
            passphrase: config.passphrase,
            operation: config.operation,
            inodes: RwLock::new(HashMap::from([(1, root_entry)])),
            inodes_recycling: Mutex::new(Vec::new()),
            handles: RwLock::new(HashMap::new()),
            handles_recycling: Mutex::new(Vec::new()),
        })
    }

    /// Mount the filesystem
    pub fn mount(&mut self) -> io::Result<()> {
        fuse::mount(self)
    }

    /// Return a path to the target directory of this filesystem
    pub fn target(&self) -> &Path {
        self.target.as_path()
    }

    //
    // FILESYSTEM OPERATIONS
    //

    /// Open a directory specified by `inode`.
    pub fn open_dir(&mut self, inode: Inode) -> io::Result<FileHandle> {
        println!("open_dir");
        let path = self.inode_path(inode)?;

        let mut inodes = self.inodes.write().unwrap();
        let mut inodes_recycling = self.inodes_recycling.lock().unwrap();

        let current_children: HashMap<_, _> = match inodes.get(&inode) {
            Some(entry) => {
                entry.children.iter()
                              .map(|i| (inodes.get(i), *i))
                              .filter(|(o, _)| o.is_some())
                              .map(|(o, i)| (o.unwrap().name.clone(), i))
                              .collect()
            },
            None => {
                HashMap::new()
            },
        };

        let mut remaining_children = current_children;
        for new_item in path.read_dir()? {
            let new_item = new_item?;
            let new_name = new_item.file_name();

            if remaining_children.contains_key(&new_name) {
                remaining_children.remove(&new_name);
            } else {
                let entry = InodeEntry {
                    name: new_name,
                    kind: new_item.file_type().unwrap().into(),
                    children: HashSet::new(),
                    parent: inode,
                };
                Self::add_inode(&mut inodes, &mut inodes_recycling, entry);
            }
        }
        for inode_to_remove in remaining_children.values() {
            Self::remove_inode(&mut inodes, &mut inodes_recycling, *inode_to_remove);
        }

        let mut handles = self.handles.write().unwrap();
        let mut handles_recycling = self.handles_recycling.lock().unwrap();
        let new_children = inodes.get(&inode)
                                 .unwrap()
                                 .children
                                 .iter()
                                 .map(|i| *i)
                                 .collect();
        let handle_entry = FileHandleEntry::Directory(inode, new_children);
        Ok(Self::add_handle(&mut handles, &mut handles_recycling, handle_entry))
    }


    pub fn read_dir<>(
        &self,
        inode: Inode,
        handle: FileHandle,
        offset: i64,
        reply: &mut fuser::ReplyDirectory,
    ) -> io::Result<()> {
        println!("read_dir");
        let handles = self.handles.read().unwrap();
        let entry = handles.get(&handle);
        if entry.is_none() {
            return Err(io::Error::new(ErrorKind::InvalidInput, "Invalid file handle"));
        }
        let entry = entry.unwrap();

        let children = if let FileHandleEntry::Directory(entry_inode, children) = entry {
            if *entry_inode == inode {
                children
            } else {
                return Err(io::Error::new(ErrorKind::InvalidInput,
                                          "Inode does not match the file handle"));
            }
        } else {
            return Err(io::Error::new(ErrorKind::InvalidInput, "Not a directory"));
        };

        if offset < 0 {
            return Err(io::Error::new(ErrorKind::InvalidInput, "Invalid offset"));
        }
        let mut offset = offset as usize;

        if offset >= children.len() {
            return Ok(());
        }

        let inodes = self.inodes.read().unwrap();
        let iter = children[offset..].iter()
                                     .map(|i| (i, inodes.get(i)))
                                     .filter(|(_, o)| o.is_some())
                                     .map(|(i, o)| (*i, o.unwrap()));
        for (i, entry) in iter {
            offset += 1;
            if !reply.add(i, offset as i64, entry.kind.into(), &entry.name) {
                break;
            }
        }
        Ok(())
    }


    /// Close the directory file handle
    pub fn release_dir(&mut self, inode: Inode, handle: FileHandle) -> io::Result<()> {
        println!("release_dir");
        let mut handles = self.handles.write().unwrap();
        let mut handles_recycling = self.handles_recycling.lock().unwrap();

        match handles.get(&handle) {
            Some(FileHandleEntry::Directory(entry_inode, _)) => {
                if inode == *entry_inode {
                    Self::remove_handle(&mut handles, &mut handles_recycling, handle);
                    Ok(())
                } else {
                    Err(io::Error::new(ErrorKind::InvalidInput,
                                       "File handle does not match the inode"))
                }
            },
            None => {
                Err(io::Error::new(ErrorKind::InvalidInput,
                                   "File handle not found"))
            },
            _ => {
                Err(io::Error::new(ErrorKind::InvalidInput,
                                   "File handle does not belong to a directory"))
            }
        }
    }

    //
    // HELPER FUNCTIONS
    //

    /// Calculate a source path to `inode`.
    ///
    /// This function locks `self.inodes` so they must be unlocked.
    fn inode_path(&self, inode: Inode) -> io::Result<PathBuf> {
        if inode == ROOT_INODE {
            return Ok(self.source.to_owned());
        }

        let inodes = self.inodes.read().unwrap();

        const DEFAULT_TRACE_CAPACITY: usize = 16;
        let mut trace = Vec::with_capacity(DEFAULT_TRACE_CAPACITY);

        let mut current_inode = inode;
        loop {
            match inodes.get(&current_inode) {
                Some(entry) => {
                    trace.push(current_inode);
                    if entry.parent == ROOT_INODE {
                        break;
                    }
                    current_inode = entry.parent;
                },
                None => {
                    return Err(io::Error::new(ErrorKind::Other,
                                              "Inode tree is corrupted"));
                },
            }
        }

        const DEFAULT_PATH_PADDING: usize = 64;
        let mut path = self.source.clone();
        path.reserve(DEFAULT_PATH_PADDING);
        while let Some(current_inode) = trace.pop() {
            path.push(&inodes.get(&current_inode).unwrap().name);
        }

        Ok(path)
    }

    /// Add inode entry into the filesystem
    fn add_inode(
        inodes: &mut RwLockWriteGuard<HashMap<Inode, InodeEntry>>,
        recycling: &mut MutexGuard<Vec<Inode>>,
        entry: InodeEntry,
    ) {
        let new_inode = if recycling.is_empty() {
            inodes.len() as Inode + ROOT_INODE
        } else {
            recycling.pop().unwrap()
        };

        debug_assert!(!inodes.contains_key(&new_inode));

        let parent = inodes.get_mut(&entry.parent).unwrap();
        parent.children.insert(new_inode);

        inodes.insert(new_inode, entry);
    }

    // Add file handle into the filesystem
    fn add_handle(
        handles: &mut RwLockWriteGuard<HashMap<FileHandle, FileHandleEntry>>,
        recycling: &mut MutexGuard<Vec<FileHandle>>,
        entry: FileHandleEntry,
    ) -> FileHandle {
        let new_handle = if recycling.is_empty() {
            handles.len() as FileHandle + 1
        } else {
            recycling.pop().unwrap()
        };

        debug_assert!(!handles.contains_key(&new_handle));

        handles.insert(new_handle, entry);
        new_handle
    }

    /// Remove inode from the filesystem
    fn remove_inode(
        inodes: &mut RwLockWriteGuard<HashMap<Inode, InodeEntry>>,
        recycling: &mut MutexGuard<Vec<Inode>>,
        inode: Inode,
    ) {
        assert_ne!(inode, ROOT_INODE);
        debug_assert!(inodes.contains_key(&inode));
        debug_assert!(!recycling.contains(&inode));

        let parent_inode = inodes.get(&inode).unwrap().parent;

        if let Some(entry) = inodes.get_mut(&parent_inode) {
            entry.children.remove(&inode);
        }

        let mut inodes_to_remove = LinkedList::new();
        let mut last_round = LinkedList::new();
        last_round.push_back(inode);

        while !last_round.is_empty() {
            let mut new_inodes: LinkedList<_> = last_round.iter()
                                                          .map(|i| inodes.get(i))
                                                          .filter(|o| o.is_some())
                                                          .map(|o| &o.unwrap().children)
                                                          .flatten()
                                                          .map(|i| *i)
                                                          .collect();
            inodes_to_remove.append(&mut last_round);
            last_round.append(&mut new_inodes);
        }

        while let Some(inode_to_remove) = inodes_to_remove.pop_back() {
            debug_assert!(inodes.remove(&inode_to_remove).is_some());
            recycling.push(inode_to_remove);
        }
    }

    /// Remove file handle from the filesystem
    fn remove_handle(
        handles: &mut RwLockWriteGuard<HashMap<FileHandle, FileHandleEntry>>,
        recycling: &mut MutexGuard<Vec<FileHandle>>,
        handle: FileHandle,
    ) {
        debug_assert!(handles.contains_key(&handle));
        debug_assert!(!recycling.contains(&handle));

        handles.remove(&handle);
        recycling.push(handle);
    }
}
