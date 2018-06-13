extern crate libc;

use std::ffi::OsStr;
use std::fs::{canonicalize, metadata};
use std::io;
use std::path::PathBuf;
use std::result;

mod env;

#[derive(Debug)]
pub enum Error {
    Canonicalize(PathBuf, io::Error),
    Chroot(i32),
    Copy(PathBuf, PathBuf, io::Error),
    CreateDir(PathBuf, io::Error),
    Exec(io::Error),
    FileName(PathBuf),
    Gid(String),
    Metadata(PathBuf, io::Error),
    NotAFile(PathBuf),
    Uid(String),
}

pub type Result<T> = result::Result<T, Error>;

pub struct JailerArgs<'a> {
    id: &'a str,
    exec_file_path: PathBuf,
    uid: u32,
    gid: u32,
}

impl<'a> JailerArgs<'a> {
    pub fn new(id: &'a str, exec_file: &'a str, uid: &str, gid: &str) -> Result<Self> {
        let exec_file_path =
            canonicalize(exec_file).map_err(|e| Error::Canonicalize(PathBuf::from(exec_file), e))?;

        if !metadata(&exec_file_path)
            .map_err(|e| Error::Metadata(exec_file_path.clone(), e))?
            .is_file()
        {
            return Err(Error::NotAFile(exec_file_path));
        }

        let uid = uid.parse::<u32>()
            .map_err(|_| Error::Uid(String::from(uid)))?;
        let gid = gid.parse::<u32>()
            .map_err(|_| Error::Gid(String::from(gid)))?;

        Ok(JailerArgs {
            id,
            exec_file_path,
            uid,
            gid,
        })
    }

    pub fn exec_file_name(&self) -> Result<&OsStr> {
        self.exec_file_path
            .file_name()
            .ok_or_else(|| Error::FileName(self.exec_file_path.clone()))
    }
}
