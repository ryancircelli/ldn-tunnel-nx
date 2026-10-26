//! Thin `Result` wrappers over nx's fs for the paths in `ident.rs` (`sdmc:/...`).
//!
//! Horizon's `RenameFile` refuses to replace an existing file, so callers that
//! replace delete the target first (see [`replace`]).
#![forbid(unsafe_code)]

use nx::fs::{self, DirectoryEntryType, DirectoryOpenMode, FileAccessor, FileOpenOption};
use nx::result::Result;

pub fn mount_sd() -> Result<()> {
    fs::initialize_fspsrv_session()?;
    fs::mount_sd_card("sdmc")
}

/// A regular file is at `path`.
pub fn exists(path: &str) -> bool {
    matches!(fs::get_entry_type(path), Ok(DirectoryEntryType::File))
}

pub fn dir_exists(path: &str) -> bool {
    matches!(fs::get_entry_type(path), Ok(DirectoryEntryType::Directory))
}

/// Creates `path` and every missing parent (`sdmc:/a/b` → `sdmc:/a`, `sdmc:/a/b`).
pub fn create_dir_all(path: &str) -> Result<()> {
    let root = path.find(":/").map_or(0, |i| i.saturating_add(2));
    for (i, _) in path.match_indices('/').filter(|&(i, _)| i > root) {
        if let Some(parent) = path.get(..i)
            && !dir_exists(parent)
        {
            fs::create_directory(parent)?;
        }
    }
    if dir_exists(path) { Ok(()) } else { fs::create_directory(path) }
}

pub fn open_read(path: &str) -> Result<FileAccessor> {
    fs::open_file(path, FileOpenOption::Read())
}

pub fn file_size(path: &str) -> Result<usize> {
    open_read(path)?.get_size()
}

/// Reads from the start of `path` until `buf` is full or the file ends; returns the length.
pub fn read_into(path: &str, buf: &mut [u8]) -> Result<usize> {
    let mut f = open_read(path)?;
    let mut len = 0;
    while let Some(rest) = buf.get_mut(len..).filter(|r| !r.is_empty()) {
        match f.read_array(rest)? {
            0 => break,
            n => len = len.saturating_add(n),
        }
    }
    Ok(len)
}

/// Opens (creating if missing) for writing at the end of the file.
pub fn open_append(path: &str) -> Result<FileAccessor> {
    fs::open_file(path, FileOpenOption::Create() | FileOpenOption::Write() | FileOpenOption::Append())
}

/// Creates `path` (it must not exist) holding `data`, flushed.
pub fn write_new(path: &str, data: &[u8]) -> Result<()> {
    fs::create_file(path, 0, fs::FileAttribute::None())?;
    let mut f = fs::open_file(path, FileOpenOption::Write() | FileOpenOption::Append())?;
    f.write_array::<u8, true>(data)
}

/// Appends `line` + `\n`, flushed.
pub fn append_line(path: &str, line: &str) -> Result<()> {
    let mut f = open_append(path)?;
    f.write_array::<u8, false>(line.as_bytes())?;
    f.write_array::<u8, true>(b"\n")
}

pub fn rename(from: &str, to: &str) -> Result<()> {
    fs::rename_file(from, to)
}

/// Deletes `path`; a missing file is success.
pub fn delete(path: &str) -> Result<()> {
    if exists(path) { fs::remove_file(path) } else { Ok(()) }
}

/// Durable replace of `path` by a complete `tmp`: delete `path`, rename `tmp` in.
/// A cut between the two leaves only `tmp`; [`recover_tmp`] finishes it.
pub fn replace(tmp: &str, path: &str) -> Result<()> {
    delete(path)?;
    rename(tmp, path)
}

/// `path` is missing but a complete `tmp` is there (a [`replace`] cut by power loss):
/// renames it in. True if `path` exists afterwards.
pub fn recover_tmp(tmp: &str, path: &str) -> bool {
    if !exists(path) && exists(tmp) {
        let _ = rename(tmp, path);
    }
    exists(path)
}

/// Calls `f` with the name of every entry in `dir` (files and directories).
pub fn for_each_entry(dir: &str, mut f: impl FnMut(&str, DirectoryEntryType)) -> Result<()> {
    let mut d = fs::open_directory(
        dir,
        DirectoryOpenMode::ReadDirectories() | DirectoryOpenMode::ReadFiles() | DirectoryOpenMode::NoFileSizes(),
    )?;
    while let Some(e) = d.read_next()? {
        if let Ok(name) = e.name.get_str() {
            f(name, e.entry_type);
        }
    }
    Ok(())
}
