// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem::zeroed;
use std::io::StdinLock;
use std::os::unix::io::RawFd;

use libc::{fcntl, tcgetattr, tcsetattr, isatty, read, c_int, termios, STDIN_FILENO, TCSANOW,
           ICANON, ECHO, ISIG, O_NONBLOCK, F_GETFL, F_SETFL};

use {Result, errno_result};

fn modify_mode<F: FnOnce(&mut termios)>(fd: RawFd, f: F) -> Result<()> {
    // Safe because we check the return value of isatty.
    if unsafe { isatty(fd) } != 1 {
        return Ok(());
    }

    // The following pair are safe because termios gets totally overwritten by tcgetattr and we
    // check the return result.
    let mut termios: termios = unsafe { zeroed() };
    let ret = unsafe { tcgetattr(fd, &mut termios as *mut _) };
    if ret < 0 {
        return errno_result();
    }
    let mut new_termios = termios;
    f(&mut new_termios);
    // Safe because the syscall will only read the extent of termios and we check the return result.
    let ret = unsafe { tcsetattr(fd, TCSANOW, &new_termios as *const _) };
    if ret < 0 {
        return errno_result();
    }

    Ok(())
}

fn get_flags(fd: RawFd) -> Result<c_int> {
    // Safe because no third parameter is expected and we check the return result.
    let ret = unsafe { fcntl(fd, F_GETFL) };
    if ret < 0 {
        return errno_result();
    }
    Ok(ret)
}


fn set_flags(fd: RawFd, flags: c_int) -> Result<()> {
    // Safe because we supply the third parameter and we check the return result.
    let ret = unsafe { fcntl(fd, F_SETFL, flags) };
    if ret < 0 {
        return errno_result();
    }
    Ok(())
}

/// Trait for file descriptors that are TTYs, according to `isatty(3)`.
///
/// This is marked unsafe because the implementation must promise that the returned RawFd is a valid
/// fd and that the lifetime of the returned fd is at least that of the trait object.
pub unsafe trait Terminal {
    /// Gets the file descriptor of the TTY.
    fn tty_fd(&self) -> RawFd;

    /// Set this terminal's mode to canonical mode (`ICANON | ECHO | ISIG`).
    fn set_canon_mode(&self) -> Result<()> {
        modify_mode(self.tty_fd(), |t| t.c_lflag |= ICANON | ECHO | ISIG)
    }

    /// Set this terminal's mode to raw mode (`!(ICANON | ECHO | ISIG)`).
    fn set_raw_mode(&self) -> Result<()> {
        modify_mode(self.tty_fd(), |t| t.c_lflag &= !(ICANON | ECHO | ISIG))
    }

    /// Sets the non-blocking mode of this terminal's file descriptor.
    ///
    /// If `non_block` is `true`, then `read_raw` will not block. If `non_block` is `false`, then
    /// `read_raw` may block if there is nothing to read.
    fn set_non_block(&self, non_block: bool) -> Result<()> {
        let old_flags = get_flags(self.tty_fd())?;
        let new_flags = if non_block {
            old_flags | O_NONBLOCK
        } else {
            old_flags & !O_NONBLOCK
        };
        if new_flags != old_flags {
            set_flags(self.tty_fd(), new_flags)?
        }
        Ok(())
    }

    /// Reads up to `out.len()` bytes from this terminal without any buffering.
    ///
    /// This may block, depending on if non-blocking was enabled with `set_non_block` or if there
    /// are any bytes to read. If there is at least one byte that is readable, this will not block.
    fn read_raw(&self, out: &mut [u8]) -> Result<usize> {
        // Safe because read will only modify the pointer up to the length we give it and we check
        // the return result.
        let ret = unsafe { read(self.tty_fd(), out.as_mut_ptr() as *mut _, out.len()) };
        if ret < 0 {
            return errno_result();
        }

        Ok(ret as usize)
    }
}

// Safe because we return a genuine terminal fd that never changes and shares our lifetime.
unsafe impl<'a> Terminal for StdinLock<'a> {
    fn tty_fd(&self) -> RawFd {
        STDIN_FILENO
    }
}

// Safe because we return a genuine pollable fd that never changes and shares our lifetime.
unsafe impl<T: Terminal> ::Pollable for T {
    fn pollable_fd(&self) -> RawFd {
        self.tty_fd()
    }
}
