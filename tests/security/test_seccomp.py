""" Tests that the seccomp filters don't let blacklisted syscalls through. """

from shutil import rmtree
from subprocess import run
from os import getcwd, makedirs, path, remove

import pytest

@pytest.fixture(scope="module")
def tmp_jailer():
    JAILER_SRCDIR = path.normpath(path.join(getcwd(), '../src/bin/demo_jailer/'))
    """ Source directory for a new binary that ingests the `seccomp` crate. """

    JAILER_BIN = path.normpath(path.join(getcwd(), '../target/x86_64-unknown-linux-musl/debug/demo_jailer'))
    """ Name of the mini jailer binary. """

    makedirs(JAILER_SRCDIR)
    with open(path.join(JAILER_SRCDIR, 'main.rs'), 'w') as jailer_src:
        jailer_src.write("""
extern crate seccomp;
use std::env::args;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
fn main() {
    let args: Vec<String> = args().collect();
    let exec_file = &args[1];
    seccomp::setup_seccomp().unwrap();
    Command::new(exec_file).stdin(Stdio::inherit()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).exec();
}
            """)
    yield JAILER_BIN

    rmtree(JAILER_SRCDIR)
    remove(JAILER_BIN)

@pytest.mark.timeout(60)
def test_seccomp_ls(tmp_jailer):
    """
    Asserts that the seccomp filters defined in Firecracker's `seccomp` crate deny a blacklisted syscall.
    """

    JAILED_BIN = '/bin/ls'
    """ Path to the `ls` binary, which attempts to execute `SYS_access`, blacklisted for Firecracker."""

    run(['cargo', 'build', '--bin', 'demo_jailer'])
    assert(path.exists(tmp_jailer))
    """ Compile the mini jailer. """

    outcome = run([tmp_jailer, JAILED_BIN])
    assert(outcome.returncode != 0)
    """ The seccomp filters should send SIGSYS (31) to the binary. `ls` doesn't handle it, so it will exit with error."""
