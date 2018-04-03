# Firecracker Integration Tests

The test here-in are meant to uphold the security, quality, and performance contracts of Firecracker.

# User Guide

## Running

To run all tests, from `tests/` run:
```
pytest
```

To all tests in one or more directories and/or files, from `tests/` run:
```
pytest relative_dir_or_file_path...
```

## Output
* Output goes to stdout, and stderr.
* `pytest` will exist with the correct return code.

## Example Setup

On an Amazon Linux 2 host:
```
# tests need to run as root, just witch to su
sudo su
export PATH+=":/usr/local/bin/"

# get firecracker
yum install -y git
git clone https://raduweiss:token@github.com/raduweiss/PRIVATE-firecracker.git firecracker

# get rust
curl https://sh.rustup.rs -sSf | sh -s -- -y
source $HOME/.cargo/env

# get python3
yum install -y python3 python3-pip
pip3 install pytest pytest-timeout

# get kcov
# TODO: This should be handled within the coverage test.
yum install -y install gcc gcc-c++ elfutils-libelf-devel libcurl-devel binutils-devel elfutils-devel cmake
cargo kcov --print-install-kcov-sh | sh

# run all tests
cd firecracker/tests
pytest
```

# Goals

* Easily run tests manually on a development/test machine, and in a continous integration environments.
* Each test should be independent, and self-contained, beyond the minimal environment dependencies: `rust`, `python`, `pytest`, and `pytest-timeout`.
* Tests will time out, expect a clean environment, and laeve a clean environment behind.
* Always run with the latest depedencies and resources.

# Implementation

## Choice of Pytest & Dependencies
Pytest was chosen since:
* Python makes it easy to fetch test resources (from clouds) and set up the test environments.
* `pytest` has great test dicovery and for allows simple, function-based tests.
* `pytest` has powerful test fixture support.

## Caveats
* `#[test] fn enable_disable_stdin_test()` from `vmm/src/lib.rs` fails if `pytest` is allowed to record stdin and stdout. Currently this is worked around by running pytest with `--capture=no`, which uglifies the output. A better way would be a bonus (Pytest can have really nice reports!).
* The codebase currently uses an older version of rustfmt than `tests/test_style.py`, so that test will fail.
* The coverage target is currently 0.9, so that test will fail.
* There's an intermittent concurrency issue with kcov on some hosts. This fails: https://github.com/SimonKagstrom/kcov/blob/master/src/engines/ptrace.cc#L145
See `TODO:` comments across `tests/*` for details