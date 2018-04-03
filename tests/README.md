# Firecracker Integration Tests

The test herein are meant to uphold the security, quality, and performance contracts of Firecracker.

## User Guide

### Running

To run all tests, from `tests/` run:

``` sh
pytest
```

To run all tests in one or more directories and/or files, from `tests/` run:

``` sh
pytest dir_or_file_path...
```

### Output

* Output goes to stdout, and stderr.
* `pytest` will exit with the correct return code.

### Dependencies

Tests are expected to handle their own dependencies, but have these basic requirements:

* A bare-metal host, root access, and `uname -r` >= 4.9.
* The latest version of [Rust's stable channel](https://github.com/rust-lang-nursery/rustup.rs#keeping-rust-up-to-date).
* `python3 --version` >= 3.5, and `pip3 --version` >= 9
* `pytest --version` >= 3.5, with `pytest-timeout-1.2.1` or newer
* Currently, distro-specific [kcov dependencies](https://github.com/SimonKagstrom/kcov) should also be provided.

### Example

Running on an Amazon Linux 2 host:

``` sh
# tests need to run as root, just switch to su
sudo su
export PATH+=":/usr/local/bin/"

# get firecracker
yum install -y git
git clone https://user:token@github.com/aws/PRIVATE-firecracker.git firecracker

# get rust
curl https://sh.rustup.rs -sSf | sh -s -- -y
source $HOME/.cargo/env

# get python3
yum install -y python3 python3-pip
pip3 install pytest pytest-timeout

# get kcov dependencies (the test will install cargo-kcov and kcov).
# TODO: This should be handled within the coverage test.
yum install -y install gcc gcc-c++ elfutils-libelf-devel libcurl-devel binutils-devel elfutils-devel cmake

# run all tests
cd firecracker/tests
pytest
```

## Goals

* Easily run tests manually on a development/test machine, and in a continuos integration environments.
* Each test should be independent, and self-contained, beyond the minimal environment dependencies.
* Tests will time out, expect a clean environment, and leave a clean environment behind.
* Always run with the latest dependencies and resources.

## Implementation

### Choice of Pytest & Dependencies

Pytest was chosen since:

* Python makes it easy to fetch test resources (from clouds) and set up the test environments.
* `pytest` has great test discovery and allows for simple, function-based tests.
* `pytest` has powerful test fixture support.

### Caveats

* `#[test] fn enable_disable_stdin_test()` from `vmm/src/lib.rs` fails if `pytest` is allowed to record stdin and stdout. Currently this is worked around by running pytest with `--capture=no`, which uglifies the output. A better way would be a bonus (Pytest can have really nice reports!).
* The coverage target is currently 0.9, so that test will fail. Once these tests are run as a result of PRs and merges, we need to set the target accordingly.
* `test_coverage` needs to do a distro-dependent `kcov` dependency installation. Currently, this is not done (and for it to work, you need to install kcov separately).
* Currently, `test_coverage` fails if run on more than 64 CPUs. As a workaround, run `taskset --cpu-list 0-63`.

See "`TODO:`" comments across `tests/*` for details.
