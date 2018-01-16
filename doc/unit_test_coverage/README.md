How to generate the unit test coverage
===========

This uses the [cargo-kcov](https://github.com/kennytm/cargo-kcov) crate for generating unit test line coverage (but not branch coverage, unfortunately).

## Prerequisites
* Install rustc 1.22.1
  * rustup install 1.22.1
* Install kcov-31 and set the PATH env variable to be able to find kcov
* cargo install cargo-kcov

## Generating unit test code coverage for a crate (Automatic)
* Run <FIRECRACKER_REPO>/scripts/unit_test_coverage/gen-code-coverage <FIRECRACKER_REPO> kcov <CRATE_REL_DIR_PATH_TO_ROOT>
  * <CRATE_REL_DIR_PATH_TO_ROOT> is the crate relative path to the repo directory.
  * The html result will be available in <FIRECRACKER_REPO>/target/cov/report/index.html.

## Generate unit test code coverage for all crates (Automatic)
* Run <FIRECRACKER_REPO>/scripts/unit_test_coverage/gen-code-coverage <FIRECRACKER_REPO> kcov
  * The html result will be available in <REPO_PATH>/target/cov/report/index.html.


# Other coverage methods investigated

## LCOV

This method uses [LLVM](https://llvm.org/) & [LCOV](http://ltp.sourceforge.net/coverage/lcov.php) for generating line & branch coverage.

### Prerequisites
* LLVM & LCOV. On Ubuntu these can be installed with: sudo apt-get install llvm-3.9 lcov
* Place the <FIRECRACKER_REPO>/scripts/unit_test_coverage/llvm-gcov script in your PATH env var
* Install rustc nightly (which supports the -Z flag)
  * rustup install nightly-2017-12-21

### Generating unit test code coverage for a crate (Manual)
* Go to the repo directory
* Set the nightly toolchain as default: rustup default nightly-2017-12-21
* Build tests: cargo rustc -p <CRATE_NAME> -- --test -Zprofile -Zno-landing-pads -Ccodegen-units=1 -Clink-dead-code
  * The passed options are:
    * -Zprofile: insert profiling code
    * -Zno-landing-pads: disable panic unwinding, which would otherwise insert code only reachable on panic
    * -Ccodegen-units=1: build everything into one compilation unit
    * -Clink-dead-code: don’t delete unused code at link-time
  * Running the cargo rustc command will generate a *.gcno file.
* Manually run the target/debug/deps/$CRATE-$SUFFIX executable ($SUFFIX is a build hash).
  * Running the executable will generate a *.gcda file. Running an executable several times, say with different arguments, will merge the data from multiple runs.
* Run <FIRECRACKER_REPO>/scripts/unit_test_coverage/llvm-gcov-gen-code-coverage to generate the html files (see target/cov/report/index.html for the result)
* Set the stable toolchain as default: rustup default stable

### Generating unit test code coverage for a crate (Automatic)
* Run <FIRECRACKER_REPO>/scripts/unit_test_coverage/gen-code-coverage <FIRECRACKER_REPO> lcov <CRATE_REL_DIR_PATH_TO_ROOT>
  * <CRATE_REL_DIR_PATH_TO_ROOT> is the crate relative path to the repo directory.
  * The html result will be available in <FIRECRACKER_REPO>/target/cov/report/index.html.

### Generating unit test code coverage for all crates (Automatic)
* Run <FIRECRACKER_REPO>/scripts/unit_test_coverage/gen-code-coverage <FIRECRACKER_REPO> lcov
  * The html result will be available in <REPO_PATH>/target/cov/report/index.html.

### Why we don't use this option
* Functions not touched by tests are ignored (this method relies on the link-dead-code rustc flag, which doesn't work for nightly-2017-12-21).

## cargo-cov

[cargo-cov](https://github.com/kennytm/cov) utilizes LLVM's gcov-compatible profile generation pass, and it supports both line and branch coverage.

### Prerequisites
* LLVM: On Ubuntu this can be installed with: sudo apt-get install llvm-3.9
* Install rustc nightly (which supports the cargo-cov flags)
  * rustup install nightly-2017-12-21
* cargo install cargo-cov
* cargo install cargo-config

### Generating unit test code coverage for a crate (Automatic)
* Run <FIRECRACKER_REPO>/scripts/unit_test_coverage/gen-code-coverage <FIRECRACKER_REPO> cargo-cov <CRATE_REL_DIR_PATH_TO_ROOT>
  * <CRATE_REL_DIR_PATH_TO_ROOT> is the crate relative path to the repo directory.
  * The html result will be available in <FIRECRACKER_REPO>/target/cov/report/index.html.

### Generate unit test code coverage for all crates (Automatic)
* Run <FIRECRACKER_REPO>/scripts/unit_test_coverage/gen-code-coverage <FIRECRACKER_REPO> cargo-cov
  * The html result will be available in <REPO_PATH>/target/cov/report/index.html.

### Why we don't use this option
* It also computes branch data for test functions. This messes up the overall data (which includes tested functions + test functions).
