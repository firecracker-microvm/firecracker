Generating unit test code coverage
===========

## Prerequisites
* LLVM & LCOV. On Ubuntu these can be installed with: sudo apt-get install llvm-3.9 lcov
* Place the <FIRECRACKER_REPO>/scripts/unit_test_coverage/llvm-gcov script in your PATH env var
* Install rustc nightly (which supports the -Z flag)
  * rustup install nightly-2017-10-21

## Generating unit test code coverage for a crate (Manual)
* Go to your crate's directory
* Set the nightly toolchain as default: rustup default nightly-2017-10-21
* Build tests: cargo rustc -- --test -Zprofile -Zno-landing-pads -Ccodegen-units=1 -Clink-dead-code
  * The passed options are:
    * -Zprofile: insert profiling code
    * -Zno-landing-pads: disable panic unwinding, which would otherwise insert code only reachable on panic
    * -Ccodegen-units=1: build everything into one compilation unit
    * -Clink-dead-code: don’t delete unused code at link-time
  * Running the cargo rustc command will generate a *.gcno file.
* Manually run the target/debug/deps/$CRATE-$SUFFIX executable ($SUFFIX is a build hash).
  * Running the executable will generate a *.gcda file. Running an executable several times, say with different arguments, will merge the data from multiple runs.
* Run <FIRECRACKER_REPO>/scripts/unit_test_coverage/llvm-gcov-gen-code-coverage to generate the html files (see target/coverage/index.html for the result)
* Set the stable toolchain as default: rustup default stable

## Generating unit test code coverage for a crate (Automatic)
* Run <FIRECRACKER_REPO>/scripts/unit_test_coverage/gen-code-coverage-for-crate <FIRECRACKER_REPO> <CRATE_REL_DIR_PATH_TO_ROOT>
  * <CRATE_REL_DIR_PATH_TO_ROOT> is the crate relative path to the repo directory
  * The html result will be available in <FIRECRACKER_REPO>/<CRATE_DIR_REL_PATH>/target/coverage/index.html.

## Generating unit test code coverage for all crates (Automatic)
* Run <FIRECRACKER_REPO>/scripts/unit_test_coverage/gen-code-coverage-for-all-crates <FIRECRACKER_REPO>
  * The html result will be available in <CRATE_PATH>/target/coverage/index.html for each crate.
