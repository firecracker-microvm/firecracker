#!/usr/bin/env bash

# Run this script to do a Firecracker integration testrun. This script sets up
# dependencies in a sandbox, does the testrun, and then tears down the sandbox.
#
# # The Goals of a Testrun
#
# - Ensure that a testrun has all mandatory dependencies available (e.g.,
#   `python`, `pytest`, `cargo`), dependencies that need to be installed at the
#   environment level (e.g., `cargo-kcov`), and dependencies that are common to
#   most tests (e.g., `boto3`, `requests`).
# - Within the filesystem / environment we find ourselves in, make a valiant
#   attempt not to litter.
#
# # Solution
# 
# - Everything that can go in a temporary directory will go in a temporary
#   directory.
# - Use environment variables for state (to benefit form bash dynamic scoping).
# - To cope with system-wide changes, rely on a testing system that has good
#   setup / teardown fixture support (we picked `pytest`).
# - Destroy the temporary directory and all environment variables whenever we
#   are exiting due to some error.
# - All arguments given to this script are passed to the test runner.
#
# # Caveats
# 
# - You need to run this script in the `tests/` dir of the `firecracker` repo.
# - Dependencies installed via the system's package manager (e.g., `python3`)
#   are not uninstalled.
#
# # TODO
#
# - Allow explicit package manager selection via arguments.
# - Command line with help and quiet options for this script.
# - Do the testrun in a container for better insulation.
# - Add layers to `say` and integrate that with the python logging.
# - Add a quiet (=`>dev/null 2>&1`) version to `say`.
# - Fix the /install-kcov.sh bug.

declare -r ACTIVITY_NAME='Firecracker Testrun'

declare -ra SUPPORTED_PLATFORMS=(Linux)
declare -ra SUPPORTED_INSTALLERS=(apt-get yum)

declare -ra PYTHON_DEPS=( \
     pytest pytest-timeout \
     boto3 \
     requests requests-unixsocket \
)

declare -r RUSTUP_URL=https://sh.rustup.rs
declare -ra RUST_DEPS=(cargo-kcov)
declare -ra KCOV_YUM_DEPS=(\
    gcc gcc-c++ cmake \
    elfutils-libelf-devel libcurl-devel binutils-devel elfutils-devel \
)
declare -ra KCOV_APT_GET_DEPS=(\
    gcc g++ cmake \
    binutils-dev libcurl4-openssl-dev zlib1g-dev libdw-dev libiberty-dev \
)

declare -a GLOBAL_SYMBOLS

main() {
    setup

    say "Starting testrun: pytest $@"
    
    pytest "$@"
    # Run the test runner, `pytest`, passing all parameters the script
    # received.

    declare testrun_result="$?"
    if [ $testrun_result -eq 0 ]; then
        say "Successfully completed testrun."
    else
        say "Testrun failed."
    fi

    teardown
    # teardown() has fatal error paths for all failures, so it either exits
    # successfully or not at all.

    return $testrun_result
}

setup() {
    say "Setup: Starting testrun setup."

    exit_if_in_python_venv
    exit_if_in_rust_tmpenv
    ensure_root
    ensure_platform
    ensure_cmd curl

    acquire_pkg_installer
    # Will set `$PKG_INSTALLER` if successful.

    export TR_TMPDIR=$(ensure mktemp -dt firecracker_testrun_XXXXXXXXXXXXXXXX)
    # The Xs are replaced with entropy.
    record_global_symbol TR_TMPDIR
    say "Setup: Testrun temporary directory is: $TR_TMPDIR"

    ensure_python3
    create_python3_venv
    install_python3_deps

    create_rust_tmpenv
    install_rust_and_deps

    say "Setup: Successfully set up testrun."
}

exit_if_in_python_venv() {
    if [ $VIRTUAL_ENV ]; then
        err "Already in a Python virtual environment. See teardown() in $0."
    fi
}

exit_if_in_rust_tmpenv() {
    if [ $RUST_TMPENV ]; then
        err "Already in a Rust temporary environment. See teardown() in $0."
    fi
}

ensure_root() {
    if [[ $EUID -ne 0 ]]; then
        err "$0 must be run as root." 
    fi
}

ensure_platform() {
    declare os="$(uname -s)"
    if [[ ! "${SUPPORTED_PLATFORMS[@]}" =~ $os ]]; then
        err "Unsupported platform: $os. Supported: ${SUPPORTED_PLATFORMS[@]}."
    fi
}

acquire_pkg_installer() {
    # Store one and only one supported package installer to `$PKG_INSTALLER`.
    # TODO: Allow explicit package manager selection via arguments.

    declare acquired_installer=false
    for installer in "${SUPPORTED_INSTALLERS[@]}"; do
        if check_cmd $installer; then
            if $acquired_installer; then
                err "Found more than one supported package manager."
            else
                export PKG_INSTALLER=$installer
                record_global_symbol PKG_INSTALLER
                acquired_installer=true
            fi
        fi
    done

    if $acquired_installer; then
        say "Setup: Package manager is: $PKG_INSTALLER"
    else
        err "Could not find a supported package manager."
    fi
}

ensure_python3() {
    check_cmd python3

    if [ $? -ne 0 ]; then
        ensure $PKG_INSTALLER install -q -y python3 2>/dev/null
        # This syntax works with all installers supported so far.
        say "Setup: Installed python3."
    else
        say "Setup: python3 is present."
    fi
}

create_python3_venv() {
    # Leverages the python built-in virtual environment manager.
    ensure python3 -m venv $TR_TMPDIR/python3_venv --clear --copies
    ensure source $TR_TMPDIR/python3_venv/bin/activate
    say "Setup: Created python3 virtual environment."
}

install_python3_deps() {
    ensure python3 -m pip install -q "${PYTHON_DEPS[@]}"
    say "Setup: Installed python3 dependencies."
}

create_rust_tmpenv() {
    # Rust installs are localized in two directories, and their defaults can
    # be changed by setting `RUSTUP_HOME` and `CARGO_HOME` before installing.

    export RUST_TMPENV="$TR_TMPDIR/rust_tmpenv"
    record_global_symbol RUST_TMPENV
    ensure mkdir $RUST_TMPENV

    export RUSTUP_HOME="$RUST_TMPENV/rustup"
    record_global_symbol RUSTUP_HOME

    export CARGO_HOME="$RUST_TMPENV/cargo"
    record_global_symbol CARGO_HOME
    
    export ORIGINAL_PATH=$PATH 
    record_global_symbol ORIGINAL_PATH
    export PATH="$CARGO_HOME/bin:$PATH"
    # Bash executes the first matching executable found in the PATH dir list,
    # so adding `$CARGO_HOME` to the start of our path works with existing
    # Rust installs. This will be undone during the teardown.

    say "Setup: Created Rust temporary environment."
}

install_rust_and_deps() {
    say "Setup: Installing Rust to: $RUST_TMPENV"

    ensure curl $RUSTUP_URL -sSf | sh -s -- -y --no-modify-path >/dev/null 2>&1
 
    ensure_cmd rustup
    ensure_cmd cargo
    ensure_cmd rustc

    ensure rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1
    # Firecracker is built with this Rust toolchain target.

    say "Setup: Installed Rust."

    say "Setup: Installing Rust coverage tooling."

    if [[ $PKG_INSTALLER == "yum" ]]; then
        declare deps="${KCOV_YUM_DEPS[@]}"
    elif [[ $PKG_INSTALLER == "apt-get" ]]; then
        declare deps="${KCOV_APT_GET_DEPS[@]}"
    fi    

    ensure $PKG_INSTALLER install -q -y $deps >/dev/null 2>&1
    ensure cargo install -f -q cargo-kcov

    declare initial_path="$(pwd)"
    cd $TR_TMPDIR
    ensure cargo kcov --print-install-kcov-sh >install-kcov.sh
    chmod +x install-kcov.sh

    #ensure ./install-kcov.sh
    # TODO: This fails to use $CARGO_HOME somehow, and errors out at the last
    #       line of the script. Fix this! The lines below are a workaround.
    ./install-kcov.sh >/dev/null 2>&1
    cd "$TR_TMPDIR/kcov-34/build/"
    cp src/kcov src/libkcov_sowrapper.so "${CARGO_HOME:-$HOME/.cargo}/bin"
    cd $initial_path

    say "Setup: Installed Rust coverage tooling."
}

teardown() {
    # This is called on any kind of error, so we always try to clean up
    # everything that this script can create.

    say "Teardown: Starting teardown."
    export TEARING_DOWN=true
    record_global_symbol TEARING_DOWN

    if [ $VIRTUAL_ENV ]; then
        ensure deactivate
        say "Teardown: Deactivated python3 virtual environment."
        # `deactivate` is created by the python3 venv activation script.
    fi

    if [ $ORIGINAL_PATH ]; then
        export PATH=$ORIGINAL_PATH
        say "Teardown: Restored PATH to previous state."
    fi

    if [ $TR_TMPDIR ]; then
        ensure rm -rf $TR_TMPDIR
        say "Teardown: Deleted tree: $TR_TMPDIR"
    fi

    destroy_globals

    say "Teardown: Testrun torn down."
}

record_global_symbol() {
    # Keeps track of global symbols it so we can clean them up.
    GLOBAL_SYMBOLS+=( "$1" )
}

destroy_globals() {
    # Unsets the global symbols recorded via `record_global_symbol()`.
    for env_symbol in "${GLOBAL_SYMBOLS[@]}"; do
        unset $env_symbol
    done
}

ensure() {
    # Run a command that should never fail. If the command fails execution will
    # immediately terminate with an error showing the failing command.
    "$@"
    if [ $? != 0 ]; then
        err "Command failed: $*"
    fi
}

ensure_cmd() {
    # Ensures the existence of a command in the current environment. If it does
    # not exist, terminate with an error showing the missing command.
    if ! check_cmd "$1"; then 
        err "Need '$1' (command not found)."
    fi
}

check_cmd() {
    # Returns an error code if a command does not exist.
    command -v "$1" >/dev/null 2>&1
    return $?
}

err() {
    # The error exit path. Will attempt to teardown the sandbox.
    say "ERR: $1" >&2
    if ! [ $TEARING_DOWN ]; then
        teardown
    else
        say "ERR: Teardown unsuccessful. There's litter. Sorry :("
        unset $TEARING_DOWN
    fi
    exit 1
}

say() {
    echo "[$(date --utc --iso-8601=seconds)] $ACTIVITY_NAME: $1"
}

main "$@"
