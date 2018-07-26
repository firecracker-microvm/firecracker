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
# - Do the testrun in a container for better insulation.
# - Add layers to `say` and integrate that with the python logging.
# - Fix the /install-kcov.sh bug.

declare -r ACTIVITY_NAME='Firecracker Testrun'

declare -ra SUPPORTED_PLATFORMS=(Linux)
declare -ra SUPPORTED_PKG_MANAGERS=(apt-get yum)

declare -ra PYTHON_DEPS=( \
     pytest pytest-timeout \
     boto3 \
     requests requests-unixsocket \
     paramiko \
     retry \
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

declare -ra PYTHON_SSH_YUM_DEPS=(python3-devel)
declare -ra PYTHON_SSH_APT_DEPS=(libssl-dev)

declare -ra GCC_STATIC_YUM_DEPS=(glibc-static)
# Some tests will build static binaries for use in systems without user space.

declare -ra EPEL_TOOLS_YUM_DEPS=(iperf3)
declare -ra EPEL_TOOLS_APT_GET_DEPS=(iperf3)
# Miscellaneous dependencies for integration testing purposes.

declare -a GLOBAL_SYMBOLS

main() {
    parse_options "$@"
    # Exports `$OPT_*` per-option variables, and `$NON_OPTION_ARGUMENTS`

    set -- $NON_OPTION_ARGUMENTS
    # `"$@"` is now everything after `'--'` from the initial options.

    if [ $OPT_HELP ]; then
        print_help
        exit
    fi

    ensure_context

    if [ $OPT_QUIET ]; then
        exec 1>/dev/null
    fi

    setup
    say "Starting testrun: pytest $*"
    
    pytest "$@"
    # Run the test runner, `pytest`, passing the non-option arguments.

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

parse_options() {
    ensure \
        getopt -uQ \
            -o hi:p:qr \
            -l help,local-images-path:,pkg-manager:,quiet,use-existing-rust \
        -- "$@"
    # Check if we can read the options into an easy to parse string ...
    declare opt="$(
        getopt -u \
            -o hi:p:qr \
            -l help,local-images-path:,pkg-manager:,quiet,use-existing-rust \
        -- $@
    )"
    # ... and actually parse them.

    set -- $opt
    # Sets $opt as the options string.
    
    while true; do
        case "$1" in
            -h | --help)
                export OPT_HELP=1
                record_global_symbol OPT_HELP
                shift
                ;;
            -q | --quiet)
                export OPT_QUIET=1
                record_global_symbol OPT_QUIET
                shift
                ;;
            -i | --local-images-path)
                export OPT_LOCAL_IMAGES_PATH=$2
                record_global_symbol OPT_LOCAL_IMAGES_PATH
                shift 2
                ;;
            -r | --use-existing-rust)
                export OPT_USE_EXISTING_RUST=1
                record_global_symbol OPT_USE_EXISTING_RUST
                shift
                ;;
            -p | --pkg-manager)
                for pkg_manager in "${SUPPORTED_PKG_MANAGERS[@]}"; do
                    if [ "$2" == "$pkg_manager" ]; then
                        export OPT_PKG_MANAGER=$pkg_manager
                        record_global_symbol OPT_PKG_MANAGER
                    fi
                done

                if [ ! $OPT_PKG_MANAGER ]; then
                    err "[-p | --pkg-manager]: $2 is an invalid choice."
                fi

                shift 2
                ;;
            --)
                shift
                break
                # Everything after `'--'` is now the new option string.
                ;;
            *)
                err "Invalid options. Try running with -h or --help."
                ;;
        esac
    done

    export NON_OPTION_ARGUMENTS="$@"
    record_global_symbol NON_OPTION_ARGUMENTS
    # At this point, `"S@"` is everything originally after `'--'`, or nothing.
}

print_help() {
    declare usage="usage: ./testrun.sh "
    usage+="[-h|--help] | "
    usage+="[ "
        usage+="[-q|--quiet] [-r|--use-existing-rust] "
        usage+="[-i|--local-images-path <path>] "
        usage+="[-p [yum|apt-get] | --pkg-manager [yum|apt-get]] "
        usage+="[-- <pytest argument>...] "
    usage+="]"
    echo $usage
}

ensure_context() {
    ensure_cmd date
    export TIMESTAMP="date"
    # This is used in `say()`, so it will prefix all output with a timestamp.
    record_global_symbol TIMESTAMP

    ensure_platform

    export TIMESTAMP="date --utc --iso-8601=seconds"
    # Once we know we are on a supported platform, we can be more specific in
    # the timestamp format.

    exit_if_in_python_venv
    exit_if_in_rust_tmpenv
    ensure_root
    ensure_cmd getopt
    ensure_cmd curl
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

setup() {
    say "Setup: Starting testrun setup."

    acquire_pkg_manager
    # Will set `$PKG_manager` if successful.

    export TR_TMPDIR=$(ensure mktemp -dt firecracker_testrun_XXXXXXXXXXXXXXXX)
    # The Xs are replaced with entropy.
    record_global_symbol TR_TMPDIR
    say "Setup: Testrun temporary directory is: $TR_TMPDIR"

    ensure_python3
    create_python3_venv
    install_python3_deps

    if [ ! $OPT_USE_EXISTING_RUST ]; then
        create_rust_tmpenv
        install_rust_and_deps
    fi

    ensure_gcc_static

    install_epel_deps

    say "Setup: Successfully set up testrun."
}

acquire_pkg_manager() {
    # Store one and only one supported package manager to `$PKG_MANAGER`.

    export PKG_MANAGER
    record_global_symbol PKG_MANAGER
    declare acquired_pkg_manager=0

    if [ $OPT_PKG_MANAGER ]; then
        ensure_cmd $OPT_PKG_MANAGER
        PKG_MANAGER=$OPT_PKG_MANAGER
        ((acquired_pkg_manager++))
    else
        for pkg_manager in "${SUPPORTED_PKG_MANAGERS[@]}"; do
            if check_cmd $pkg_manager; then
                PKG_MANAGER=$pkg_manager
                ((acquired_pkg_manager++))
            fi
        done
    fi

    if [[ $acquired_pkg_manager -eq 1 ]]; then
        say "Setup: Package manager is: $PKG_MANAGER"
    elif [[ $acquired_pkg_manager -gt 1 ]]; then
        err "Found more supported package managers. Try ./testrun.sh -h."
    else
        err "Could not find a supported package manager."
    fi
}

ensure_python3() {
    check_cmd python3

    if [ $? -ne 0 ]; then
        ensure $PKG_MANAGER install -q -y python3 2>/dev/null
        # This syntax works with all package managers supported so far.
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
    say "Setup: Installing python-devel."
    if [ $PKG_MANAGER == "yum" ]; then
        declare deps="${PYTHON_SSH_YUM_DEPS[@]}"
    elif [ $PKG_MANAGER == "apt-get" ]; then
        # It looks like on Debian and Ubuntu python-devel -static is included by default.
        declare deps="${PYTHON_SSH_APT_DEPS[@]}"
    fi
    ensure $PKG_MANAGER install -q -y $deps >/dev/null 2>&1
    say "Setup: Installed python-devel."

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

    if [ $PKG_MANAGER == "yum" ]; then
        declare deps="${KCOV_YUM_DEPS[@]}"
    elif [ $PKG_MANAGER == "apt-get" ]; then
        declare deps="${KCOV_APT_GET_DEPS[@]}"
    fi    

    ensure $PKG_MANAGER install -q -y $deps >/dev/null 2>&1
    ensure cargo install -f -q cargo-kcov

    declare initial_path="$(pwd)"
    ensure cd $TR_TMPDIR
    ensure cargo kcov --print-install-kcov-sh >install-kcov.sh
    chmod +x install-kcov.sh

    #ensure ./install-kcov.sh
    # TODO: This fails to use $CARGO_HOME somehow, and errors out at the last
    #       line of the script. Fix this! The lines below are a workaround.
    ./install-kcov.sh >/dev/null 2>&1
    ensure cd $TR_TMPDIR/kcov-*/build/
    cp src/kcov src/libkcov_sowrapper.so "${CARGO_HOME:-$HOME/.cargo}/bin"
    ensure cd $initial_path

    say "Setup: Installed Rust coverage tooling."
}

ensure_gcc_static() {
    if [ $PKG_MANAGER == "yum" ]; then
        say "Setup: Installing gcc static build deps."
        declare deps="${GCC_STATIC_YUM_DEPS[@]}"
        ensure $PKG_MANAGER install -q -y $deps >/dev/null 2>&1
        say "Setup: Installed gcc static build deps."
    fi
    # It looks like on Debian and Ubuntu gcc -static is included by default.
}

install_epel_deps() {
    if [ $PKG_MANAGER == "yum" ]; then
        ensure yum-config-manager --enable epel
        declare deps="${EPEL_TOOLS_YUM_DEPS[@]}"
    elif [ $PKG_MANAGER == "apt-get" ]; then
        declare deps="${EPEL_TOOLS_APT_GET_DEPS[@]}"
    fi
    ensure $PKG_MANAGER install -q -y $deps >/dev/null 2>&1
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

    say "Teardown: Testrun torn down."
    destroy_globals
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
        err "Command failed: $@"
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
    echo "[`$TIMESTAMP`] $ACTIVITY_NAME: $1"
}

main "$@"
