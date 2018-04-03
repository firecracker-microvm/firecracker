from subprocess import run

import pytest


SUCCESS_CODE = 0


def install_rustfmt_if_needed():
    # rustfmt may not be available yet.
    # grep will return exitcode 1 if rustfmt is not in the component list.
    rustfmt_check = run(
        'rustup component list | grep --silent "rustfmt.*(installed)"',
        shell=True
    )

    if not rustfmt_check.returncode == SUCCESS_CODE:
        # rustfmt-preview is used with the current state of things.
        # See github.com/rust-lang-nursery/rustfmt for information.
        run('rustup component add rustfmt-preview', shell=True, check=True)


@pytest.mark.timeout(120)
def test_style():
    install_rustfmt_if_needed()

    # If there's missbehaving syntax, rustfmt will exit with an error code, and
    # print out the correctin. pytest will handle that.
    run('cargo fmt --all -- --write-mode=diff', shell=True, check=True)
