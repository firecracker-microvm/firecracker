import os
from subprocess import run

"""
The following paths are used by the build tests. The release relative path
is also used in functional/security/performance & other tests.
"""
CARGO_BUILD_REL_PATH = 'firecracker_binaries'
CARGO_RELEASE_REL_PATH = os.path.join(CARGO_BUILD_REL_PATH, "release")

RELEASE_BINARIES_REL_PATH = 'x86_64-unknown-linux-musl/release/'


def cargo_build(path, flags='', extra_args=''):
    cmd = "CARGO_TARGET_DIR={} cargo build {} {}".format(
        path,
        flags,
        extra_args
    )
    run(cmd, shell=True, check=True)
