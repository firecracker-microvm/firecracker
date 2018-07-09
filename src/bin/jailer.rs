extern crate clap;

extern crate jailer;
extern crate seccomp;

use std::env;

const SECCOMP_ENVVAR: &str = "USE_SECCOMP";

fn main() -> jailer::Result<()> {
    if is_seccomp_enabled() {
        // If the seccomp filters installation fails, it's OK to panic.
        seccomp::setup_seccomp().unwrap();
    }

    jailer::run(jailer::clap_app().get_matches())
}

fn is_seccomp_enabled() -> bool {
    match env::var(SECCOMP_ENVVAR) {
        Ok(_) => true,
        Err(_) => false,
    }
}
