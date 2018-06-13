#[macro_use(crate_version, crate_authors)]
extern crate clap;

extern crate jailer;

use clap::{App, Arg};

use jailer::JailerArgs;

fn main() -> jailer::Result<()> {
    // Initially, the uid and gid params had default values, but it turns out that it's quite
    // easy to shoot yourself in the foot by not setting proper permissions when preparing the
    // contents of the jail, so I think their values should be provided explicitly.
    let cmd_arguments = App::new("firejailer")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Jail a microVM.")
        .arg(
            Arg::with_name("id")
                .long("id")
                .help("Jail ID")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("exec_file")
                .long("exec-file")
                .help("File path to exec into")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("uid")
                .long("uid")
                .help("Chroot uid")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("gid")
                .long("gid")
                .help("Chroot gid")
                .required(true)
                .takes_value(true),
        )
        .get_matches();

    // All arguments are either mandatory, or have default values, so the unwraps should not fail.
    let args = JailerArgs::new(
        cmd_arguments.value_of("id").unwrap(),
        cmd_arguments.value_of("exec_file").unwrap(),
        cmd_arguments.value_of("uid").unwrap(),
        cmd_arguments.value_of("gid").unwrap(),
    )?;

    jailer::run(args)
}
