#[macro_use(crate_version, crate_authors)]
extern crate clap;

use clap::{App, Arg};

fn main() {
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
}
