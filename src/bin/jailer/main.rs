use std::env::args;
use std::fs::metadata;
use std::path::Path;
use std::process::exit;

mod env;
use env::Env;

fn print_usage() {
    println!("Usage: jailer [OPTION] ID EXEC-FILE\n");
    println!("Example: jailer 73 /usr/bin/firecracker\n");
    println!("Options:");
    println!("    -h, --help    display this text and exit");
}

struct Args {
    id: String,
    exec_file: String,
}

fn parse_args() -> Args {
    let mut id = String::from("");
    let mut exec_file = String::from("");
    let args: Vec<String> = args().collect();
    for arg in &args[1..] {
        match arg.as_ref() {
            "-h" => {
                print_usage();
                exit(0);
            },
            _ => {
                if id.is_empty() {
                    id = arg.to_string();
                } else if exec_file.is_empty() {
                    exec_file = arg.to_string();
                } else {
                    println!("failed to parse the command line arguments");
                    exit(1);
                }
            },
        }
    }
    Args { id: id, exec_file: exec_file }
}

fn validate_args(args: &Args) {
    if args.id.is_empty() {
        println!("id is missing");
        exit(1);
    }
    if args.exec_file.is_empty() {
        println!("exec-file is missing");
        exit(1);
    }
    let metadata = match metadata(Path::new(&args.exec_file)) {
        Ok(c) => c,
        Err(_) => {
            println!("failed to get the metadata for {}", args.exec_file);
            exit(1);
        },
    };
    if metadata.is_file() == false {
        println!("{} is not a file", args.exec_file);
        exit(1);
    }
}

fn main() {
    let args = parse_args();
    validate_args(&args);
    let env = Env::new(&args.id, &args.exec_file);
    env.run();
    exit(1);
}
