extern crate clap;

extern crate jailer;

fn main() -> jailer::Result<()> {
    jailer::run(jailer::clap_app().get_matches())
}
