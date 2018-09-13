extern crate chrono;
extern crate clap;

extern crate jailer;

fn main() -> jailer::Result<()> {
    jailer::run(
        jailer::clap_app().get_matches(),
        chrono::Utc::now().timestamp_millis() as u64,
    )
}
