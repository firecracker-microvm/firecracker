extern crate cc;

fn main() {
    cc::Build::new()
        .compiler("gcc")
        .flag("-nostdlib")
        .flag("-nodefaultlibs")
        .file("src/cpuid/host_cpuid.c")
        .compile("x86_64_c");
}
