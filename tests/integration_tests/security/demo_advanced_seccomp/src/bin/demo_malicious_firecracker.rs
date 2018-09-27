extern crate libc;

fn main() {
    unsafe {
        // In this example, the malicious component is outputing to standard input.
        libc::syscall(libc::SYS_write, libc::STDIN_FILENO, "Hello, world!\n", 14);
    }
}
