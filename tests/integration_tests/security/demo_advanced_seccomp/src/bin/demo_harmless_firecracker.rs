extern crate libc;

fn main() {
    unsafe {
        // Harmless print to standard output.
        libc::syscall(libc::SYS_write, libc::STDOUT_FILENO, "Hello, world!\n", 14);
    }
}
