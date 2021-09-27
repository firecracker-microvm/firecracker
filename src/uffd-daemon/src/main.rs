use std::io::prelude::*;
use std::io::Write;
use std::os::unix::net::UnixStream;
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

fn firecracker_api_call(sock: &mut UnixStream, method_and_uri: &str, body: &str) {
    let request = format!(
        "{} HTTP/1.1\r\n\
         Content-Length: {}\r\n\
         Content-Type: application/json\r\n\r\n\
         {}",
        method_and_uri,
        body.len(),
        body
    );
    println!("API request:\n{}", request);
    sock.write_all(request.as_bytes()).unwrap();

    let mut response = vec![0u8; 1024];
    let (bytes_read, file) = sock.recv_with_fd(&mut response[..]).unwrap();
    let passed_fd = file.is_some();
    println!(
        "API response with {} bytes and {} FD:\n{}",
        bytes_read,
        passed_fd,
        String::from_utf8(response).unwrap()
    );

    // if let Some(mut file) = file {
    //     let mut contents = String::new();
    //     file.read_to_string(&mut contents)
    //         .expect("could not read file");
    //     println!("Passed FD contents: {}", contents);
    // }
}

fn main() {
    println!("Connecting to Firecracker API.");

    let path_to_socket = "/tmp/firecracker-sb0.sock";
    let mut socket = UnixStream::connect(path_to_socket).expect("cannot connect");

    firecracker_api_call(
        &mut socket,
        "PUT /snapshot/load",
        "{\"snapshot_path\":\"foo.image\",\"mem_file_path\":\"foo.mem\"}",
    );

    firecracker_api_call(&mut socket, "PATCH /vm", "{\"state\":\"Resumed\"}");
}
