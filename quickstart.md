
# Firecracker Quickstart

Tested on Amazon Linux 2

## Binary

- Create an `i3.metal` instance usiung Ubuntu
- Download latest Firecracker binary from https://s3.console.aws.amazon.com/s3/object/firecracker.build.us-east-1/firecracker-latest?region=us-east-1&tab=overview#
- Copy binary to EC2 instance: `scp -i <key> ubunutu@<public-ip>`
- Start Firecracker:

  ```
  ssh -i <key> ubuntu@<public-ip>
  sudo su
  rm -f /tmp/firecracker.socket
  ./firecracker-latest
  ```

- Open another terminal to query the VM:

  ```
  curl --unix-socket /tmp/firecracker.socket "http://localhost/machine-config"
  ```


## Source Code (TODO)

- Install Rust: `curl https://sh.rustup.rs -sSf | sh`
- Setup environment vars: `source $HOME/.cargo/env`
- Clone repo: `git clone https://github.com/firecracker-microvm/firecracker`
- Install Rust _musl_ toolchain: `rustup target add x86_64-unknown-linux-musl`
- Build: `cargo build --release`

