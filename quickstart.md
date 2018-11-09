
# Firecracker Quickstart

Tested on Amazon Linux 2

## Binary

- Create an `i3.metal` instance usiung Ubuntu
- Download latest Firecracker binary from https://s3.console.aws.amazon.com/s3/object/firecracker.build.us-east-1/firecracker-latest?region=us-east-1&tab=overview#
- Copy binary to EC2 instance: `scp -i <key> firecracker-latest ubunutu@<public-ip>:/home/ubuntu`
- Start Firecracker:

  ```
  ssh -i <key> ubuntu@<public-ip>
  sudo su
  rm -f /tmp/firecracker.socket
  chmod +x firecracker-latest
  ./firecracker-latest
  ```

- Open another terminal to query the VM:

  ```
  sudo su
  curl --unix-socket /tmp/firecracker.socket "http://localhost/machine-config"
  ```

  It returns the response:

  ```
  { "vcpu_count": 1, "mem_size_mib": 128,  "ht_enabled": false,  "cpu_template": "Uninitialized" }
  ```


## Source Code (TODO)

- Install Rust: `curl https://sh.rustup.rs -sSf | sh`
- Setup environment vars: `source $HOME/.cargo/env`
- Clone repo: `git clone https://github.com/firecracker-microvm/firecracker`
- Install Rust _musl_ toolchain: `rustup target add x86_64-unknown-linux-musl`
- Build: `cargo build --release`

