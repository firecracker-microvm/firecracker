
# Firecracker Quickstart

This section explains how to quickly get started with Firecracker and create a microVM.

## Download the Binary

Firecracker can run on any machine where `/dev/kvm` is available. This section provide instructions that are specific to Amazon Web Services.

### Use the pre-built binary

- Create an `i3.metal` instance using Ubuntu
- Download latest Firecracker binary from https://s3.console.aws.amazon.com/s3/object/firecracker.build.us-east-1/firecracker-latest?region=us-east-1&tab=overview#
- Copy binary to EC2 instance: `scp -i <key> firecracker-latest ubuntu@<public-ip>:/home/ubuntu`

### Build from the GitHub repo

- Install packages:

  ```
  sudo apt-get update
  sudo apt-get install -y musl-tools
  ```

- Install Rust: `curl https://sh.rustup.rs -sSf | sh`
- Setup environment vars: `source $HOME/.cargo/env`
- Install Rust _musl_ toolchain: `rustup target add x86_64-unknown-linux-musl`
- Clone repo: `git clone https://github.com/firecracker-microvm/firecracker`
- Build: `cargo build --release`

The binary is in `target/x86_64-unknown-linux-musl/release/firecracker`.

## Running Firecracker on Amazon EC2

- Log in to your EC2 instance:

  ```
  ssh -i <key> ubuntu@<public-ip>
  ```

- Set networking capabilities on the Firecracker binary:

  ```
  sudo su
  ```

- Firecracker will refuse to run with a preexisting socket file. This could be a left over from a previous run.

  ```
  rm -f /tmp/firecracker.socket
  ```

- Start Firecracker:

  ```
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
