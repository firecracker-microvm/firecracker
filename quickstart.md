
# Firecracker Quickstart

## Get the Binary

### Using the pre-built binary

- Create an `i3.metal` instance usiung Ubuntu
- Download latest Firecracker binary from https://s3.console.aws.amazon.com/s3/object/firecracker.build.us-east-1/firecracker-latest?region=us-east-1&tab=overview#
- Copy binary to EC2 instance: `scp -i <key> firecracker-latest ubunutu@<public-ip>:/home/ubuntu`

### From the GitHub repo

- Install Rust: `curl https://sh.rustup.rs -sSf | sh¸`
- Setup environment vars: `source $HOME/.cargo/env`
- Clone repo: `git clone https://github.com/firecracker-microvm/firecracker`
- Install Rust _musl_ toolchain: `rustup target add x86_64-unknown-linux-musl`
- Install packages:

  ```
  sudo apt-get update
  sudo apt-get install -y gcc g++ cmake jq binutils-dev libcurl4-openssl-dev zlib1g-dev libdw-dev libiberty-dev musl-tools
  ```

- Build: `cargo build --release`

The binary is in `target/x86_64-unknown-linux-musl/release/firecracker`.

## Create a microVM

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
