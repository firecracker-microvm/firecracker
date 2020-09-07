use std::net::{TcpListener, TcpStream};

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

extern crate vm_memory;
pub use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion, ByteValued};

pub use kvm_ioctls::VcpuFd;
pub use kvm_bindings::{kvm_translation, kvm_sregs};

use gdbstub::{Connection, DisconnectReason, GdbStub};

mod target;
use target::*;

pub type DynResult<T> = Result<T, Box<dyn std::error::Error>>;

fn wait_for_tcp(port: u16) -> DynResult<TcpStream> { 
    let sockaddr = format!("127.0.0.1:{}", port);
    eprintln!("Waiting for a GDB connection on {:?}...", sockaddr);

    let sock = TcpListener::bind(sockaddr)?;
    let (stream, addr) = sock.accept()?;
    eprintln!("Debugger connected from {}", addr);
    Ok(stream) 
}

#[cfg(unix)]
fn wait_for_uds(path: &str) -> DynResult<UnixStream> {
    match std::fs::remove_file(path) {
        Ok(_) => {}
        Err(e) => match e.kind() {
            std::io::ErrorKind::NotFound => {}
            _ => return Err(e.into()),
        },
    }

    eprintln!("Waiting for a GDB connection on {}...", path);

    let sock = UnixListener::bind(path)?;
    let (stream, addr) = sock.accept()?;
    eprintln!("Debugger connected from {:?}", addr);

    Ok(stream)
}

pub fn run_gdb_server<'a>(vmm_gm: &'a GuestMemoryMmap, vcpu: &'a VcpuFd) -> DynResult<()> {
    let mut target = FirecrackerGDBServer::new(vmm_gm, vcpu)?;

    let connection: Box<dyn Connection<Error = std::io::Error>> = {
        if std::env::args().nth(1) == Some("--uds".to_string()) {
            #[cfg(not(unix))]
            {
                return Err("Unix Domain Sockets can only be used on Unix".into());
            }
            #[cfg(unix)]
            {
                Box::new(wait_for_uds("/tmp/armv4t_gdb")?)
            }
        } else {
            Box::new(wait_for_tcp(9001)?)
        }
    };
    let mut debugger = GdbStub::new(connection);
    match debugger.run(&mut target)? {
       DisconnectReason::Disconnect => {
            println!("Disconnected from GDB.");
                return Ok(());
       }
       DisconnectReason::TargetHalted => println!("Target halted!"),
       DisconnectReason::Kill => {
           println!("GDB sent a kill command!");
           return Ok(());
       }
    }

    Ok(())
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
