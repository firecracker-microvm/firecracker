use std::net::{TcpListener, TcpStream};

pub use arch;
pub use kernel::loader::{Elf64_Phdr, PT_LOAD};
pub use kvm_bindings;
pub use kvm_ioctls::VcpuFd;
pub use std::sync::mpsc::{Receiver, Sender};
pub use vm_memory::{
    ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion,
};

pub use gdbstub::GdbStubError;
use gdbstub::{Connection, DisconnectReason, GdbStub, ResumeAction};

extern crate vm_memory;

mod target;
mod util;

use target::*;
pub use util::*;

pub type DynResult<T> = Result<T, Box<dyn std::error::Error>>;

fn wait_for_tcp(port: u16) -> DynResult<TcpStream> {
    let sockaddr = format!("0.0.0.0:{}", port);
    eprintln!("Waiting for a GDB connection on {:?}...", sockaddr);

    let sock = TcpListener::bind(sockaddr)?;
    let (stream, addr) = sock.accept()?;
    eprintln!("Debugger connected from {}", addr);
    Ok(stream)
}

pub fn run_gdb_server<'a>(
    vmm_gm: GuestMemoryMmap,
    entry_addr: GuestAddress,
    e_phdrs: Vec<Elf64_Phdr>,
    vcpu_event_receiver: Receiver<DebugEvent>,
    vcpu_event_sender: Sender<DebugEvent>,
) -> DynResult<()> {
    let mut target = FirecrackerGDBServer::new(
        vmm_gm,
        vcpu_event_receiver,
        vcpu_event_sender,
        e_phdrs,
        entry_addr,
    )?;

    if target.insert_bp(entry_addr.0, false).is_err() {
        return Err("GDB server error".into());
    }

    let connection: Box<dyn Connection<Error = std::io::Error>> = { Box::new(wait_for_tcp(8443)?) };
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
