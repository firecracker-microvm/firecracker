use std::net::{TcpListener, TcpStream};

pub use std::sync::mpsc::{Receiver, Sender};
pub use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion, ByteValued};
pub use kvm_ioctls::VcpuFd;
pub use kvm_bindings;
pub use kernel::loader::{Elf64_Phdr, PT_LOAD};

use gdbstub::{Connection, DisconnectReason, GdbStub, ResumeAction};
pub use gdbstub::GdbStubError;

extern crate vm_memory;

mod target;
mod util;

use target::*;
pub use util::*;

pub type DynResult<T> = Result<T, Box<dyn std::error::Error>>;

fn wait_for_tcp(port: u16) -> DynResult<TcpStream> { 
    let sockaddr = format!("127.0.0.1:{}", port);
    eprintln!("Waiting for a GDB connection on {:?}...", sockaddr);

    let sock = TcpListener::bind(sockaddr)?;
    let (stream, addr) = sock.accept()?;
    eprintln!("Debugger connected from {}", addr);
    Ok(stream) 
}

pub fn run_gdb_server<'a>(vmm_gm: GuestMemoryMmap, entry_addr: GuestAddress, e_phdrs: Vec<Elf64_Phdr>,
                     vcpu_event_receiver: Receiver<DebugEvent>, vcpu_event_sender: Sender<DebugEvent>) -> DynResult<()> {
    let mut target = FirecrackerGDBServer::new(vmm_gm,
        vcpu_event_receiver, vcpu_event_sender, e_phdrs)?;

    if target.insert_bp(entry_addr.0).is_err() {
        return Err("GDB server error".into());
    }

    // This signals the main thread it is ok to start the vcpus
    if target.vcpu_event_sender.send(DebugEvent::START).is_err() {
        return Err("GDB server - main thread communication error".into());
    }
    // Guarantees that the vcpus are in a waiting state at the entry point of the kernel
    if target.vcpu_event_receiver.recv().is_err() {
        return Err("GDB server - main thread communication error".into());
    }

    if target.remove_bp(entry_addr.0).is_err() {
        return Err("GDB server error".into());
    }

    // Retrieving the guest state. We will not be doing this again until
    // after the first continue/single-step
    if target.vcpu_event_sender.send(DebugEvent::GET_REGS).is_err() {
        return Err("GDB server - main thread communication error".into());
    }
    if let Ok(DebugEvent::PEEK_REGS(state)) = target.vcpu_event_receiver.recv() {
        target.guest_state = state;
    } else {
        return Err("GDB server - main thread communication error".into());
    }

    let connection: Box<dyn Connection<Error = std::io::Error>> = {
            Box::new(wait_for_tcp(9001)?)
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

