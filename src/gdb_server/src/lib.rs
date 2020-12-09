use std::net::{TcpListener, TcpStream};

pub use arch;
pub use arch::x86_64::regs::setup_sregs;
pub use kernel::loader::elf::{Elf64_Phdr, PT_LOAD};
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

const PORT_NUM: u16 = 8443;

fn wait_for_tcp(port: u16) -> DynResult<TcpStream> {
    let sockaddr = format!("0.0.0.0:{}", port);
    eprintln!("Waiting for a GDB connection on {:?}...", sockaddr);

    let sock = TcpListener::bind(sockaddr)?;
    let (stream, addr) = sock.accept()?;
    eprintln!("Debugger connected from {}", addr);
    Ok(stream)
}

pub fn run_gdb_server(
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
    // Setting this breakpoint guarantees that the first continue command issued
    // by the client will bring the guest at the entry point of the kernel image.
    // This is necessary in the case of IDEs, which automatically issue a continue
    // command when the debugger is started and is useful in the case of CLI, as
    // this initial breakpoint also allows for guest information retrieval (its
    // state) - which is necessary for page walking and breakpoint setting, implicitly.
    if target.insert_bp(entry_addr.0, false).is_err() {
        return Err("GDB server error".into());
    }

    let connection: Box<dyn Connection<Error = std::io::Error>> =
        { Box::new(wait_for_tcp(PORT_NUM)?) };
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
