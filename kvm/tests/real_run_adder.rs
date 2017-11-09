// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(any(target_arch = "x86", target_arch = "x86_64"))]

extern crate sys_util;
extern crate kvm_sys;
extern crate kvm;

use kvm::*;
use kvm_sys::kvm_regs;
use sys_util::{GuestAddress, GuestMemory};

#[test]
fn test_run() {
    // This example based on https://lwn.net/Articles/658511/
    let code = [
        0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
        0x00, 0xd8,       /* add %bl, %al */
        0x04, '0' as u8,  /* add $'0', %al */
        0xee,             /* out %al, (%dx) */
        0xb0, '\n' as u8, /* mov $'\n', %al */
        0xee,             /* out %al, (%dx) */
        0x2e, 0xc6, 0x06, 0xf1, 0x10, 0x13, /* movb $0x13, %cs:0xf1 */
        0xf4,             /* hlt */
    ];

    let mem_size = 0x1000;
    let load_addr = GuestAddress(0x1000);
    let mem = GuestMemory::new(&vec![(load_addr, mem_size)]).unwrap();

    let kvm = Kvm::new().expect("new kvm failed");
    let vm = Vm::new(&kvm, mem).expect("new vm failed");
    let vcpu = Vcpu::new(0, &kvm, &vm).expect("new vcpu failed");

    vm.get_memory()
        .write_slice_at_addr(&code, load_addr)
        .expect("Writing code to memory failed.");

    let mut vcpu_sregs = vcpu.get_sregs().expect("get sregs failed");
    assert_ne!(vcpu_sregs.cs.base, 0);
    assert_ne!(vcpu_sregs.cs.selector, 0);
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;
    vcpu.set_sregs(&vcpu_sregs).expect("set sregs failed");

    let mut vcpu_regs: kvm_regs = unsafe { std::mem::zeroed() };
    vcpu_regs.rip = 0x1000;
    vcpu_regs.rax = 2;
    vcpu_regs.rbx = 7;
    vcpu_regs.rflags = 2;
    vcpu.set_regs(&vcpu_regs).expect("set regs failed");

    let mut out = String::new();
    loop {
        match vcpu.run().expect("run failed") {
            VcpuExit::IoOut(0x3f8, data) => {
                assert_eq!(data.len(), 1);
                out.push(data[0] as char);
            },
            VcpuExit::Hlt => break,
            r => panic!("unexpected exit reason: {:?}", r),
        }
    }

    assert_eq!(out, "9\n");
    let result: u8 =
        vm.get_memory()
            .read_obj_from_addr(load_addr.checked_add(0xf1).unwrap())
            .expect("Error reading the result.");
    assert_eq!(result, 0x13);
}
