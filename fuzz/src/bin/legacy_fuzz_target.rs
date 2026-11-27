// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "afl_fuzz")]
#[macro_use]
extern crate afl;

use fuzzer::*;

#[cfg(feature = "afl_fuzz")]
afl_main!(fuzzing::target);

#[cfg(feature = "stdin_fuzz")]
stdin_main!(fuzzing::target);

pub mod fuzzing {
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex};

    #[cfg(target_arch = "aarch64")]
    use vmm::devices::legacy::RTCDevice;
    use vmm::devices::legacy::serial::{RawIOHandler, SerialOut, SerialOutInner};
    use vmm::devices::legacy::{EventFdTrigger, I8042Device, SerialEventsWrapper, SerialWrapper};
    use vmm::devices::virtio::test_utils::InputData;
    use vmm::utils::byte_order;
    use vmm::vstate::bus::Bus;
    use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

    pub fn target(data: &[u8]) {
        const SERIAL_LEN: u64 = 0x8;
        const I8042_LEN: u64 = 0x5;
        // 1 byte for reading the read/write indicator and 8 bytes for the
        // address.
        const DESCRIPTOR_DATA_SIZE: usize = 9;

        let mut data_size = data.len();
        let bus = Bus::new();

        /////////////////Serial Device Setup/////////////////////////
        let interrupt_event = EventFdTrigger::new(EventFd::new(EFD_NONBLOCK).unwrap());

        let serial = SerialWrapper {
            serial: vm_superio::Serial::with_events(
                interrupt_event.try_clone().unwrap(),
                SerialEventsWrapper {
                    buffer_ready_event_fd: Some(EventFdTrigger::new(
                        EventFd::new(EFD_NONBLOCK).unwrap(),
                    )),
                },
                SerialOut::new(SerialOutInner::Sink, None),
            ),
            input: Some(std::io::stdin()),
        };

        let address_serial = 0x0;
        let device_serial = Arc::new(Mutex::new(serial));
        bus.insert(device_serial.clone(), address_serial, SERIAL_LEN)
            .unwrap();

        /////////////////Keyboard Device Setup/////////////////////////
        let i8042 = I8042Device::new(EventFd::new(libc::EFD_NONBLOCK).unwrap()).unwrap();
        let address_keyboard = address_serial + SERIAL_LEN;
        let device_keyboard = Arc::new(Mutex::new(i8042));
        bus.insert(device_keyboard.clone(), address_keyboard, I8042_LEN)
            .unwrap();

        /////////////////Real Time Clock PL031 Setup/////////////////////////
        // we do not fuzz on aarch64 yet.
        #[cfg(target_arch = "aarch64")]
        {
            const RTC_LEN: u64 = 0x1000;
            let address_pl031 = address_keyboard + RTC_LEN;
            let device_pl031 = Arc::new(Mutex::new(RTCDevice::new()));
            bus.insert(device_pl031, address_pl031, RTC_LEN).unwrap();
        }

        let input = InputData {
            data: data.to_vec(),
            read_pos: AtomicUsize::new(0),
        };

        loop {
            if data_size < DESCRIPTOR_DATA_SIZE {
                break;
            }

            let read_write = input.get_slice(1);
            let address = byte_order::read_le_u64(input.get_slice(8));

            data_size -= DESCRIPTOR_DATA_SIZE;

            if read_write.first().unwrap() % 2 == 0 {
                let _ = bus.read(address, &mut [0]);
            } else {
                if data_size < 1 {
                    break;
                }
                let data = input.get_slice(1);
                let _ = bus.write(address, data);
                data_size -= 1;
            }
        }

        // Exercise serial raw_input (host→guest data path) with any remaining bytes.
        // This covers the FIFO enqueue path and interrupt triggering.
        {
            let mut serial = device_serial.lock().unwrap();
            let _ = serial.serial.raw_input(&[b'A', b'B', b'C']);
        }
    }
}

#[cfg(test)]
mod seed_gen {
    use std::fs::OpenOptions;
    use std::io::Write;

    // Device layout: serial at 0x0 (8 bytes), i8042 at 0x8 (5 bytes)
    const SERIAL_BASE: u64 = 0x0;
    const I8042_BASE: u64 = 0x8;

    fn write_seed(name: &str, data: &[u8]) {
        let _ = std::fs::create_dir_all("in/legacy");
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(format!("in/legacy/{name}"))
            .unwrap()
            .write_all(data)
            .unwrap();
    }

    fn bus_read(addr: u64) -> Vec<u8> {
        let mut v = vec![0x00]; // even = read
        v.extend_from_slice(&addr.to_le_bytes());
        v
    }

    fn bus_write(addr: u64, val: u8) -> Vec<u8> {
        let mut v = vec![0x01]; // odd = write
        v.extend_from_slice(&addr.to_le_bytes());
        v.push(val);
        v
    }

    /// Exercise all 8 serial registers with reads and writes.
    /// Covers: THR/RBR, IER, IIR/FCR, LCR, MCR, LSR, MSR, SCR
    #[test]
    fn generate_serial_registers_seed() {
        let mut seed = Vec::new();

        // Read all 8 serial registers (offsets 0-7)
        for offset in 0..8u64 {
            seed.extend_from_slice(&bus_read(SERIAL_BASE + offset));
        }

        // Write to writable registers
        seed.extend_from_slice(&bus_write(SERIAL_BASE + 0, b'A')); // THR
        seed.extend_from_slice(&bus_write(SERIAL_BASE + 1, 0x0F)); // IER: enable all interrupts
        seed.extend_from_slice(&bus_write(SERIAL_BASE + 2, 0xC7)); // FCR: enable FIFO, clear, 14-byte trigger
        seed.extend_from_slice(&bus_write(SERIAL_BASE + 3, 0x03)); // LCR: 8N1
        seed.extend_from_slice(&bus_write(SERIAL_BASE + 4, 0x0B)); // MCR: DTR, RTS, OUT2
        seed.extend_from_slice(&bus_write(SERIAL_BASE + 7, 0xAA)); // SCR: scratch register

        write_seed("serial_regs.in", &seed);
    }

    /// DLAB sequence: set divisor latch to configure baud rate.
    /// Covers LCR DLAB bit, divisor low/high via offsets 0/1 when DLAB=1.
    #[test]
    fn generate_serial_dlab_seed() {
        let mut seed = Vec::new();

        // Set DLAB bit (bit 7 of LCR at offset 3)
        seed.extend_from_slice(&bus_write(SERIAL_BASE + 3, 0x80));
        // Write divisor low byte (offset 0 when DLAB=1)
        seed.extend_from_slice(&bus_write(SERIAL_BASE + 0, 0x0C)); // 9600 baud low
        // Write divisor high byte (offset 1 when DLAB=1)
        seed.extend_from_slice(&bus_write(SERIAL_BASE + 1, 0x00)); // 9600 baud high
        // Read back divisor
        seed.extend_from_slice(&bus_read(SERIAL_BASE + 0));
        seed.extend_from_slice(&bus_read(SERIAL_BASE + 1));
        // Clear DLAB
        seed.extend_from_slice(&bus_write(SERIAL_BASE + 3, 0x03)); // 8N1

        // Now write data with DLAB cleared
        seed.extend_from_slice(&bus_write(SERIAL_BASE + 0, b'H'));
        seed.extend_from_slice(&bus_write(SERIAL_BASE + 0, b'i'));
        // Read IIR to check interrupt status
        seed.extend_from_slice(&bus_read(SERIAL_BASE + 2));
        // Read LSR to check TX empty
        seed.extend_from_slice(&bus_read(SERIAL_BASE + 5));

        write_seed("serial_dlab.in", &seed);
    }

    /// i8042 commands: exercise all command paths in the keyboard controller.
    #[test]
    fn generate_i8042_commands_seed() {
        let mut seed = Vec::new();

        // Read status register
        seed.extend_from_slice(&bus_read(I8042_BASE + 4));
        // Read data port (empty buffer → 0)
        seed.extend_from_slice(&bus_read(I8042_BASE + 0));

        // CMD_READ_CTR (0x20): read controller configuration byte
        seed.extend_from_slice(&bus_write(I8042_BASE + 4, 0x20));
        seed.extend_from_slice(&bus_read(I8042_BASE + 0)); // read result

        // CMD_WRITE_CTR (0x60): write controller configuration byte
        seed.extend_from_slice(&bus_write(I8042_BASE + 4, 0x60));
        seed.extend_from_slice(&bus_write(I8042_BASE + 0, 0x47)); // new config byte

        // CMD_READ_OUTP (0xD0): read output port
        seed.extend_from_slice(&bus_write(I8042_BASE + 4, 0xD0));
        seed.extend_from_slice(&bus_read(I8042_BASE + 0)); // read the output port value

        // CMD_WRITE_OUTP (0xD1): write output port
        seed.extend_from_slice(&bus_write(I8042_BASE + 4, 0xD1));
        seed.extend_from_slice(&bus_write(I8042_BASE + 0, 0xFF)); // output port value

        // CMD_RESET_CPU (0xFE): trigger CPU reset
        seed.extend_from_slice(&bus_write(I8042_BASE + 4, 0xFE));

        // Unknown command to exercise default path
        seed.extend_from_slice(&bus_write(I8042_BASE + 4, 0xFF));

        // Read status and data after commands
        seed.extend_from_slice(&bus_read(I8042_BASE + 4));
        seed.extend_from_slice(&bus_read(I8042_BASE + 0));

        write_seed("i8042_cmds.in", &seed);
    }

    /// Original seed preserved for backwards compatibility
    #[test]
    fn create_in_file() {
        let mut seed = Vec::new();

        seed.extend_from_slice(&bus_read(SERIAL_BASE + 0));
        seed.extend_from_slice(&bus_write(SERIAL_BASE + 1, 0x01));
        seed.extend_from_slice(&bus_read(I8042_BASE + 0));
        seed.extend_from_slice(&bus_write(I8042_BASE + 4, 0x20));
        seed.extend_from_slice(&bus_write(I8042_BASE + 4, 0x60));

        write_seed("ex1.in", &seed);
    }
}
