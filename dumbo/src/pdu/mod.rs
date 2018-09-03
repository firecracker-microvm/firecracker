//! A module for interpreting byte slices as `PDU`s.
//!
//! PDU stands for protocol data unit, and represents data transmitted as a single unit during
//! communication using a specific protocol. Ethernet frames, IP packets, and TCP segments are all
//! example of protocol data units.

pub mod bytes;
