# Changelog

## [0.1.1]

### Changed

* Users can now specify the MAC address of a guest network interface via the PUT network interface API request. Previously, the guest MAC address parameter was ignored.

### Fixed

* Fixed a guest memory allocation issue, which previously led to a potentially significant memory chunk being wasted.
* Fixed an issue which caused compilation problems, due to a compatibility breaking transitive dependency in the tokio suite of crates.


## [0.1.0]

### Added

* One-process virtual machine manager (one Firecracker per microVM).
* RESTful API running on a unix socket. The API supported by v0.1 can be found at `api/swagger/firecracker-v0.1.yaml`.
* Emulated keyboard (i8042) and serial console (UART). The microVM serial console input and output are connected to those of the Firecracker process (this allows direct console access to the guest OS).
* The capability of mapping an existing host tun-tap device as a virtIO/net device into the microVM.
* The capability of mapping an existing host file as a virtIO/block device into the microVM.
* The capability of creating a virtIO/vsock between the host and the microVM.
* Default demand fault paging & CPU oversubscription.