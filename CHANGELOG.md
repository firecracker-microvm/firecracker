# Changelog

## [0.2.0]

### Added

* Users can now interrogate Instance Information (currently just instance state) through the API.

### Changed

* Renamed `api/swagger/all.yaml` to `api/swagger/firecracker-v1.0.yaml` which specifies targeted API support for Firecracker v1.0.
* Renamed `api/swagger/firecracker-v0.1.yaml` to `api/swagger/firecracker-beta.yaml` which specifies the currently supported API.
* Users can now enforce that an emulated block device is read-only via the API. To specify whether a block device is read-only or read-write, an extra "permissions" field was added to the Drive definition in the API. The root filesystem is automatically mounted in the guest OS as ro/rw according to the specified "permissions". It's the responsibility of the user to mount any other read-only block device as such within the guest OS.
* Users can now stop the guest VM using the API. Actions of type 'InstanceHalt' are now supported via the API.

### Fixed

* Added support for getDeviceID() in virtIO-block. Without this, the guest Linux kernel would complain at boot time that the operation is unsupported.
* STDIN control is returned to the Firecracker process when guest VM is inactive. Raw mode STDIN is forwarded to the guest OS when guest VM is running.

### Removed

* Removed `api/swagger/actions.yaml`.
* Removed `api/swagger/devices.yaml`.
* Removed `api/swagger/firecracker-mvp.yaml`.
* Removed `api/swagger/limiters.yaml`.


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
