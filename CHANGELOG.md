# Changelog

## [0.3.0]

### Added

* Users can interrogate the Machine Configuration (i.e. vcpu count and memory size) using a GET request on /machine-config.
* The logging system can be configured through the API using a PUT on /logger.
* Block devices support live resize by calling PUT with the same parameters as when the block was created.
* Release builds have Link Time Optimization (LTO) enabled.
* Firecracker is built with musl, resulting in a statically linked binary.
* More in-tree integration tests were added as part of the continuous integration system.

### Changed

* The vcpu count is enforced to 1 or an even number.
* The Swagger definition of rate limiters was updated.
* Syslog-enabled logs were replaced with a hostfile backed mechanism.

### Fixed

* The host topology of the CPU and the caches is not leaked into the microvm anymore.
* Boot time was improved by advertising the availability of the TSC deadline timer.
* Fixed an issue which prevented Firecracker from working on 4.14 (or newer) host kernels.
* Specifying the MAC address for an interface through the API is optional.

### Removed

* Removed support for attaching vsock devices.
* Removed support for building Firecracker with glibc.


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
