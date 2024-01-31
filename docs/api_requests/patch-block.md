# Updating block devices after boot

## Updating Virtio block devices after boot

Firecracker offers support to update attached block devices after the microVM
has been started. This is provided via PATCH /drives API which notifies
Firecracker that the underlying block file has been changed on the host. It
should be called when the path to the block device is changed or if the file
size has been modified. It is important to note that external changes to the
block device file do not automatically trigger a notification in Firecracker so
the explicit PATCH API call is mandatory.

### How it works

The implementation of the PATCH /drives API does not modify the host backing
file. It only updates the emulation layer block device properties, path and
length and then triggers a virtio device reconfiguration that is handled by the
guest driver which will update the size of the raw block device. With that being
said, a sequence which performs resizing/altering of the block underlying host
file followed by a PATCH /drives API call is not an atomic operation as the
guest can also modify the block file via emulation during the sequence, if the
raw block device is mounted or accessible.

### Supported use case

This feature was designed to work with a cooperative guest in order to
effectively simulate hot plug/unplug functionality for block devices.

The following guarantees need to be provided:

- guest did not mount the device
- guest does not read or write from the raw block device `/dev/vdX` during the
  update sequence

Example sequence that configures a microVM with a placeholder drive and then
updates it with the real one:

```bash
# Create and set up a block device.
touch ${ro_drive_path}

curl --unix-socket ${socket} -i \
     -X PUT "http://localhost/drives/scratch" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d "{
             \"drive_id\": \"scratch\",
             \"path_on_host\": \"${ro_drive_path}\",
             \"is_root_device\": false,
             \"is_read_only\": true
             \"rate_limiter\": {
                \"bandwidth\": {
                        \"size\": 100000,
                        \"one_time_burst\": 4096,
                        \"refill_time\": 150
                },
                \"ops\": {
                        \"size\": 10,
                        \"refill_time\": 250
                }
            }
         }"
# Finish configuring and start the microVM. Wait for the guest to boot.

# Before mounting the block device in the guest:
# Use another backing file of different size to effectively resize the
# vm block device.
touch ${updated_ro_drive_path}
truncate --size ${new_size}M ${updated_ro_drive_path}
# Create a filesystem in it.
mkfs.ext4 ${updated_ro_drive_path}

# PATCH the block device to use the new backing file.
curl --unix-socket ${socket} -i \
     -X PATCH "http://localhost/drives/scratch" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d "{
             \"drive_id\": \"scratch\",
             \"path_on_host\": \"${updated_ro_drive_path}\"
         }"

# It's now safe to mount the block device in the guest and use it
# with the updated backing file.
```

### Data integrity and other issues

We do not recommend using this feature outside of its supported use case scope.
If the required guarantees are not provided, data integrity and potential other
issues may arise depending on the actual use case. There are two major aspects
that need be considered here:

#### Atomicity of the update sequence

If the guest has the opportunity to perform I/O against the block device during
the update sequence it can either read data while it is changed or can overwrite
data already written by a host process. For example a truncate operation can be
undone if the guest issues a write for the last sector of the raw block device,
or the guest application can become inconsistent or/and can create inconsistency
in the block device itself.

#### In flight I/O requests

If the atomicity of the operation is guaranteed by using methods to make the
microVM quiescence during the update sequence (for example pausing the microVM)
the guest itself or block device can still become incosistent from in flight I/O
requests in the guest that will be executed after it is resumed.

## Updating vhost-user block devices after boot

Unlike with Virtio block device, with vhost-user block devices, Firecracker does
not interact with the underlying block file directly (the vhost-user backend
does). It means that changes to the file are not automatically seen by
Firecracker. There is a mechanism in the
[vhost-user protocol](https://qemu-project.gitlab.io/qemu/interop/vhost-user.html)
for the backend to notify the frontend about changes in the device config via
`VHOST_USER_BACKEND_CONFIG_CHANGE_MSG` message. This requires an extra UDS
socket connection between the frontend and backend used for backend-originated
messages. This mechanism **is not supported** by Firecracker. Instead,
Firecracker makes use of the `PATCH /drives` API request to get notified about
such changes. Such an API request only includes the required property
(`drive_id`), because optional properties are not relevant to vhost-user.

Example of a `PATCH` request for a vhost-user drive:

```bash
curl --unix-socket ${socket} -i \
     -X PATCH "http://localhost/drives/scratch" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d "{
             \"drive_id\": \"scratch\"
         }"
```

A `PATCH` request to a vhost-user drive will make Firecracker retrieve the new
device config from the backend and send a config change notification to the
guest.
