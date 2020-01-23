# Updating a Block Device

Attached block devices require a PATCH /drives API call when the backing
file's path or size changes, otherwise Firecracker and the running guest will
not be notified of the changes.

Is is important to note that the block device should not be mounted by the
guest at the time of the API call, else the call will silently fail -
no error is returned from either the guest or the host, but the guest might end
up in an inconsistent state.

## Example

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
         }"

# Finish configuring and start the microVM. Wait for the guest to boot.

# Resize the block device's backing file and create a filesystem in it.
truncate --size 100M ${drive_path}
mkfs.ext4 ${ro_drive_path}

# Even though the path has not changed, this triggers a device rescan.
curl --unix-socket ${socket} -i \
     -X PATCH "http://localhost/drives/scratch" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d "{
            \"drive_id\": \"scratch\",
            \"path_on_host\": \"${ro_drive_path}\"
         }"

# Move the backing file.
mv ${ro_drive_path} ${new_ro_drive_path}

# Notify the guest that the path has changed.
curl --unix-socket ${socket} -i \
     -X PATCH "http://localhost/drives/scratch" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d "{
            \"drive_id\": \"scratch\",
            \"path_on_host\": \"${new_ro_drive_path}\"
         }"
```
