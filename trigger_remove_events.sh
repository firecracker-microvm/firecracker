API_SOCKET="/tmp/firecracker.socket"

sudo curl --unix-socket "${API_SOCKET}" -i     -X PUT 'http://localhost/snapshot/load'     -H  'Accept: application/json'     -H  'Content-Type: application/json'     -d '{
            "snapshot_path": "/tmp/snapshot_file",
            "mem_backend": {
                "backend_path": "/tmp/uffd.socket",
                "backend_type": "Uffd"
            },
            "enable_diff_snapshots": true,
            "resume_vm": true
    }'

# Inflate balloon to trigger remove events
sudo curl --unix-socket "${API_SOCKET}" -i  -X PATCH 'http://localhost/balloon' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d "{
        \"amount_mib\": 20 \
    }"


