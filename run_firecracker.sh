# Run in a separate terminal and leave open

API_SOCKET="/tmp/firecracker.socket"
sudo rm -f $API_SOCKET
sudo firecracker --api-sock "${API_SOCKET}"

