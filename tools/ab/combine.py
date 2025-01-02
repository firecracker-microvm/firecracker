import argparse
import json
import os
from pathlib import Path

parser = argparse.ArgumentParser(
    description="Combine A/B test fails into groups per test type"
)
parser.add_argument(
    "path",
    help="Path to the directory with failed A/B runs",
    type=Path,
)
args = parser.parse_args()

BLOCK = "test_block_performance"
NET_THROUGHPUT = "test_network_throughput"
NET_LATENCY = "test_network_latency"

block_data = []
net_data = []
net_lat_data = []
for d in os.walk(args.path):
    if "ab.json" in d[-1]:
        path = d[0] + "/ab.json"
        print(path)
        with open(path, "r+") as f:
            lines = f.read()
            j = '{"data":' + lines + "}"
            data = json.loads(j)
            for e in data["data"]:
                match e["performance_test"]:
                    case BLOCk:
                        block_data.append(e)
                    case NET_THROUGHPUT:
                        net_data.append(e)
                    case NET_LATENCY:
                        net_lat_data.append(e)

with open(f"{NET_LATENCY}.json", "w") as f:
    json.dump({"results": net_lat_data}, f, indent=2, sort_keys=True)
with open(f"{NET_THROUGHPUT}.json", "w") as f:
    json.dump({"results": net_data}, f, indent=2, sort_keys=True)
with open(f"{BLOCK}.json", "w") as f:
    json.dump({"fails": block_data}, f, indent=2, sort_keys=True)
