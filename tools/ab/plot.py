import argparse
import json
import os
from enum import Enum

import matplotlib.pyplot as plt
import numpy as np

plt.style.use("dark_background")


def clamp(min_v, max_v, v):
    return max(min_v, min(max_v, v))


def lerp(color_a, color_b, t):
    return (
        clamp(0.0, 1.0, abs(color_a[0] * (1.0 - t) + color_b[0] * t)),
        clamp(0.0, 1.0, abs(color_a[1] * (1.0 - t) + color_b[1] * t)),
        clamp(0.0, 1.0, abs(color_a[2] * (1.0 - t) + color_b[2] * t)),
    )


GREY = (0.5, 0.5, 0.5)
GREEN = (0.1, 0.8, 0.1)
RED = (0.8, 0.0, 0.1)

POSITIVE_COLOR = GREEN
NEGATIVE_COLOR = RED


class DataType(Enum):
    Block = "block"
    Net = "net"
    NetLatency = "net_latency"


parser = argparse.ArgumentParser(description="Plot results of A/B test")
parser.add_argument("path", type=str)
args = parser.parse_args()

paths = [f"{args.path}/{f}" for f in os.listdir(args.path)]
for path in paths:
    print(f"processing: {path}")
    with open(path) as f:
        fails = json.load(f)["fails"]

    if not fails:
        print(f"skipping {path}. No data present")
        continue

    instances = set()
    host_kernels = set()
    aggregated = {}

    match fails[0]["performance_test"]:
        case "test_block_performance":
            data_type = DataType.Block
        case "test_network_tcp_throughput":
            data_type = DataType.Net
        case "test_network_latency":
            data_type = DataType.NetLatency
        case _:
            print("unknown data type. skipping")
            continue

    for fail in fails:
        instances.add(fail["instance"])
        host_kernels.add(fail["host_kernel"])

        if data_type == DataType.Block:
            tag = (
                fail["instance"],
                fail["host_kernel"],
                fail["guest_kernel"],
                fail["fio_mode"],
                fail["vcpus"],
                fail["io_engine"],
            )
        elif data_type == DataType.Net:
            tag = (
                fail["instance"],
                fail["host_kernel"],
                fail["guest_kernel"],
                fail["mode"],
                fail["vcpus"],
            )
        elif data_type == DataType.NetLatency:
            tag = (
                fail["instance"],
                fail["host_kernel"],
                fail["guest_kernel"],
            )
            POSITIVE_COLOR = RED
            NEGATIVE_COLOR = GREEN

        if tag not in aggregated:
            aggregated[tag] = []
        aggregated[tag].append(fail["diff"])

    for instance in sorted(instances):
        fig, ax = plt.subplots(len(host_kernels), figsize=(16, 11))
        if len(host_kernels) == 1:
            ax = [ax]
        fig.tight_layout(pad=8.0)

        for i, host_kernel in enumerate(sorted(host_kernels)):
            data = []
            for key, value in aggregated.items():
                if key[0] == instance and key[1] == host_kernel:
                    label = "\n".join(key[2:])
                    values = np.array(value)
                    mean = np.mean(values)
                    std = np.std(values)
                    data.append((label, mean, std))
            data.sort()
            labels = np.array([t[0] for t in data])
            means = np.array([t[1] for t in data])
            errors = np.array([t[2] for t in data])
            colors = [
                (
                    lerp(GREY, POSITIVE_COLOR, t)
                    if 0.0 < t
                    else lerp(GREY, NEGATIVE_COLOR, -t)
                )
                for t in [m / 100.0 for m in means]
            ]

            bar = ax[i].bar(labels, means, yerr=errors, color=colors, ecolor="white")
            bar_labels = [f"{m:.2f} / {s:.2f}" for (m, s) in zip(means, errors)]
            ax[i].bar_label(bar, labels=bar_labels)
            ax[i].set_ylabel("Percentage of change: mean / std")
            ax[i].grid(color="grey", linestyle="-.", linewidth=0.5, alpha=0.5)
            ax[i].set_title(
                f"{data_type}\nInstance: {instance}\nHost kernel: {host_kernel}",
            )

        plt.savefig(f"{args.path}/{data_type}_{instance}.png")
