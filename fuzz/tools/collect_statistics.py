# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import re
import json
from datetime import datetime
import subprocess
from pathlib import Path
import argparse

AFL_STATS_FILE = 'fuzzer_stats'

ENV_FILE = 'env'

TARGET_REGEX = r'cargo_target\/(.+)\/(debug|release)\/(\w+)_fuzz_target'
CORES_REGEX = r'fuzzer\d{2}'

def parseArguments():
    # Create argument parser
    parser = argparse.ArgumentParser()

    # Positional mandatory arguments
    parser.add_argument("target", help="Target for which to collect metrics.", type=str)

    args = parser.parse_args()
    return args

def get_fuzzer_stats(fuzz_out_dir):
    is_crash = True
    d = {}
    fuzzer_stats_file = os.path.join(fuzz_out_dir, AFL_STATS_FILE)

    with open(fuzzer_stats_file, 'r') as file:
        fuzz_stats = {}
        lines = file.readlines()

        # AFL fuzzer generates a file containing statistics of the fuzzing session. These statistics help us picture
        # the performance of the fuzzing session. We are interested in the value of this statistics because a big
        # decrease in fuzzing coverage might mean that the input files are no longer relevant.
        # Key represent the name of a characteristic(i.e unique_crashes, paths_found), and value represent the value
        # of said key.
        for line in lines:
            components = line.split(':')
            key = components[0].strip()
            value = components[1].strip()
            fuzz_stats[key] = value

        words = re.findall(TARGET_REGEX, fuzz_stats['command_line'])[0]

        d['fuzz_target'] = words[2]
        d['profile'] = words[1]
        d['target'] = words[0]
        d['cores'] = len(list((filter(re.compile(CORES_REGEX).match, os.listdir(fuzz_out_dir)))))
        d['start_time'] = datetime.fromtimestamp(int(fuzz_stats['start_time']))
        d['execs_done'] = int(fuzz_stats['execs_done'])
        d['cycles_done'] = int(fuzz_stats['cycles_done'])
        d['stability'] = fuzz_stats['stability']
        d['unique_hangs'] = int(fuzz_stats['saved_hangs'])
        d['unique_crashes'] = int(fuzz_stats['saved_crashes'])
        d['paths_total'] = int(fuzz_stats['corpus_count'])
        d['paths_found'] = int(fuzz_stats['corpus_found'])
        d['bitmap_cvg'] =  fuzz_stats['bitmap_cvg']
        d['exec_timeout'] = int(fuzz_stats['exec_timeout'])
        d['command_line'] = fuzz_stats['command_line']
        if d["unique_crashes"] == 0 and d["unique_hangs"] == 0:
            is_crash = False
    return (d, is_crash)

def get_environment(fuzz_out_dir):
    d = {}
    fuzzer_environment_file = os.path.join(fuzz_out_dir, ENV_FILE)
    with open(fuzzer_environment_file, 'r') as file_handle:
        fuzz_environment_lines = file_handle.readlines()
        d["rustc_version"] = fuzz_environment_lines[0][:-1]
        d["afl_version"] = fuzz_environment_lines[1][:-1]
    return d

def get_firecracker_version():
    manifest_json = subprocess.check_output(["cargo", "read-manifest"], cwd = "../src/firecracker")
    fc_version = json.loads(manifest_json)['version']
    commit = subprocess.check_output(["git", "rev-parse", "--verify", "HEAD"], cwd = "..").strip()

    return [fc_version, commit]

if __name__ == "__main__":
    args = parseArguments()
    statistics = {}
    base_path = Path("out_{}".format(args.target))
    for d in base_path.iterdir():
        if d.is_dir() and d.name.startswith("fuzzer"):
            statistics[d.name] = get_fuzzer_stats(d)
    environment = get_environment("out_{}".format(args.target))
    version_string = get_firecracker_version()
    statistics["rustc_version"] = environment["rustc_version"]
    statistics["afl_version"] = environment["afl_version"]
    statistics["firecracker_version"] = version_string
    path_post = "out_{}/session_statistics".format(args.target)
    with open(path_post, "w+") as file_handle:
        file_handle.write(str(statistics))
