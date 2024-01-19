import subprocess
from pathlib import Path

from integration_tests.security.test_jail import cgroups_info
from framework.microvm_helpers import docker_apt_install


def get_numa_cpus(node):
    """Retrieve CPUs from NUMA node."""
    node_dir = Path(f"/sys/devices/system/node/node{node}")
    assert node_dir.is_dir()
    node_cpus = node_dir / "cpulist"
    return node_cpus.read_text().strip()


def test_FC_DEV_1362(uvm_plain, cgroups_info):
    """
    https://sim.amazon.com/issues/FC-DEV-1903

    ./tools/devtool test_debug integration_tests/test_FC-DEV-1362.py

    Test that we only write to cgroup.procs once instead of once per --cgroup parameter.

22:27:30.417558 write(3</sys/fs/cgroup/custom_cgroup/group2/9d1e4709-5789-4092-bc4b-f5b0a9169a86/cpuset.cpus>, "0-7\n", 4) = 4 <0.000012578>
22:27:30.417649 write(3</sys/fs/cgroup/custom_cgroup/group2/9d1e4709-5789-4092-bc4b-f5b0a9169a86/cgroup.procs>, "76\n", 3) = 3 <0.023667513>
22:27:30.441467 write(3</sys/fs/cgroup/custom_cgroup/group2/9d1e4709-5789-4092-bc4b-f5b0a9169a86/cgroup.procs>, "76\n", 3) = 3 <0.000011930>
22:27:30.441615 write(3</sys/fs/cgroup/custom_cgroup/group2/9d1e4709-5789-4092-bc4b-f5b0a9169a86/cgroup.procs>, "76\n", 3) = 3 <0.000008260>
    """

    docker_apt_install("inotify-tools")

    uvm = uvm_plain
    uvm.jailer.cgroup_ver = cgroups_info.version
    parent_cgroup = "custom_cgroup/group2"
    uvm.jailer.parent_cgroup = parent_cgroup
    cgroups_info.new_cgroup(parent_cgroup)
    cgroups_info.new_cgroup(f"{parent_cgroup}/{uvm.id}")
    Path("inot.log").unlink(missing_ok=True)
    inot = subprocess.Popen("inotifywait -m -r -o inot.log /sys/fs/cgroup", shell=True)

    cgroups = {
        "cpuset.cpus": get_numa_cpus(0),
        "cpu.weight": 2,
        "memory.max": 256*2**20,
        "memory.min": 1*2**20,
    }
    uvm.jailer.cgroups = [f"{k}={v}" for k, v in cgroups.items()]
    uvm.spawn()
    uvm.basic_config()
    uvm.add_net_iface()
    uvm.start()
    strace_out = Path("strace.out").read_text().splitlines()
    write_lines = [
        line for line in strace_out
        if "write" in line
        and f"{uvm.id}/cgroup.procs" in line
    ]
    mkdir_lines = [
        line for line in strace_out
        if "mkdir" in line
        and f"{parent_cgroup}/{uvm.id}" in line
    ]
    assert len(write_lines) != len(cgroups), "writes equal to number of cgroups"
    assert len(write_lines) == 1
    assert len(mkdir_lines) != len(cgroups), "mkdir equal to number of cgroups"
    assert len(mkdir_lines) == 1



"""
    docker_apt_install("inotify-tools")
inot = subprocess.Popen(
    "inotifywait -m -r -o inot.log /sys/fs/cgroup",
    shell=True,
)
    Path("inot.log").unlink()


    dev_full = Path(uvm.chroot()) / "full"
    os.mknod(dev_full, mode=0o666|stat.S_IFCHR, device=os.makedev(1, 7))
    dev_full.chmod(0o666)
    os.chown(dev_full, 1234, 1234)

"""
