#!/bin/bash
# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Boot a freshly built kernel tree under nested KVM with virtme-ng and run every
# KVM selftest installed from that same tree. The host must already allow
# nested VMX (kvm_intel nested=1); the Buildkite agent is never rebooted.
#
# Usage: run_kvm_selftests.sh <kernel-tree> <results-dir>

set -euo pipefail

KERNEL=$(realpath "$1")
RESULTS=$(realpath -m "$2")
GUEST_TIMEOUT=${GUEST_TIMEOUT:-2400}

grep -Eq '^(Y|1)$' /sys/module/kvm_intel/parameters/nested ||
  { echo "kvm_intel nested=1 is required on the host" >&2; exit 1; }

mkdir -p "$RESULTS"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

make -C "$KERNEL" headers >"$RESULTS/build.log" 2>&1
make -C "$KERNEL/tools/testing/selftests" TARGETS=kvm SKIP_TARGETS= FORCE_TARGETS=1 \
  -j "$(nproc)" KSFT_INSTALL_PATH="$STAGE" install >>"$RESULTS/build.log" 2>&1
cp "$STAGE/kselftest-list.txt" "$RESULTS/"
RELEASE=$(make -s -C "$KERNEL" kernelrelease)

# The guest sees the container's root filesystem read-only at the same paths,
# plus the results directory read-write. The TAP output goes to a file there
# because virtme relays guest stdout and stderr separately, which can interleave
# lines on the console. The MMU stress test is sized to fit the guest, and the
# per-test timeout is raised from the 120s default because nested KVM is slow.
TAP=$RESULTS/kvm.tap
: >"$TAP"
cat >"$STAGE/guest.sh" <<EOF
set -e
test "\$(uname -r)" = "$RELEASE"
test -c /dev/kvm
export KSELFTEST_MMU_STRESS_TEST_ARGS="-m 4 -s 1 -c 4"
"$STAGE/run_kselftest.sh" -c kvm -o 600 >"$TAP" 2>&1
echo KVM_SELFTESTS_DONE >>"$TAP"
EOF

timeout --kill-after=30 "$GUEST_TIMEOUT" \
  vng --verbose --skip-modules --force-9p --rwdir "$RESULTS" --memory 16G \
  --cpus 8,sockets=2,cores=4,threads=1 --numa 8G,cpus=0-3 --numa 8G,cpus=4-7 \
  --run "$KERNEL/arch/x86/boot/bzImage" --qemu-opts="-machine accel=kvm -cpu host,vmx=on" \
  --append "kvm_intel.nested=1 hugepagesz=2M hugepages=1152" \
  --exec "sh $STAGE/guest.sh" >"$RESULTS/console.log" 2>&1 || echo "virtme exited with status $?"

# run_kselftest.sh exits 0 even when tests fail, so check the TAP output against
# the installed test list instead. Hardware-dependent skips are fine.
expected=$(grep -c . "$STAGE/kselftest-list.txt")
reported=$(grep -cE '^(ok|not ok) [0-9]+ selftests: kvm: ' "$TAP" || true)
skipped=$(grep -cE '^ok [0-9]+ selftests: kvm: .* # SKIP' "$TAP" || true)
if ! grep -q '^KVM_SELFTESTS_DONE' "$TAP" || [ "$reported" -ne "$expected" ] ||
  [ "$skipped" -eq "$expected" ] || grep -qE '^not ok |^Bail out!' "$TAP" ||
  grep -qE 'Kernel panic - not syncing|\] (Oops|BUG):' "$RESULTS/console.log"; then
  grep -E '^not ok ' "$TAP" >&2 || true
  echo "KVM selftests failed: see $RESULTS" >&2
  exit 1
fi
echo "KVM selftests passed: $((reported - skipped)) passed, $skipped skipped"
