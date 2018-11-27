# Production Host Setup Recommendations

## Host Security Configuration

### Mitigating Side-Channel Issues

When deploying Firecracker microVMs to handle multi-tenant workloads, the
following host environment configurations are strongly recommended to guard
against side-channel security issues.

#### Disable Simultaneous Multithreading (SMT)

  Disabling of SMT will help mitigate side-channels issues between sibling
  threads on the same physical core.

  SMT can be disabled by adding the following Kernel boot parameter to the host:

  ```
  nosmt=force
  ````

  Verification can be done by running

  ```bash
  (grep -q "^forceoff$\|^notsupported$" /sys/devices/system/cpu/smt/control && echo "Hyperthreading: DISABLED") || echo "Hyperthreading: ENABLED"
  ```

#### Check Kernel Page-Table Isolation (KPTI) is supported

  KPTI is used to prevent certain side-channel issues that allow access to
  protected kernel memory pages that are normally inaccessible to guests. Some
  variants of Meltdown can be mitigated by enabling this feature.

  Verification can be done by running

  ```bash
  (grep -q "^Mitigation: PTI$" /sys/devices/system/cpu/vulnerabilities/meltdown && echo "KPTI: SUPPORTED") || echo "KPTI: NOT SUPPORTED"
  ```

#### Disable Kernel Same-page Merging (KSM)/sharing/de-duplication

  Disabling KSM mitigates side-channel issues which relies on de-duplication to
  reveal what memory line was accessed by another process.

  KSM can be disabled by executing the following as root:

  ```
   echo "0" > /sys/kernel/mm/ksm/run
  ```

  Verification can be done by running

  ```bash
  (grep -q "^0$" /sys/kernel/mm/ksm/run && echo "KSM: DISABLED") || echo "KSM: ENABLED"
  ```

#### Use kernel compiled with retpoline and run on hardware with microcode supporting Indirect Branch Prediction Barriers (IBPB) and Indirect Branch Restricted Speculation (IBRS)

  These features provide side-channel mitigation for variants of Spectre such
  as the Branch Target Injection variant.

  Verification can be done by running

  ```bash
  (grep -q "^Mitigation: Full generic retpoline, IBPB, IBRS_FW$" /sys/devices/system/cpu/vulnerabilities/spectre_v2 && echo "retpoline, IBPB, IBRS: ENABLED") || echo "retpoline, IBPB, IBRS: DISABLED"
  ```

#### Apply L1 Terminal Fault (L1TF) mitigation when entering into VM context

  These features provide mitigation for Foreshadow/L1TF side-channel issue on
  affected hardware.

  Enabling can be done by adding Linux Kernel boot parameter:

  ```
  l1tf=full,force
  ```

  which will also implicitly disable SMT.

  Verification can be done by running

  ```bash
  declare -a CONDITIONS=("Mitigation: PTE Inversion" "VMX: cache flushes")
  for cond in "${CONDITIONS[@]}"; do (grep -q "$cond" /sys/devices/system/cpu/vulnerabilities/l1tf && echo "$cond: ENABLED") || echo "$cond: DISABLED"; done
  ```

#### Ensure that Speculative Store Bypass mitigation is applied to Firecracker

  Applying SSBD will mitigate variants of Spectre side-channel issues such as
  Speculative Store Bypass and SpectreNG.

  SSBD can be applied when seccomp is used by Firecracker's jailer through the
  following Kernel boot parameter:

  ```
  spec_store_bypass_disable=seccomp
  ```

  Verification can be done by running

  ```bash
  cat /proc/*PID*/status | grep Speculation_Store_Bypass
  ```

  where *PID* is the process ID being check.  Output shows one of the
  following:
  - not vulnerable
  - thread mitigated
  - thread force mitigated
  - globally mitigated

#### Use memory with Rowhammer mitigation support

  Certain DDR memory are susceptible to Rowhammer issues, using DDR4 memory that
  supports Target Row Refresh (TRR) with error-correcting code (ECC) is
  recommended. Use of pseudo target row refresh (pTRR) for system with
  pTRR-compliant DDR3 memory can help mitigation the issue however it will have
  memory performance impact.

#### Disable swapping to disk or enable secure swap

  Disabling swapping to disk or enabling securing swap file on host mitigates
  data remanence in storage devices of guest memory.

  Verify that swap is disabled by running

  ```bash
  cat /proc/swaps
  ```

  and the output shows no swap partition.
