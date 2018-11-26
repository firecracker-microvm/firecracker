# Production Host Setup Recommendations

## Host Security Configuration

### Mitigating Side-Channel Issues

When deploying Firecracker microVMs to handle multi-tenant workloads, the
following host environment configurations are strongly recommended to guard
against side-channel security issues.

- Disable Hyperthreading

  Disabling of Hyperthreading will help mitigate side-channels issues between
  sibling threads on the same physical core.

  Hyperthreading can be disabled by adding the following kernel parameter to
  the host:

  ```
  nosmt=force
  ````

  Verification can be done by running

  ```bash
  (grep -q "^forceoff$\|^notsupported$" /sys/devices/system/cpu/smt/control && echo "Hyperthreading: DISABLED") || echo "Hyperthreading: ENABLED"
  ```

- Check Kernel Page-Table Isolation (KPTI) is supported

  KPTI is used to prevent certain side-channel issues that allow access to
  protected kernel memory pages that are normally inaccessible to guests. Some
  variants of Meltdown can be mitigated by enabling this feature.

  Verification can be done by running

  ```bash
  (grep -q "^Mitigation: PTI$" /sys/devices/system/cpu/vulnerabilities/meltdown && echo "KPTI: SUPPORTED") || echo "KPTI: NOT SUPPORTED"
  ```

- Disable Kernel Same-page Merging  (KSM)/sharing/de-duplication between
  microVMs

  Disabling KSM mitigates side-channel issues which relies on de-duplication to
  reveal what memory line was accessed by another process.

  Verification can be done by running

  ```bash
  (grep -q "^0$" /sys/kernel/mm/ksm/run && echo "KSM: DISABLED") || echo "KSM: ENABLED"
  ```

- Use kernel compiled with retpoline and run on hardware with microcode
  supporting Indirect Branch Prediction Barriers (IBPB) and Indirect Branch
  Restricted Speculation (IBRS).

  These features provide side-channel mitigation for variants of Spectre such
  as the Branch Target Injection variant.

  Verification can be done by running

  ```bash
  (grep -q "^Mitigation: Full generic retpoline, IBPB, IBRS_FW$" /sys/devices/system/cpu/vulnerabilities/spectre_v2 && echo "retpoline, IBPB, IBRS: ENABLED") || echo "retpoline, IBPB, IBRS: DISABLED"
  ```

- Enable PTE inversion mitigation and cache flushing the cache on every VM
  context change

  These features provide mitigation for Foreshadow/L1 Terminal Fault (L1TF)
  side-channel issue on affected hardware.

  Enabling can be done by adding Linux Kernel boot parameter:

  ```
  l1tf=full,force kvm-intel.vmentry_l1d_flush=always
  ```

  Verification can be done by running

  ```bash
  declare -a CONDITIONS=("Mitigation: PTE Inversion" "VMX: cache flushes")
  for cond in "${CONDITIONS[@]}"; do (grep -q "$cond" /sys/devices/system/cpu/vulnerabilities/l1tf && echo "$cond: ENABLED") || echo "$cond: DISABLED"; done
  ```

- Ensure that Speculative Store Bypass Disable (SSBD) is applied for
  Firecracker process

  Applying SSBD will mitigate variants of Spectre side-channel issues such as
  Speculative Store Bypass and SpectreNG.

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

- Use DDR4 memory that supports target row refresh or use pseudo target row
  refresh (pTRR) for system with DDR3 memory

  Having these features will help mitigate Rowhammer side-channel issues.

- Disable swapping to disk or enable secure swap

  Disabling swapping to disk or enabling securing swap file on host mitigates
  data remanence in storage devices of guest memory.

  Verify that swap is disabled by running

  ```bash
  cat /proc/swaps
  ```

  and the output shows no swap partition.
