### Snapshot save/load benchmarks
Snapshot contains 100 structs and a 10k array.  
Snapshot size: 83886 bytes.  

### Host configuration
- Architecture:        x86_64
- CPU op-mode(s):      32-bit, 64-bit
- Byte Order:          Little Endian
- CPU(s):              12
- Thread(s) per core:  2
- Core(s) per socket:  6
- Socket(s):           1
- NUMA node(s):        1
- Vendor ID:           GenuineIntel
- CPU family:          6
- Model:               158
- Model name:          Intel(R) Core(TM) i7-8700 - CPU @ 3.20GHz
- Stepping:            10
- CPU MHz:             800.077
- CPU max MHz:         4600.0000
- CPU min MHz:         800.0000
- BogoMIPS:            6399.96
- Virtualization:      VT-x
- L1d cache:           32K
- L1i cache:           32K
- L2 cache:            256K
- L3 cache:            12288K
- NUMA node0 CPU(s):   0-11
- Flags:               `fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb invpcid_single pti ssbd ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 hle avx2 smep bmi2 erms invpcid rtm mpx rdseed adx smap clflushopt intel_pt xsaveopt xsavec xgetbv1 xsaves dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp md_clear flush_l1d`

### Current baseline
Serialize: **356.42 us**                     
Deserialize: **74.710 us**  
Serialize + crc64: **402.89 us**  
Deserialize + crc64: **248.62 us**
