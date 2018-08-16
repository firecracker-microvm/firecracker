#ifdef __x86_64__

#include <stdint.h>

void x86_64_cpuid_host_cpuid(
    uint32_t leaf,
    uint32_t *eax,
    uint32_t *ebx,
    uint32_t *ecx,
    uint32_t *edx
) {
    asm volatile(

        "cpuid"

        /* out */ :
            "=a" (*eax),
            "=b" (*ebx),
            "=c" (*ecx),
            "=d" (*edx)
        /* in */ :
            "a" (leaf) /* place leaf in EAX */
        /* clobber */ : 
    );
}

#endif
