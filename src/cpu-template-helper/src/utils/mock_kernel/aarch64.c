#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Kernel header for AArch64.
// It comes from the kernel doc Documentation/arm64/booting.txt.
typedef struct {
    uint32_t code0;          // Executable code
    uint32_t code1;          // Executable code
    uint64_t text_offset;    // Image load offset, little endian
    uint64_t image_size;     // Effective Image size, little endian
    uint64_t flags;          // kernel flags, little endian
    uint64_t res2;           // reserved
    uint64_t res3;           // reserved
    uint64_t res4;           // reserved
    uint32_t magic;          // Magic number, little endian, "ARM\x64"
    uint32_t res5;           // reserved (used for PE COFF offset)
} __attribute__((packed)) kernel_header;

int main(int argc, char **argv) {
    kernel_header header = {
        .code0 = 0,
        .code1 = 0,
        .text_offset = sizeof(kernel_header),
        .image_size = 0,
        .flags = 0,
        .magic = 0x644d5241, // "ARM\x64"
        .res5 = sizeof(kernel_header),
    };

    FILE *output_fp = fopen("aarch64.bin", "wb");
    if (!output_fp) {
        perror("Failed to create output image");
        return 1;
    }
    fwrite(&header, sizeof(header), 1, output_fp);
    fclose(output_fp);

    return 0;
}
