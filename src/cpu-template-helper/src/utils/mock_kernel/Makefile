# This is used to create a mock kernel to be embedded in CPU template helper tool.
# It requires a valid ELF file for x86_64 and a file containing a valid kernel header for aarch64.

ARCH := $(shell uname -m)

.PHONY: clean

$(ARCH).bin: $(ARCH).c
ifeq ($(ARCH),x86_64)
	gcc -nostdlib -fno-asynchronous-unwind-tables -s -o $(ARCH).bin $(ARCH).c
else
	gcc $(ARCH).c
	./a.out
endif

clean:
	rm -rf a.out $(ARCH).bin
