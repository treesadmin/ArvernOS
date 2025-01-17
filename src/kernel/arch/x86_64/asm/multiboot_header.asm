; This is a Multiboot-compliant header file in assembly code.
section .multiboot_header
align 8

%define MULTIBOOT2_MAGIC_NUMBER  0xe85250d6
%define PROTECTED_MODE_CODE      0 ; architecture 0 (protected mode i386)
                                   ; architecture 4 (MIPS)

header_start:
  ; `dd` means 'define double word'
  dd MULTIBOOT2_MAGIC_NUMBER   ; magic number
  dd PROTECTED_MODE_CODE       ; architecture
  dd header_end - header_start ; header length

  ; checksum
  dd 0x100000000 - (MULTIBOOT2_MAGIC_NUMBER + 0 + (header_end - header_start))

%ifdef ENABLE_FRAMEBUFFER
  ; framebuffer
  dw 5
  dw 0
  dd 20
  dd VBE_WIDTH
  dd VBE_HEIGHT
  dd VBE_BPP
  dd 0
%endif

  ; required end tag
  ; `dw` means 'define word' (word = 16 bits on x86_64)
  dw 0  ; type
  dw 0  ; flags
  dd 8  ; size
header_end:
