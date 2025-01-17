/**
 * @file
 * @see https://www.gnu.org/software/grub/manual/multiboot2/multiboot.html
 */
#ifndef CORE_MULTIBOOT_H
#define CORE_MULTIBOOT_H

#include <stdbool.h>
#include <stdint.h>

// Flags set in the 'flags' member of the multiboot header.
#define MULTIBOOT_TAG_TYPE_END              0
#define MULTIBOOT_TAG_TYPE_CMDLINE          1
#define MULTIBOOT_TAG_TYPE_BOOT_LOADER_NAME 2
#define MULTIBOOT_TAG_TYPE_MODULE           3
#define MULTIBOOT_TAG_TYPE_BASIC_MEMINFO    4
#define MULTIBOOT_TAG_TYPE_BOOTDEV          5
#define MULTIBOOT_TAG_TYPE_MMAP             6
#define MULTIBOOT_TAG_TYPE_VBE              7
#define MULTIBOOT_TAG_TYPE_FRAMEBUFFER      8
#define MULTIBOOT_TAG_TYPE_ELF_SECTIONS     9
#define MULTIBOOT_TAG_TYPE_APM              10
#define MULTIBOOT_TAG_TYPE_EFI32            11
#define MULTIBOOT_TAG_TYPE_EFI64            12
#define MULTIBOOT_TAG_TYPE_SMBIOS           13
#define MULTIBOOT_TAG_TYPE_ACPI_OLD         14
#define MULTIBOOT_TAG_TYPE_ACPI_NEW         15
#define MULTIBOOT_TAG_TYPE_NETWORK          16
#define MULTIBOOT_TAG_TYPE_EFI_MMAP         17
#define MULTIBOOT_TAG_TYPE_EFI_BS           18
#define MULTIBOOT_TAG_TYPE_EFI32_IH         19
#define MULTIBOOT_TAG_TYPE_EFI64_IH         20
#define MULTIBOOT_TAG_TYPE_LOAD_BASE_ADDR   21

#define MULTIBOOT_MEMORY_AVAILABLE 1
#define MULTIBOOT_MEMORY_RESERVED  2

#define MULTIBOOT_ELF_SECTION_TYPE_NULL       0
#define MULTIBOOT_ELF_SECTION_FLAG_WRITABLE   0x1
#define MULTIBOOT_ELF_SECTION_FLAG_ALLOCATED  0x2
#define MULTIBOOT_ELF_SECTION_FLAG_EXECUTABLE 0x4

typedef struct multiboot_tag
{
  uint32_t type;
  uint32_t size;
  // other fieds
} __attribute__((packed)) multiboot_tag_t;

typedef struct multiboot_info
{
  uint32_t size;
  uint32_t reserved;
  multiboot_tag_t tags[];
  // end tags
} __attribute__((packed)) multiboot_info_t;

typedef struct multiboot_tag_string
{
  uint32_t type;
  uint32_t size;
  char string[];
} __attribute__((packed)) multiboot_tag_string_t;

typedef struct multiboot_tag_basic_meminfo
{
  uint32_t type;
  uint32_t size;
  uint32_t mem_lower;
  uint32_t mem_upper;
} __attribute__((packed)) multiboot_tag_basic_meminfo_t;

typedef struct multiboot_tag_bootdev
{
  uint32_t type;
  uint32_t size;
  uint32_t biosdev;
  uint32_t slice;
  uint32_t part;
} __attribute__((packed)) multiboot_tag_bootdev_t;

typedef struct multiboot_tag_module
{
  uint32_t type;
  uint32_t size;
  uint32_t mod_start;
  uint32_t mod_end;
  char cmdline[];
} __attribute__((packed)) multiboot_tag_module_t;

typedef struct multiboot_mmap_entry
{
  uint64_t addr;
  uint64_t len;
  uint32_t type;
  uint32_t zero;
} __attribute__((packed)) multiboot_mmap_entry_t;

typedef struct multiboot_tag_mmap
{
  uint32_t type;
  uint32_t size;
  uint32_t entry_size;
  uint32_t entry_version;
  multiboot_mmap_entry_t entries[];
} __attribute__((packed)) multiboot_tag_mmap_t;

/**
 * @see
 * https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#Section_header
 */
typedef struct multiboot_elf_sections_entry
{
  uint32_t name;
  uint32_t type;
  uint64_t flags;
  uint64_t addr;
  uint64_t offset;
  uint64_t size;
  uint32_t link;
  uint32_t info;
  uint64_t alignment;
  uint64_t entry_size;
} __attribute__((packed)) multiboot_elf_sections_entry_t;

typedef struct multiboot_tag_elf_sections
{
  uint32_t type;
  uint32_t size;
  uint32_t num;
  uint32_t section_size;
  uint32_t shndx;
  multiboot_elf_sections_entry_t sections[];
} __attribute__((packed)) multiboot_tag_elf_sections_t;

typedef struct reserved_areas
{
  uint64_t kernel_start;
  uint64_t kernel_end;
  uint64_t multiboot_start;
  uint64_t multiboot_end;
  uint64_t start;
  uint64_t end;
} reserved_areas_t;

typedef struct multiboot_color
{
  uint8_t red;
  uint8_t green;
  uint8_t blue;
} __attribute__((packed)) multiboot_color_t;

typedef struct multiboot_tag_framebuffer_common
{
  uint32_t type;
  uint32_t size;

  uint64_t framebuffer_addr;
  uint32_t framebuffer_pitch;
  uint32_t framebuffer_width;
  uint32_t framebuffer_height;
  uint8_t framebuffer_bpp;
  uint8_t framebuffer_type;
  uint16_t reserved;
} __attribute__((packed)) multiboot_tag_framebuffer_common_t;

typedef struct multiboot_tag_framebuffer
{
  multiboot_tag_framebuffer_common_t common;
  union
  {
    struct
    {
      uint16_t framebuffer_palette_num_colors;
      multiboot_color_t framebuffer_palette;
    };
    struct
    {
      uint8_t framebuffer_red_field_position;
      uint8_t framebuffer_red_mask_size;
      uint8_t framebuffer_green_field_position;
      uint8_t framebuffer_green_mask_size;
      uint8_t framebuffer_blue_field_position;
      uint8_t framebuffer_blue_mask_size;
    };
  };
} __attribute__((packed)) multiboot_tag_framebuffer_t;

void multiboot_init(multiboot_info_t* mbi);

reserved_areas_t multiboot_get_reserved_areas();

multiboot_tag_framebuffer_t* multiboot_get_framebuffer();

const char* multiboot_get_cmdline();

multiboot_info_t* multiboot_get_info();

multiboot_tag_mmap_t* multiboot_get_mmap();

/**
 * Finds and returns a pointer to a specific "tag" in the multiboot
 * information.
 *
 * @param type the type of the tag to find
 * @return a pointer to a multiboot tag structure or `0`
 */
void* multiboot_find(uint16_t type);

#endif
