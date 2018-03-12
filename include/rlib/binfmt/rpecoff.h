/* RLIB - Convenience library for useful things
 * Copyright (C) 2018 Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 * See the COPYING file at the root of the source repository.
 */
#ifndef __R_PECOFF_H__
#define __R_PECOFF_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

R_BEGIN_DECLS

#define R_PE_DOS_MAGIC                      0x5a4d
#define R_PE_IMAGE_MAGIC                    0x00004550
#define R_PE_PE32_MAGIC                     0x010b
#define R_PE_PE32PLUS_MAGIC                 0x020b

typedef struct {
  ruint16 magic;
  ruint16 cblp;
  ruint16 cp;
  ruint16 crlc;
  ruint16 cparhdr;
  ruint16 minalloc;
  ruint16 maxalloc;
  ruint16 ss;
  ruint16 sp;
  ruint16 csum;
  ruint16 ip;
  ruint16 cs;
  ruint16 lfarlc;
  ruint16 ovno;
  ruint16 res[4];
  ruint16 oemid;
  ruint16 oeminfo;
  ruint16 res2[10];
  ruint32 lfanew;
} RPeDosHdr;


#define R_PE_MACHINE_UNKNOWN                0x0000 /* The contents of this field are assumed to be applicable to any machine type */
#define R_PE_MACHINE_AM33                   0x01d3 /* Matsushita AM33 */
#define R_PE_MACHINE_AMD64                  0x8664 /* x64 */
#define R_PE_MACHINE_ARM                    0x01c0 /* ARM little endian */
#define R_PE_MACHINE_ARM64                  0xaa64 /* ARM64 little endian */
#define R_PE_MACHINE_ARMNT                  0x01c4 /* ARM Thumb-2 little endian */
#define R_PE_MACHINE_EBC                    0x0ebc /* EFI byte code */
#define R_PE_MACHINE_I386                   0x014c /* Intel 386 or later processors and compatible processors */
#define R_PE_MACHINE_IA64                   0x0200 /* Intel Itanium processor family */
#define R_PE_MACHINE_M32R                   0x9041 /* Mitsubishi M32R little endian */
#define R_PE_MACHINE_MIPS16                 0x0266 /* MIPS16 */
#define R_PE_MACHINE_MIPSFPU                0x0366 /* MIPS with FPU */
#define R_PE_MACHINE_MIPSFPU16              0x0466 /* MIPS16 with FPU */
#define R_PE_MACHINE_POWERPC                0x01f0 /* Power PC little endian */
#define R_PE_MACHINE_POWERPCFP              0x01f1 /* Power PC with floating point support */
#define R_PE_MACHINE_R4000                  0x0166 /* MIPS little endian */
#define R_PE_MACHINE_RISCV32                0x5032 /* RISC-V 32-bit address space */
#define R_PE_MACHINE_RISCV64                0x5064 /* RISC-V 64-bit address space */
#define R_PE_MACHINE_RISCV128               0x5128 /* RISC-V 128-bit address space */
#define R_PE_MACHINE_SH3                    0x01a2 /* Hitachi SH3 */
#define R_PE_MACHINE_SH3DSP                 0x01a3 /* Hitachi SH3 DSP */
#define R_PE_MACHINE_SH4                    0x01a6 /* Hitachi SH4 */
#define R_PE_MACHINE_SH5                    0x01a8 /* Hitachi SH5 */
#define R_PE_MACHINE_THUMB                  0x01c2 /* Thumb */
#define R_PE_MACHINE_WCEMIPSV2              0x0169 /* MIPS little-endian WCE v2 */
R_API const rchar * r_pe_machine_str (ruint16 machine);

#define R_PE_FILE_RELOCS_STRIPPED           0x0001
#define R_PE_FILE_EXECUTABLE_IMAGE          0x0002
#define R_PE_FILE_LINE_NUMS_STRIPPED        0x0004
#define R_PE_FILE_LOCAL_SYMS_STRIPPED       0x0008
#define R_PE_FILE_AGGRESSIVE_WS_TRIM        0x0010
#define R_PE_FILE_LARGE_ADDRESS_AWARE       0x0020
#define R_PE_FILE_BYTES_REVERSED_LO         0x0080
#define R_PE_FILE_32BIT_MACHINE             0x0100
#define R_PE_FILE_DEBUG_STRIPPED            0x0200
#define R_PE_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400
#define R_PE_FILE_NET_RUN_FROM_SWAP         0x0800
#define R_PE_FILE_SYSTEM                    0x1000
#define R_PE_FILE_DLL                       0x2000
#define R_PE_FILE_UP_SYSTEM_ONLY            0x4000
#define R_PE_FILE_BYTES_REVERSED_HI         0x8000

typedef struct {
  ruint16 machine;
  ruint16 nsect;
  ruint32 ts;
  ruint32 ptr_symtbl;
  ruint32 nsyms;
  ruint16 size_opthdr;
  ruint16 characteristics;
} RPeCoffImageHdr;

typedef struct {
  ruint32 magic;
  RPeCoffImageHdr coff;
} RPeImageHdr;

R_API RPeImageHdr * r_pe_image_from_dos_header (const RPeDosHdr * dos);
static inline rboolean r_pe_image_is_valid (rconstpointer mem) {
  return r_pe_image_from_dos_header (mem) != NULL;
}
R_API ruint16 r_pe_image_pe32_magic (rconstpointer mem);
R_API rsize r_pe_image_size (rconstpointer mem);
R_API rsize r_pe_image_calc_size (rconstpointer mem);


#define R_PE_SUBSYSTEM_UNKNOWN                   0 /* An unknown subsystem */
#define R_PE_SUBSYSTEM_NATIVE                    1 /* Device drivers and native Windows processes */
#define R_PE_SUBSYSTEM_WINDOWS_GUI               2 /* The Windows graphical user interface (GUI) subsystem */
#define R_PE_SUBSYSTEM_WINDOWS_CUI               3 /* The Windows character subsystem */
#define R_PE_SUBSYSTEM_OS2_CUI                   5 /* The OS/2 character subsystem */
#define R_PE_SUBSYSTEM_POSIX_CUI                 7 /* The Posix character subsystem */
#define R_PE_SUBSYSTEM_NATIVE_WINDOWS            8 /* Native Win9x driver */
#define R_PE_SUBSYSTEM_WINDOWS_CE_GUI            9 /* Windows CE */
#define R_PE_SUBSYSTEM_EFI_APPLICATION          10 /* An Extensible Firmware Interface (EFI) application */
#define R_PE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  11 /* An EFI driver with boot services */
#define R_PE_SUBSYSTEM_EFI_RUNTIME_DRIVER       12 /* An EFI driver with run-time services */
#define R_PE_SUBSYSTEM_EFI_ROM                  13 /* An EFI ROM image */
#define R_PE_SUBSYSTEM_XBOX                     14 /* XBOX */
#define R_PE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16 /* Windows boot application. */

typedef struct {
  ruint16 magic;
  ruint8 major_linker_ver;
  ruint8 minor_linker_ver;
  ruint32 size_code;
  ruint32 size_initialized_data;
  ruint32 size_uninitialized_data;
  ruint32 addr_entrypoint;
  ruint32 base_code;
} RPeOptHdr;

#define R_PE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA         0x0020
#define R_PE_DLLCHARACTERISTICS_DYNAMIC_BASE            0x0040
#define R_PE_DLLCHARACTERISTICS_FORCE_INTEGRITY         0x0080
#define R_PE_DLLCHARACTERISTICS_NX_COMPAT               0x0100
#define R_PE_DLLCHARACTERISTICS_NO_ISOLATION            0x0200
#define R_PE_DLLCHARACTERISTICS_NO_SEH                  0x0400
#define R_PE_DLLCHARACTERISTICS_NO_BIND                 0x0800
#define R_PE_DLLCHARACTERISTICS_APPCONTAINER            0x1000
#define R_PE_DLLCHARACTERISTICS_WDM_DRIVER              0x2000
#define R_PE_DLLCHARACTERISTICS_GUARD_CF                0x4000
#define R_PE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE   0x8000

typedef struct {
  ruint32 base_data;
  ruint32 image_base;
  ruint32 section_alignment;
  ruint32 file_alignment;
  ruint16 major_os_ver;
  ruint16 minor_os_ver;
  ruint16 major_image_ver;
  ruint16 minor_image_ver;
  ruint16 major_subsystem_ver;
  ruint16 minor_subsystem_ver;
  ruint32 win32_ver;
  ruint32 size_image;
  ruint32 size_headers;
  ruint32 checksum;
  ruint16 subsystem;
  ruint16 dll_characteristics;
  ruint32 size_stack_reserve;
  ruint32 size_stack_commit;
  ruint32 size_heap_reserve;
  ruint32 size_heap_commit;
  ruint32 loader_flags;
  ruint32 number_rva_and_sizes;
} RPe32WinOptHdr;

typedef struct {
  ruint64 image_base;
  ruint32 section_alignment;
  ruint32 file_alignment;
  ruint16 major_os_ver;
  ruint16 minor_os_ver;
  ruint16 major_image_ver;
  ruint16 minor_image_ver;
  ruint16 major_subsystem_ver;
  ruint16 minor_subsystem_ver;
  ruint32 win32_ver;
  ruint32 size_image;
  ruint32 size_headers;
  ruint32 checksum;
  ruint16 subsystem;
  ruint16 dll_characteristics;
  ruint64 size_stack_reserve;
  ruint64 size_stack_commit;
  ruint64 size_heap_reserve;
  ruint64 size_heap_commit;
  ruint32 loader_flags;
  ruint32 number_rva_and_sizes;
} RPe32PlusWinOptHdr;

typedef struct {
  ruint32 vmaddr;
  ruint32 size;
} RPeDataDirectory;

typedef enum {
  R_PE_DATA_DIR_EXPORT = 0,
  R_PE_DATA_DIR_IMPORT,
  R_PE_DATA_DIR_RESOURCE,
  R_PE_DATA_DIR_EXCEPTION,
  R_PE_DATA_DIR_CERT,
  R_PE_DATA_DIR_BASERELOC,
  R_PE_DATA_DIR_DEBUG,
  R_PE_DATA_DIR_ARCH,
  R_PE_DATA_DIR_GLOBALPTR,
  R_PE_DATA_DIR_TLS,
  R_PE_DATA_DIR_LOAD_CONFIG,
  R_PE_DATA_DIR_BOUND_IMPORT,
  R_PE_DATA_DIR_IAT,
  R_PE_DATA_DIR_DELAY_IMPORT,
  R_PE_DATA_DIR_COM_DESCRIPTOR,
  R_PE_DATA_DIR_ZERO
} RPeDataDirEntry;

typedef struct {
  RPeImageHdr image;
  RPeOptHdr opt;
  RPe32WinOptHdr winopt;
  RPeDataDirectory datadir[16];
} RPe32ImageHdr;

typedef struct {
  RPeImageHdr image;
  RPeOptHdr opt;
  RPe32PlusWinOptHdr winopt;
  RPeDataDirectory datadir[16];
} RPe32PlusImageHdr;


#define R_PE_SCN_TYPE_NO_PAD               0x00000008
#define R_PE_SCN_CNT_CODE                  0x00000020
#define R_PE_SCN_CNT_INITIALIZED_DATA      0x00000040
#define R_PE_SCN_CNT_UNINITIALIZED_DATA    0x00000080
#define R_PE_SCN_LNK_OTHER                 0x00000100
#define R_PE_SCN_LNK_INFO                  0x00000200
#define R_PE_SCN_LNK_REMOVE                0x00000800
#define R_PE_SCN_LNK_COMDAT                0x00001000
#define R_PE_SCN_GPREL                     0x00008000
#define R_PE_SCN_MEM_PURGEABLE             0x00020000
#define R_PE_SCN_MEM_16BIT                 0x00020000
#define R_PE_SCN_MEM_LOCKED                0x00040000
#define R_PE_SCN_MEM_PRELOAD               0x00080000
#define R_PE_SCN_ALIGN_1BYTES              0x00100000
#define R_PE_SCN_ALIGN_2BYTES              0x00200000
#define R_PE_SCN_ALIGN_4BYTES              0x00300000
#define R_PE_SCN_ALIGN_8BYTES              0x00400000
#define R_PE_SCN_ALIGN_16BYTES             0x00500000
#define R_PE_SCN_ALIGN_32BYTES             0x00600000
#define R_PE_SCN_ALIGN_64BYTES             0x00700000
#define R_PE_SCN_ALIGN_128BYTES            0x00800000
#define R_PE_SCN_ALIGN_256BYTES            0x00900000
#define R_PE_SCN_ALIGN_512BYTES            0x00A00000
#define R_PE_SCN_ALIGN_1024BYTES           0x00B00000
#define R_PE_SCN_ALIGN_2048BYTES           0x00C00000
#define R_PE_SCN_ALIGN_4096BYTES           0x00D00000
#define R_PE_SCN_ALIGN_8192BYTES           0x00E00000
#define R_PE_SCN_LNK_NRELOC_OVFL           0x01000000
#define R_PE_SCN_MEM_DISCARDABLE           0x02000000
#define R_PE_SCN_MEM_NOT_CACHED            0x04000000
#define R_PE_SCN_MEM_NOT_PAGED             0x08000000
#define R_PE_SCN_MEM_SHARED                0x10000000
#define R_PE_SCN_MEM_EXECUTE               0x20000000
#define R_PE_SCN_MEM_READ                  0x40000000
#define R_PE_SCN_MEM_WRITE                 0x80000000


typedef struct {
  rchar name[8];
  ruint32 vmsize;
  ruint32 vmaddr;
  ruint32 size_raw_data;
  ruint32 ptr_raw_data;
  ruint32 ptr_relocs;
  ruint32 ptr_linenos;
  ruint16 nrelocs;
  ruint16 nlinenos;
  ruint32 characteristics;
} RPeSectionHdr;


typedef struct {
  ruint32 nsyms;
  ruint32 lva_first_symbol;
  ruint32 nlinenos;
  ruint32 lva_first_lineno;
  ruint32 rva_first_byte_code;
  ruint32 rva_last_byte_code;
  ruint32 rva_first_byte_data;
  ruint32 rva_last_byte_data;
} RCoffSymbolsHdr;

typedef struct {
  ruint32 characteristics;
  ruint32 ts;
  ruint16 major;
  ruint16 minor;
  ruint32 type;
  ruint32 size;
  ruint32 addr_raw_data;
  ruint32 ptr_raw_data;
} RPeDebugDirectory;

typedef struct {
  ruint32 starting_address;
  ruint32 ending_address;
  ruint32 end_prologue;
} RPeFuncEntry;

typedef struct {
  ruint32 size;
  ruint32 ts;
  ruint16 major;
  ruint16 minor;
  ruint32 global_flags_clear;
  ruint32 global_flags_set;
  ruint32 critical_section_default_timeout;
  ruint64 de_commit_free_block_threshold;
  ruint64 de_commit_total_free_threshold;
  ruint64 lock_prefix_table;
  ruint64 maximum_allocation_size;
  ruint64 virtual_memory_threshold;
  ruint64 process_affinity_mask;
  ruint32 process_heap_flags;
  ruint16 csd_version;
  ruint16 reserved1;
  ruint64 edit_list;
  ruint64 sec_cookie;
  ruint64 sehandler_table;
  ruint64 nsehandler;
} RPeLoadConfigDirectory64;


R_END_DECLS

#endif /* __R_PECOFF_H__ */

