/* RLIB - Convenience library for useful things
 * Copyright (C) 2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_MACHO_H__
#define __R_MACHO_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

R_BEGIN_DECLS

#pragma pack(push, 1)

typedef ruint32 RMachoStrOffset;

#define R_MACHO_MAGIC_32              0xfeedface
#define R_MACHO_MAGIC_64              0xfeedfacf

/* Mach CPU types */
#define R_MACH_CPU_ARCH_ABI64         0x1000000
#define R_MACH_CPU_TYPE_VAX           1
#define R_MACH_CPU_TYPE_ROMP          2
#define R_MACH_CPU_TYPE_NS32032       4
#define R_MACH_CPU_TYPE_NS32332       5
#define R_MACH_CPU_TYPE_MC680x0       6
#define R_MACH_CPU_TYPE_I386          7
#define R_MACH_CPU_TYPE_MIPS          8
#define R_MACH_CPU_TYPE_NS32532       9
#define R_MACH_CPU_TYPE_HPPA          11
#define R_MACH_CPU_TYPE_ARM           12
#define R_MACH_CPU_TYPE_MC88000       13
#define R_MACH_CPU_TYPE_SPARC         14
#define R_MACH_CPU_TYPE_I860          15 /* big-endian */
#define R_MACH_CPU_TYPE_I860_LITTLE   16 /* little-endian */
#define R_MACH_CPU_TYPE_RS6000        17
#define R_MACH_CPU_TYPE_MC98000       18
#define R_MACH_CPU_TYPE_POWERPC       R_MACH_CPU_TYPE_MC98000
#define R_MACH_CPU_TYPE_VEO           255
#define R_MACH_CPU_TYPE_X86_64        (R_MACH_CPU_TYPE_I386 | R_MACH_CPU_ARCH_ABI64)
#define R_MACH_CPU_TYPE_POWERPC64     (R_MACH_CPU_TYPE_POWERPC | R_MACH_CPU_ARCH_ABI64)
#define R_MACH_CPU_TYPE_ARM64         (R_MACH_CPU_TYPE_ARM | R_MACH_CPU_ARCH_ABI64)

/* Mach CPU subtypes */
/* FIXME: Add more subtypes*/
#define R_MACH_CPU_SUBTYPE_INTEL(f, m)        ((f) + ((m) << 4))
#define R_MACH_CPU_SUBTYPE_INTEL_FAMILY_MAX   15
#define R_MACH_CPU_SUBTYPE_INTEL_MODEL_ALL    0
#define R_MACH_CPU_SUBTYPE_INTEL_FAMILY(x)    ((x) & R_MACH_CPU_SUBTYPE_INTEL_FAMILY_MAX)
#define R_MACH_CPU_SUBTYPE_INTEL_MODEL(x)     ((x) >> 4)

#define R_MACH_CPU_SUBTYPE_I386_ALL     3
#define R_MACH_CPU_SUBTYPE_X86_64_ALL   R_MACH_CPU_SUBTYPE_I386_ALL
#define R_MACH_CPU_SUBTYPE_386          3
#define R_MACH_CPU_SUBTYPE_486          4
#define R_MACH_CPU_SUBTYPE_486SX        4 + 128
#define R_MACH_CPU_SUBTYPE_586          5
#define R_MACH_CPU_SUBTYPE_X86_64_H     8 /* Haswell and compatible */
#define R_MACH_CPU_SUBTYPE_PENT         CPU_SUBTYPE_INTEL (5, 0)
#define R_MACH_CPU_SUBTYPE_PENTPRO      CPU_SUBTYPE_INTEL (6, 1)
#define R_MACH_CPU_SUBTYPE_PENTII_M3    CPU_SUBTYPE_INTEL (6, 3)
#define R_MACH_CPU_SUBTYPE_PENTII_M5    CPU_SUBTYPE_INTEL (6, 5)
#define R_MACH_CPU_SUBTYPE_PENTIUM_4    CPU_SUBTYPE_INTEL (10, 0)

#define R_MACH_CPU_SUBTYPE_ARM_ALL        0
#define R_MACH_CPU_SUBTYPE_ARM_A500_ARCH  1
#define R_MACH_CPU_SUBTYPE_ARM_A500       2
#define R_MACH_CPU_SUBTYPE_ARM_A440       3
#define R_MACH_CPU_SUBTYPE_ARM_M4         4
#define R_MACH_CPU_SUBTYPE_ARM_V4T        5
#define R_MACH_CPU_SUBTYPE_ARM_V6         6
#define R_MACH_CPU_SUBTYPE_ARM_V5TEJ      7
#define R_MACH_CPU_SUBTYPE_ARM_XSCALE     8
#define R_MACH_CPU_SUBTYPE_ARM_V7         9
#define R_MACH_CPU_SUBTYPE_ARM_V7F        10 /* Cortex A9 */
#define R_MACH_CPU_SUBTYPE_ARM_V7S        11 /* Swift */
#define R_MACH_CPU_SUBTYPE_ARM_V7K        12 /* Kirkwood40 */
#define R_MACH_CPU_SUBTYPE_ARM_V6M        14 /* Not meant to be run under xnu */
#define R_MACH_CPU_SUBTYPE_ARM_V7M        15 /* Not meant to be run under xnu */
#define R_MACH_CPU_SUBTYPE_ARM_V7EM       16 /* Not meant to be run under xnu */
#define R_MACH_CPU_SUBTYPE_ARM_V8         13

#define R_MACH_CPU_SUBTYPE_ARM64_ALL      0
#define R_MACH_CPU_SUBTYPE_ARM64_V8       1

R_API rchar * r_macho_cpu_str (ruint32 cputype, ruint32 cpusubtype);

/* Mach-o filetypes */
#define R_MACHO_FT_OBJECT         0x01
#define R_MACHO_FT_EXECUTE        0x02
#define R_MACHO_FT_FVMLIB         0x03
#define R_MACHO_FT_CORE           0x04
#define R_MACHO_FT_PRELOAD        0x05
#define R_MACHO_FT_DYLIB          0x06
#define R_MACHO_FT_DYLINKER       0x07
#define R_MACHO_FT_BUNDLE         0x08

R_API const rchar * r_macho_file_str (ruint32 filetype);

/* Mach-o files */
#define R_MACHO_FLAG_NOUNDEFS     0x01
#define R_MACHO_FLAG_INCRLINK     0x02
#define R_MACHO_FLAG_DYLDLINK     0x04
#define R_MACHO_FLAG_BINDATLOAD   0x08
#define R_MACHO_FLAG_PREBOUND     0x10

typedef struct {
  ruint32 magic;
  ruint32 cputype;
  ruint32 cpusubtype;
  ruint32 filetype;
  ruint32 ncmds;
  ruint32 sizeofcmds;
  ruint32 flags;
} RMacho32Hdr;

typedef struct {
  ruint32 magic;
  ruint32 cputype;
  ruint32 cpusubtype;
  ruint32 filetype;
  ruint32 ncmds;
  ruint32 sizeofcmds;
  ruint32 flags;
  ruint32 reserved;
} RMacho64Hdr;

/* Mach-O load commands */
#define R_MACHO_LC_REQ_DYLD           0x80000000

#define R_MACHO_LC_SEGMENT            0x01  /* segment of this file to be mapped */
#define R_MACHO_LC_SYMTAB             0x02  /* link-edit stab symbol table info */
#define R_MACHO_LC_SYMSEG             0x03  /* link-edit gdb symbol table info (obsolete) */
#define R_MACHO_LC_THREAD             0x04  /* thread */
#define R_MACHO_LC_UNIXTHREAD         0x05  /* unix thread (includes a stack) */
#define R_MACHO_LC_LOADFVMLIB         0x06  /* load a specified fixed VM shared library */
#define R_MACHO_LC_IDFVMLIB           0x07  /* fixed VM shared library identification */
#define R_MACHO_LC_IDENT              0x08  /* object identification info (obsolete) */
#define R_MACHO_LC_FVMFILE            0x09  /* fixed VM file inclusion (internal use) */
#define R_MACHO_LC_PREPAGE            0x0a  /* prepage command (internal use) */
#define R_MACHO_LC_DYSYMTAB           0x0b  /* dynamic link-edit symbol table info */
#define R_MACHO_LC_LOAD_DYLIB         0x0c  /* load a dynamicly linked shared library */
#define R_MACHO_LC_ID_DYLIB           0x0d  /* dynamicly linked shared lib identification */
#define R_MACHO_LC_LOAD_DYLINKER      0x0e  /* load a dynamic linker */
#define R_MACHO_LC_ID_DYLINKER        0x0f  /* dynamic linker identification */
#define R_MACHO_LC_PREBOUND_DYLIB     0x10  /* modules prebound for a dynamicly */
#define R_MACHO_LC_ROUTINES           0x11  /* image routines */
#define R_MACHO_LC_SUB_FRAMEWORK      0x12  /* sub framework */
#define R_MACHO_LC_SUB_UMBRELLA       0x13  /* sub umbrella */
#define R_MACHO_LC_SUB_CLIENT         0x14  /* sub client */
#define R_MACHO_LC_SUB_LIBRARY        0x15  /* sub library */
#define R_MACHO_LC_TWOLEVEL_HINTS     0x16  /* two-level namespace lookup hints */
#define R_MACHO_LC_PREBIND_CKSUM      0x17  /* prebind checksum */
#define R_MACHO_LC_LOAD_WEAK_DYLIB   (0x18 | R_MACHO_LC_REQ_DYLD)
#define R_MACHO_LC_SEGMENT_64         0x19  /* 64-bit segment of this file to be mapped */
#define R_MACHO_LC_ROUTINES_64        0x1a  /* 64-bit image routines */
#define R_MACHO_LC_UUID               0x1b  /* the uuid */
#define R_MACHO_LC_RPATH             (0x1c | R_MACHO_LC_REQ_DYLD)    /* runpath additions */
#define R_MACHO_LC_CODE_SIGNATURE     0x1d /* local of code signature */
#define R_MACHO_LC_SEGMENT_SPLIT_INFO 0x1e /* local of info to split segments */
#define R_MACHO_LC_REEXPORT_DYLIB    (0x1f | R_MACHO_LC_REQ_DYLD) /* load and re-export dylib */
#define R_MACHO_LC_LAZY_LOAD_DYLIB    0x20 /* delay load of dylib until first use */
#define R_MACHO_LC_ENCRYPTION_INFO    0x21 /* encrypted segment information */
#define R_MACHO_LC_DYLD_INFO          0x22 /* compressed dyld information */
#define R_MACHO_LC_DYLD_INFO_ONLY    (0x22 | R_MACHO_LC_REQ_DYLD) /* compressed dyld information only */
#define R_MACHO_LC_LOAD_UPWARD_DYLIB (0x23 | R_MACHO_LC_REQ_DYLD) /* load upward dylib */
#define R_MACHO_LC_VERSION_MIN_MACOSX 0x24 /* build for MacOSX min OS version */
#define R_MACHO_LC_VERSION_MIN_IPHONEOS 0x25 /* build for iPhoneOS min OS version */
#define R_MACHO_LC_FUNCTION_STARTS    0x26 /* compressed table of function start addresses */
#define R_MACHO_LC_DYLD_ENVIRONMENT   0x27 /* string for dyld to treat like environment variable */
#define R_MACHO_LC_MAIN              (0x28 | R_MACHO_LC_REQ_DYLD) /* replacement for LC_UNIXTHREAD */
#define R_MACHO_LC_DATA_IN_CODE       0x29 /* table of non-instructions in __text */
#define R_MACHO_LC_SOURCE_VERSION     0x2a /* source version used to build binary */
#define R_MACHO_LC_DYLIB_CODE_SIGN_DRS 0x2b /* Code signing DRs copied from linked dylibs */
#define R_MACHO_LC_ENCRYPTION_INFO_64 0x2c /* 64-bit encrypted segment information */
#define R_MACHO_LC_LINKER_OPTION      0x2d /* linker options in MH_OBJECT files */
#define R_MACHO_LC_LINKER_OPTIMIZATION_HINT 0x2e /* optimization hints in MH_OBJECT files */

typedef struct {
  ruint32 cmd;
  ruint32 cmdsize;
} RMachoLoadCmd;

R_API const rchar * r_macho_lc_str (ruint32 cmd);

#define R_MACHO_SEG_FLAG_HIGHVM   0x1
#define R_MACHO_SEG_FLAG_FVMLIB   0x2
#define R_MACHO_SEG_FLAG_NORELOC  0x4

#define R_MACHO_SEG_TEXT          "__TEXT"
#define R_MACHO_SEG_DATA          "__DATA"
#define R_MACHO_SEG_OBJC          "__OBJC"
#define R_MACHO_SEG_ICON          "__ICON"
#define R_MACHO_SEG_LINKEDIT      "__LINKEDIT"
#define R_MACHO_SEG_PAGEZERO      "__PAGEZERO"
#define R_MACHO_SEG_UNIXSTACK     "__UNIXSTACK"
#define R_MACHO_SEG_IMPORT        "__IMPORT"

/* R_MACHO_LC_SEGMENT */
typedef struct {
  RMachoLoadCmd lc;
  rchar   segname[16];
  ruint32 vmaddr;
  ruint32 vmsize;
  ruint32 fileoff;
  ruint32 filesize;
  ruint32 maxprot;
  ruint32 initprot;
  ruint32 nsects;
  ruint32 flags;
} RMachoSegment32Cmd;

/* R_MACHO_LC_SEGMENT_64 */
typedef struct {
  RMachoLoadCmd lc;
  rchar   segname[16];
  ruint64 vmaddr;
  ruint64 vmsize;
  ruint64 fileoff;
  ruint64 filesize;
  ruint32 maxprot;
  ruint32 initprot;
  ruint32 nsects;
  ruint32 flags;
} RMachoSegment64Cmd;

/* Section types (Least significant byte of flags) */
#define R_MACHO_SECTION_TYPE_REGULAR                              0x00
#define R_MACHO_SECTION_TYPE_ZEROFILL                             0x01
#define R_MACHO_SECTION_TYPE_CSTRING_LITERALS                     0x02
#define R_MACHO_SECTION_TYPE_4BYTE_LITERALS                       0x03
#define R_MACHO_SECTION_TYPE_8BYTE_LITERALS                       0x04
#define R_MACHO_SECTION_TYPE_LITERAL_POINTERS                     0x05
#define R_MACHO_SECTION_TYPE_NON_LAZY_SYMBOL_POINTERS             0x06
#define R_MACHO_SECTION_TYPE_LAZY_SYMBOL_POINTERS                 0x07
#define R_MACHO_SECTION_TYPE_SYMBOL_STUBS                         0x08
#define R_MACHO_SECTION_TYPE_MOD_INIT_FUNC_POINTERS               0x09
#define R_MACHO_SECTION_TYPE_MOD_TERM_FUNC_POINTERS               0x0a
#define R_MACHO_SECTION_TYPE_COALESCED                            0x0b
#define R_MACHO_SECTION_TYPE_GB_ZEROFILL                          0x0c
#define R_MACHO_SECTION_TYPE_INTERPOSING                          0x0d
#define R_MACHO_SECTION_TYPE_16BYTE_LITERALS                      0x0e
#define R_MACHO_SECTION_TYPE_DTRACE_DOF                           0x0f
#define R_MACHO_SECTION_TYPE_LAZY_DYLIB_SYMBOL_POINTERS           0x10
#define R_MACHO_SECTION_TYPE_THREAD_LOCAL_REGULAR                 0x11
#define R_MACHO_SECTION_TYPE_THREAD_LOCAL_ZEROFILL                0x12
#define R_MACHO_SECTION_TYPE_THREAD_LOCAL_VARIABLES               0x13
#define R_MACHO_SECTION_TYPE_THREAD_LOCAL_VARIABLE_POINTERS       0x14
#define R_MACHO_SECTION_TYPE_THREAD_LOCAL_INIT_FUNCTION_POINTERS  0x15


/* Section attributes */
#define R_MACHO_SECTION_ATTR_PURE_INSTRUCTIONS          0x80000000
#define R_MACHO_SECTION_ATTR_NO_TOC                     0x40000000
#define R_MACHO_SECTION_ATTR_STRIP_STATIC_SYMS          0x20000000
#define R_MACHO_SECTION_ATTR_NO_DEAD_STRIP              0x10000000
#define R_MACHO_SECTION_ATTR_LIVE_SUPPORT               0x08000000
#define R_MACHO_SECTION_ATTR_SELF_MODIFYING_CODE        0x04000000
#define R_MACHO_SECTION_ATTR_DEBUG                      0x02000000
#define R_MACHO_SECTION_ATTR_SOME_INSTRUCTIONS          0x00000400
#define R_MACHO_SECTION_ATTR_EXT_RELOC                  0x00000200
#define R_MACHO_SECTION_ATTR_LOC_RELOC                  0x00000100

typedef struct {
  rchar   sectname[16];
  rchar   segname[16];
  ruint32 addr;
  ruint32 size;
  ruint32 offset;
  ruint32 align;
  ruint32 reloff;
  ruint32 nreloc;
  ruint32 flags;
  ruint32 reserved1;
  ruint32 reserved2;
} RMachoSection32;

typedef struct {
  rchar   sectname[16];
  rchar   segname[16];
  ruint64 addr;
  ruint64 size;
  ruint32 offset;
  ruint32 align;
  ruint32 reloff;
  ruint32 nreloc;
  ruint32 flags;
  ruint32 reserved1;
  ruint32 reserved2;
  ruint32 reserved3;
} RMachoSection64;

/* R_MACHO_LC_IDFVMLIB, R_MACHO_LC_LOADFVMLIB */
/* Obsolete */
typedef struct {
  RMachoLoadCmd lc;
  RMachoStrOffset name;
  ruint32         minor_version;
  ruint32         header_addr;
} RMachoFVMLibCmd;

/* R_MACHO_LC_ID_DYLIB, R_MACHO_LC_LOAD_DYLIB, R_MACHO_LC_LOAD_WEAK_DYLIB,
 * R_MACHO_LC_REEXPORT_DYLIB */
typedef struct {
  RMachoLoadCmd lc;
  RMachoStrOffset name;
  ruint32         timestamp;
  ruint32         current_version;
  ruint32         compatibility_version;
} RMachoDyLibCmd;

/* R_MACHO_LC_SUB_FRAMEWORK */
typedef struct {
  RMachoLoadCmd lc;
  RMachoStrOffset umbrella;
} RMachoSubFrameworkCmd;

/* R_MACHO_LC_SUB_CLIENT */
typedef struct {
  RMachoLoadCmd lc;
  RMachoStrOffset client;
} RMachoSubClientCmd;

/* R_MACHO_LC_SUB_UMBRELLA */
typedef struct {
  RMachoLoadCmd lc;
  RMachoStrOffset sub_umbrella;
} RMachoSubUmbrellaCmd;

/* R_MACHO_LC_SUB_LIBRARY */
typedef struct {
  RMachoLoadCmd lc;
  RMachoStrOffset sub_library;
} RMachoSubLibraryCmd;

/* R_MACHO_LC_PREBOUND_DYLIB */
typedef struct {
  RMachoLoadCmd lc;
  RMachoStrOffset name;
  ruint32         nmodules;
  RMachoStrOffset linked_modules;
} RMachoPreboundDylibCmd;

/* R_MACHO_LC_ID_DYLINKER, R_MACHO_LC_LOAD_DYLINKER, R_MACHO_LC_DYLD_ENVIRONMENT */
typedef struct {
  RMachoLoadCmd lc;
  RMachoStrOffset name;
} RMachoDylinkerCmd;

/* R_MACHO_LC_UNIXTHREAD, R_MACHO_LC_THREAD */
typedef struct {
  RMachoLoadCmd lc;
  ruint32 flavor;
  ruint32 count;
  /* flavor specific */
} RMachoThreadCmd;

/* R_MACHO_LC_ROUTINES */
typedef struct {
  RMachoLoadCmd lc;
  ruint32 init_addr;
  ruint32 init_module; /* index into modules table */
  ruint32 reserved1;
  ruint32 reserved2;
  ruint32 reserved3;
  ruint32 reserved4;
  ruint32 reserved5;
  ruint32 reserved6;
} RMachoRoutines32Cmd;

/* R_MACHO_LC_ROUTINES_64 */
typedef struct {
  RMachoLoadCmd lc;
  ruint64 init_addr;
  ruint64 init_module; /* index into modules table */
  ruint64 reserved1;
  ruint64 reserved2;
  ruint64 reserved3;
  ruint64 reserved4;
  ruint64 reserved5;
  ruint64 reserved6;
} RMachoRoutines64Cmd;

/* R_MACHO_LC_SYMTAB */
typedef struct {
  RMachoLoadCmd lc;
  ruint32 symoff;
  ruint32 nsyms;
  ruint32 stroff;
  ruint32 strsize;
} RMachoSymTabCmd;

/* R_MACHO_LC_DYSYMTAB */
typedef struct {
  RMachoLoadCmd lc;
  ruint32 ilocalsym;  /* index to local symbols */
  ruint32 nlocalsym;  /* number of local symbols */
  ruint32 iextdefsym; /* index to externally defined symbols */
  ruint32 nextdefsym; /* number of externally defined symbols */
  ruint32 iundefsym;  /* index to undefined symbols */
  ruint32 nundefsym;  /* number of undefined symbols */
  ruint32 tocoff;     /* file offset to table of contents */
  ruint32 ntoc;       /* number of entries in table of contents */
  ruint32 modtaboff;  /* file offset to module table */
  ruint32 nmodtab;    /* number of module table entries */
  ruint32 extrefsymoff;   /* offset to referenced symbol table */
  ruint32 nextrefsyms;    /* number of referenced symbol table entries */
  ruint32 indirectsymoff; /* file offset to the indirect symbol table */
  ruint32 nindirectsyms;  /* number of indirect symbol table entries */
  ruint32 extreloff;      /* offset to external relocation entries */
  ruint32 nextrel;        /* number of external relocation entries */
  ruint32 locreloff;      /* offset to local relocation entries */
  ruint32 nlocrel;        /* number of local relocation entries */
} RMachoDySymTabCmd;

#define R_MACHO_INDIRECT_SYMBOL_LOCAL   0x80000000
#define R_MACHO_INDIRECT_SYMBOL_ABS     0x40000000

typedef struct {
  ruint32 symbol_index;
  ruint32 module_index;
} RMachoDylibTOC;


typedef struct {
  ruint32 module_name;  /* the module name (index into string table) */
  ruint32 iextdefsym;   /* index into externally defined symbols */
  ruint32 nextdefsym;   /* number of externally defined symbols */
  ruint32 irefsym;      /* index into reference symbol table */
  ruint32 nrefsym;      /* number of reference symbol table entries */
  ruint32 ilocalsym;    /* index into symbols for local symbols */
  ruint32 nlocalsym;    /* number of local symbols */
  ruint32 iextrel;      /* index into external relocation entries */
  ruint32 nextrel;      /* number of external relocation entries */
  ruint32 iinit_iterm;
  ruint32 ninit_nterm;
  ruint32 objc_module_info_addr;
  ruint32 objc_module_info_size;
} RMachoDylibModule32;

typedef struct {
  ruint32 module_name;  /* the module name (index into string table) */
  ruint32 iextdefsym;   /* index into externally defined symbols */
  ruint32 nextdefsym;   /* number of externally defined symbols */
  ruint32 irefsym;      /* index into reference symbol table */
  ruint32 nrefsym;      /* number of reference symbol table entries */
  ruint32 ilocalsym;    /* index into symbols for local symbols */
  ruint32 nlocalsym;    /* number of local symbols */
  ruint32 iextrel;      /* index into external relocation entries */
  ruint32 nextrel;      /* number of external relocation entries */
  ruint32 iinit_iterm;
  ruint32 ninit_nterm;
  ruint32 objc_module_info_addr;
  ruint64 objc_module_info_size;
} RMachoDylibModule64;

typedef struct {
  ruint32 isym:24,  /* index into the symbol table */
          flags:8;  /* flags to indicate the type of reference */
} RMachoDylibReference;

/* R_MACHO_LC_TWOLEVEL_HINTS */
typedef struct {
  RMachoLoadCmd lc;
  ruint32 offset;
  ruint32 nhints;
} RMachoTwoLevelHintsCmd;

typedef struct {
  ruint32 isub_image:8, /* index into the sub images */
          itoc:24;      /* index into the table of contents */
} RMachoTwoLevelHint;

/* R_MACHO_LC_PREBIND_CKSUM */
typedef struct {
  RMachoLoadCmd lc;
  ruint32 cksum;
} RMachoPrebindCksumCmd;

/* R_MACHO_LC_UUID */
typedef struct {
  RMachoLoadCmd lc;
  ruint8 uuid[16];
} RMachoUUIDCmd;

/* R_MACHO_LC_RPATH */
typedef struct {
  RMachoLoadCmd lc;
  RMachoStrOffset path;
} RMachoRPathCmd;

/* R_MACHO_LC_CODE_SIGNATURE, R_MACHO_LC_SEGMENT_SPLIT_INFO,
 * R_MACHO_LC_FUNCTION_STARTS, R_MACHO_LC_DATA_IN_CODE,
 * R_MACHO_LC_DYLIB_CODE_SIGN_DRS, R_MACHO_LC_LINKER_OPTIMIZATION_HINT */
typedef struct {
  RMachoLoadCmd lc;
  ruint32 dataoff;
  ruint32 datasize;
} RMachoLinkeditDataCmd;

/* R_MACHO_LC_ENCRYPTION_INFO */
typedef struct {
  RMachoLoadCmd lc;
  ruint32 cryptoff;
  ruint32 cryptsize;
  ruint32 cryptid;
} RMachoEncryptionInfo32Cmd;

/* R_MACHO_LC_ENCRYPTION_INFO_64 */
typedef struct {
  RMachoLoadCmd lc;
  ruint32 cryptoff;
  ruint32 cryptsize;
  ruint32 cryptid;
  ruint32 pad;
} RMachoEncryptionInfo64Cmd;

/* R_MACHO_LC_VERSION_MIN_MACOSX, R_MACHO_LC_VERSION_MIN_IPHONEOS */
typedef struct {
  RMachoLoadCmd lc;
  ruint32 version;
  ruint32 sdk;
} RMachoVersionMinCmd;

/* R_MACHO_LC_DYLD_INFO, R_MACHO_LC_DYLD_INFO_ONLY */
typedef struct {
  RMachoLoadCmd lc;
  ruint32 rebase_off;     /* file offset to rebase info */
  ruint32 rebase_size;    /* size of rebase info */
  ruint32 bind_off;       /* file offset to binding info */
  ruint32 bind_size;      /* size of binding info */
  ruint32 weak_bind_off;  /* file offset to weak binding info */
  ruint32 weak_bind_size; /* size of weak binding info */
  ruint32 lazy_bind_off;  /* file offset to lazy binding info */
  ruint32 lazy_bind_size; /* size of lazy binding infs */
  ruint32 export_off;     /* file offset to lazy binding info */
  ruint32 export_size;    /* size of lazy binding infs */
} RMachoDyldInfoCmd;

#define R_MACHO_REBASE_TYPE_POINTER                               1
#define R_MACHO_REBASE_TYPE_TEXT_ABSOLUTE32                       2
#define R_MACHO_REBASE_TYPE_TEXT_PCREL32                          3

#define R_MACHO_REBASE_OPCODE_MASK                                0xf0
#define R_MACHO_REBASE_IMMEDIATE_MASK                             0x0f
#define R_MACHO_REBASE_OPCODE_DONE                                0x00
#define R_MACHO_REBASE_OPCODE_SET_TYPE_IMM                        0x10
#define R_MACHO_REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB         0x20
#define R_MACHO_REBASE_OPCODE_ADD_ADDR_ULEB                       0x30
#define R_MACHO_REBASE_OPCODE_ADD_ADDR_IMM_SCALED                 0x40
#define R_MACHO_REBASE_OPCODE_DO_REBASE_IMM_TIMES                 0x50
#define R_MACHO_REBASE_OPCODE_DO_REBASE_ULEB_TIMES                0x60
#define R_MACHO_REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB             0x70
#define R_MACHO_REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB  0x80


#define R_MACHO_BIND_TYPE_POINTER                                 1
#define R_MACHO_BIND_TYPE_TEXT_ABSOLUTE32                         2
#define R_MACHO_BIND_TYPE_TEXT_PCREL32                            3

#define R_MACHO_BIND_SPECIAL_DYLIB_SELF                           0
#define R_MACHO_BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE                -1
#define R_MACHO_BIND_SPECIAL_DYLIB_FLAT_LOOKUP                    -2

#define R_MACHO_BIND_SYMBOL_FLAGS_WEAK_IMPORT                     0x1
#define R_MACHO_BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION             0x8

#define R_MACHO_BIND_OPCODE_MASK                                  0xf0
#define R_MACHO_BIND_IMMEDIATE_MASK                               0x0f
#define R_MACHO_BIND_OPCODE_DONE                                  0x00
#define R_MACHO_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM                 0x10
#define R_MACHO_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB                0x20
#define R_MACHO_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM                 0x30
#define R_MACHO_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM         0x40
#define R_MACHO_BIND_OPCODE_SET_TYPE_IMM                          0x50
#define R_MACHO_BIND_OPCODE_SET_ADDEND_SLEB                       0x60
#define R_MACHO_BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB           0x70
#define R_MACHO_BIND_OPCODE_ADD_ADDR_ULEB                         0x80
#define R_MACHO_BIND_OPCODE_DO_BIND                               0x90
#define R_MACHO_BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB                 0xa0
#define R_MACHO_BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED           0xb0
#define R_MACHO_BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB      0xc0


#define R_MACHO_EXPORT_SYMBOL_FLAGS_KIND_MASK                     0x03
#define R_MACHO_EXPORT_SYMBOL_FLAGS_KIND_REGULAR                  0x00
#define R_MACHO_EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL             0x01
#define R_MACHO_EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION               0x04
#define R_MACHO_EXPORT_SYMBOL_FLAGS_REEXPORT                      0x08
#define R_MACHO_EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER             0x10

/* R_MACHO_LC_LINKER_OPTION */
typedef struct {
  RMachoLoadCmd lc;
  ruint32 count;
} RMachoLinkerOptionCmd;

/* R_MACHO_LC_SYMSEG */
typedef struct {
  RMachoLoadCmd lc;
  ruint32 offset;
  ruint32 size;
} RMachoSymSegCmd;

/* R_MACHO_LC_IDENT */
typedef struct {
  RMachoLoadCmd lc;
} RMachoIdentCmd;

/* R_MACHO_LC_FVMFILE */
typedef struct {
  RMachoLoadCmd lc;
  RMachoStrOffset name;
  ruint32         header_addr;
} RMachoFVMFileCmd;

/* R_MACHO_LC_MAIN */
typedef struct {
  RMachoLoadCmd lc;
  ruint64 entryoff;
  ruint64 stacksize;
} RMachoEntryPointCmd;

/* R_MACHO_LC_SOURCE_VERSION */
typedef struct {
  RMachoLoadCmd lc;
  ruint64 version;
} RMachoSourceVersionCmd;


typedef struct {
  ruint32 offset;  /* from mach_header to start of data range*/
  ruint16 length;  /* number of bytes in data range */
  ruint16 kind;    /* a DICE_KIND_* value  */
} RDataInCodeEntry;

#define R_MACHO_DICE_KIND_DATA              0x0001
#define R_MACHO_DICE_KIND_JUMP_TABLE8       0x0002
#define R_MACHO_DICE_KIND_JUMP_TABLE16      0x0003
#define R_MACHO_DICE_KIND_JUMP_TABLE32      0x0004
#define R_MACHO_DICE_KIND_ABS_JUMP_TABLE32  0x0005

#pragma pack(pop)

R_END_DECLS

#endif /* __R_MACHO_H__ */

