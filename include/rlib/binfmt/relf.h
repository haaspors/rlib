/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_ELF_H__
#define __R_ELF_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

R_BEGIN_DECLS

/* ELF header */
#define R_ELF_IDX_MAG0                0
#define R_ELF_IDX_MAG1                1
#define R_ELF_IDX_MAG2                2
#define R_ELF_IDX_MAG3                3
#define R_ELF_IDX_CLASS               4
#define R_ELF_IDX_DATA                5
#define R_ELF_IDX_VERSION             6
#define R_ELF_IDX_OSABI               7
#define R_ELF_IDX_ABIVERSION          8
#define R_ELF_IDX_PAD                 9
#define R_ELF_NIDENT                  16

#define R_ELF_MAG0                    0x7F
#define R_ELF_MAG1                    'E'
#define R_ELF_MAG2                    'L'
#define R_ELF_MAG3                    'F'
#define R_ELF_MAG                     "\177ELF"

#define R_ELF_CLASSNONE               0
#define R_ELF_CLASS32                 1
#define R_ELF_CLASS64                 2

#define R_ELF_DATANONE                0
#define R_ELF_DATA2LSB                1
#define R_ELF_DATA2MSB                2

#define R_ELF_VER_NONE                0
#define R_ELF_VER_CURRENT             1

#define R_ELF_OSABI_NONE              0
#define R_ELF_OSABI_SYSV              R_ELF_OSABI_NONE
#define R_ELF_OSABI_HPUX              1
#define R_ELF_OSABI_NETBSD            2
#define R_ELF_OSABI_LINUX             3
#define R_ELF_OSABI_SOLARIS           6
#define R_ELF_OSABI_AIX               7
#define R_ELF_OSABI_IRIX              8
#define R_ELF_OSABI_FREEBSD           9
#define R_ELF_OSABI_TRU64             10
#define R_ELF_OSABI_MODESTO           11
#define R_ELF_OSABI_OPENBSD           12
#define R_ELF_OSABI_OPENVMS           13
#define R_ELF_OSABI_NSK               14
#define R_ELF_OSABI_AROS              15
#define R_ELF_OSABI_ARM               97
#define R_ELF_OSABI_STANDALONE        255 /* embedded */


#define R_ELF_ETYPE_NONE              0
#define R_ELF_ETYPE_REL               1
#define R_ELF_ETYPE_EXEC              2
#define R_ELF_ETYPE_DYN               3
#define R_ELF_ETYPE_CORE              4
#define R_ELF_ETYPE_NUM               5
#define R_ELF_ETYPE_LOOS              0xfe00
#define R_ELF_ETYPE_LOSUNW            0xfeff
#define R_ELF_ETYPE_SUNWPSEUDO        0xfeff
#define R_ELF_ETYPE_HISUNW            0xfeff
#define R_ELF_ETYPE_HIOS              0xfeff
#define R_ELF_ETYPE_LOPROC            0xff00
#define R_ELF_ETYPE_HIPROC            0xffff


#define R_ELF_MACHINE_NONE            0
#define R_ELF_MACHINE_M32             1
#define R_ELF_MACHINE_SPARC           2
#define R_ELF_MACHINE_386             3
#define R_ELF_MACHINE_68K             4
#define R_ELF_MACHINE_88K             5
#define R_ELF_MACHINE_486             6
#define R_ELF_MACHINE_860             7
#define R_ELF_MACHINE_MIPS            8
#define R_ELF_MACHINE_S370            9
#define R_ELF_MACHINE_MIPS_RS3_LE     10
#define R_ELF_MACHINE_RS6000          11
#define R_ELF_MACHINE_PA_RISC         15
#define R_ELF_MACHINE_PARISC          R_ELF_MACHINE_PA_RISC
#define R_ELF_MACHINE_nCUBE           16
#define R_ELF_MACHINE_VPP500          17
#define R_ELF_MACHINE_SPARC32PLUS     18
#define R_ELF_MACHINE_960             19
#define R_ELF_MACHINE_PPC             20
#define R_ELF_MACHINE_PPC64           21
#define R_ELF_MACHINE_S390            22
#define R_ELF_MACHINE_V800            36
#define R_ELF_MACHINE_FR20            37
#define R_ELF_MACHINE_RH32            38
#define R_ELF_MACHINE_RCE             39
#define R_ELF_MACHINE_ARM             40
#define R_ELF_MACHINE_ALPHA           41
#define R_ELF_MACHINE_SH              42
#define R_ELF_MACHINE_SPARCV9         43
#define R_ELF_MACHINE_TRICORE         44
#define R_ELF_MACHINE_ARC             45
#define R_ELF_MACHINE_H8_300          46
#define R_ELF_MACHINE_H8_300H         47
#define R_ELF_MACHINE_H8S             48
#define R_ELF_MACHINE_H8_500          49
#define R_ELF_MACHINE_IA_64           50
#define R_ELF_MACHINE_MIPS_X          51
#define R_ELF_MACHINE_COLDFIRE        52
#define R_ELF_MACHINE_68HC12          53
#define R_ELF_MACHINE_MMA             54
#define R_ELF_MACHINE_PCP             55
#define R_ELF_MACHINE_NCPU            56
#define R_ELF_MACHINE_NDR1            57
#define R_ELF_MACHINE_STARCORE        58
#define R_ELF_MACHINE_ME16            59
#define R_ELF_MACHINE_ST100           60
#define R_ELF_MACHINE_TINYJ           61
#define R_ELF_MACHINE_AMD64           62
#define R_ELF_MACHINE_X86_64          R_ELF_MACHINE_AMD64
#define R_ELF_MACHINE_PDSP            63
#define R_ELF_MACHINE_FX66            66
#define R_ELF_MACHINE_ST9PLUS         67
#define R_ELF_MACHINE_ST7             68
#define R_ELF_MACHINE_68HC16          69
#define R_ELF_MACHINE_68HC11          70
#define R_ELF_MACHINE_68HC08          71
#define R_ELF_MACHINE_68HC05          72
#define R_ELF_MACHINE_SVX             73
#define R_ELF_MACHINE_ST19            74
#define R_ELF_MACHINE_VAX             75
#define R_ELF_MACHINE_CRIS            76
#define R_ELF_MACHINE_JAVELIN         77
#define R_ELF_MACHINE_FIREPATH        78
#define R_ELF_MACHINE_ZSP             79
#define R_ELF_MACHINE_MMIX            80
#define R_ELF_MACHINE_HUANY           81
#define R_ELF_MACHINE_PRISM           82
#define R_ELF_MACHINE_AVR             83
#define R_ELF_MACHINE_FR30            84
#define R_ELF_MACHINE_D10V            85
#define R_ELF_MACHINE_D30V            86
#define R_ELF_MACHINE_V850            87
#define R_ELF_MACHINE_M32R            88
#define R_ELF_MACHINE_MN10300         89
#define R_ELF_MACHINE_MN10200         90
#define R_ELF_MACHINE_PJ              91
#define R_ELF_MACHINE_OPENRISC        92
#define R_ELF_MACHINE_ARC_A5          93
#define R_ELF_MACHINE_XTENSA          94
#define R_ELF_MACHINE_BLACKFIN        106
#define R_ELF_MACHINE_ALTERA_NIOS2    113
#define R_ELF_MACHINE_TI_C6000        140
#define R_ELF_MACHINE_AARCH64         183
#define R_ELF_MACHINE_TILEPRO         188
#define R_ELF_MACHINE_MICROBLAZE      189
#define R_ELF_MACHINE_TILEGX          191
#define R_ELF_MACHINE_FRV             0x5441
#define R_ELF_MACHINE_AVR32           0x18ad


typedef struct {
  ruint8  ident[R_ELF_NIDENT];
  ruint16 type;
  ruint16 machine;
  ruint32 version;
  ruint32 entry;
  ruint32 phoff;
  ruint32 shoff;
  ruint32 flags;
  ruint16 ehsize;
  ruint16 phentsize;
  ruint16 phnum;
  ruint16 shentsize;
  ruint16 shnum;
  ruint16 shstrndx;
} RElf32EHdr;

typedef struct {
  ruint8  ident[R_ELF_NIDENT];
  ruint16 type;
  ruint16 machine;
  ruint32 version;
  ruint64 entry;
  ruint64 phoff;
  ruint64 shoff;
  ruint32 flags;
  ruint16 ehsize;
  ruint16 phentsize;
  ruint16 phnum;
  ruint16 shentsize;
  ruint16 shnum;
  ruint16 shstrndx;
} RElf64EHdr;

/* Program header */
#define R_ELF_PTYPE_NULL              0
#define R_ELF_PTYPE_LOAD              1
#define R_ELF_PTYPE_DYNAMIC           2
#define R_ELF_PTYPE_INTERP            3
#define R_ELF_PTYPE_NOTE              4
#define R_ELF_PTYPE_SHLIB             5
#define R_ELF_PTYPE_PHDR              6
#define R_ELF_PTYPE_TLS               7
#define R_ELF_PTYPE_LOOS              0x60000000
#define R_ELF_PTYPE_SUNW_UNWIND       0x6464e550
#define R_ELF_PTYPE_GNU_EH_FRAME      R_ELF_PTYPE_SUNW_UNWIND
#define R_ELF_PTYPE_LOSUNW            0x6ffffffa
#define R_ELF_PTYPE_SUNWBSS           0x6ffffffa
#define R_ELF_PTYPE_SUNWSTACK         0x6ffffffb
#define R_ELF_PTYPE_SUNWDTRACE        0x6ffffffc
#define R_ELF_PTYPE_SUNWCAP           0x6ffffffd
#define R_ELF_PTYPE_HISUNW            0x6fffffff
#define R_ELF_PTYPE_HIOS              0x6fffffff
#define R_ELF_PTYPE_LOPROC            0x70000000
#define R_ELF_PTYPE_HIPROC            0x7fffffff

#define R_ELF_PFLAGS_X                0x1
#define R_ELF_PFLAGS_W                0x2
#define R_ELF_PFLAGS_R                0x4
#define R_ELF_PFLAGS_MASKOS           0x0ff00000
#define R_ELF_PFLAGS_MASKPROC         0xf0000000
#define R_ELF_PFLAGS_SUNW_FAILURE     0x00100000

typedef struct {
  ruint32 type;
  ruint32 offset;
  ruint32 vaddr;
  ruint32 paddr;
  ruint32 filesz;
  ruint32 memsz;
  ruint32 flags;
  ruint32 align;
} RElf32PHdr;

typedef struct {
  ruint32 type;
  ruint32 flags;
  ruint64 offset;
  ruint64 vaddr;
  ruint64 paddr;
  ruint64 filesz;
  ruint64 memsz;
  ruint64 align;
} RElf64PHdr;

/* Section header indices */
#define R_ELF_SHN_UNDEF               0
#define R_ELF_SHN_LORESERVE           0xff00
#define R_ELF_SHN_LOPROC              0xff00
#define R_ELF_SHN_BEFORE              0xff00
#define R_ELF_SHN_AFTER               0xff01
#define R_ELF_SHN_HIPROC              0xff1f
#define R_ELF_SHN_LOOS                0xff20
#define R_ELF_SHN_HIOS                0xff3f
#define R_ELF_SHN_ABS                 0xfff1
#define R_ELF_SHN_COMMON              0xfff2
#define R_ELF_SHN_XINDEX              0xffff
#define R_ELF_SHN_HIRESERVE           0xffff

/* Section header */
#define R_ELF_STYPE_NULL              0
#define R_ELF_STYPE_PROGBITS          1
#define R_ELF_STYPE_SYMTAB            2
#define R_ELF_STYPE_STRTAB            3
#define R_ELF_STYPE_RELA              4
#define R_ELF_STYPE_HASH              5
#define R_ELF_STYPE_DYNAMIC           6
#define R_ELF_STYPE_NOTE              7
#define R_ELF_STYPE_NOBITS            8
#define R_ELF_STYPE_REL               9
#define R_ELF_STYPE_SHLIB             10
#define R_ELF_STYPE_DYNSYM            11
#define R_ELF_STYPE_INIT_ARRAY        14
#define R_ELF_STYPE_FINI_ARRAY        15
#define R_ELF_STYPE_PREINIT_ARRAY     16
#define R_ELF_STYPE_GROUP             17
#define R_ELF_STYPE_SYMTAB_SHNDX      18
#define R_ELF_STYPE_LOOS              0x60000000
#define R_ELF_STYPE_LOSUNW            0x6ffffff1
#define R_ELF_STYPE_SUNW_symsort      0x6ffffff1
#define R_ELF_STYPE_SUNW_tlssort      0x6ffffff2
#define R_ELF_STYPE_SUNW_LDYNSYM      0x6ffffff3
#define R_ELF_STYPE_SUNW_dof          0x6ffffff4
#define R_ELF_STYPE_SUNW_cap          0x6ffffff5
#define R_ELF_STYPE_SUNW_SIGNATURE    0x6ffffff6
#define R_ELF_STYPE_SUNW_ANNOTATE     0x6ffffff7
#define R_ELF_STYPE_SUNW_DEBUGSTR     0x6ffffff8
#define R_ELF_STYPE_SUNW_DEBUG        0x6ffffff9
#define R_ELF_STYPE_SUNW_move         0x6ffffffa
#define R_ELF_STYPE_SUNW_COMDAT       0x6ffffffb
#define R_ELF_STYPE_SUNW_syminfo      0x6ffffffc
#define R_ELF_STYPE_SUNW_verdef       0x6ffffffd
#define R_ELF_STYPE_SUNW_verneed      0x6ffffffe
#define R_ELF_STYPE_SUNW_versym       0x6fffffff
#define R_ELF_STYPE_HISUNW            0x6fffffff
#define R_ELF_STYPE_HIOS              0x6fffffff
#define R_ELF_STYPE_GNU_verdef        0x6ffffffd
#define R_ELF_STYPE_GNU_verneed       0x6ffffffe
#define R_ELF_STYPE_GNU_versym        0x6fffffff
#define R_ELF_STYPE_LOPROC            0x70000000
#define R_ELF_STYPE_HIPROC            0x7fffffff
#define R_ELF_STYPE_LOUSER            0x80000000
#define R_ELF_STYPE_HIUSER            0xffffffff

#define R_ELF_SFLAGS_WRITE            0x01
#define R_ELF_SFLAGS_ALLOC            0x02
#define R_ELF_SFLAGS_EXECINSTR        0x04
#define R_ELF_SFLAGS_MERGE            0x10
#define R_ELF_SFLAGS_STRINGS          0x20
#define R_ELF_SFLAGS_INFO_LINK        0x40
#define R_ELF_SFLAGS_LINK_ORDER       0x80
#define R_ELF_SFLAGS_OS_NONCONFORMING 0x100
#define R_ELF_SFLAGS_GROUP            0x200
#define R_ELF_SFLAGS_TLS              0x400
#define R_ELF_SFLAGS_MASKOS           0x0ff00000
#define R_ELF_SFLAGS_MASKPROC         0xf0000000

typedef struct {
  ruint32 name;
  ruint32 type;
  ruint32 flags;
  ruint32 addr;
  ruint32 offset;
  ruint32 size;
  ruint32 link;
  ruint32 info;
  ruint32 addralign;
  ruint32 entsize;
} RElf32SHdr;

typedef struct {
  ruint32 name;
  ruint32 type;
  ruint64 flags;
  ruint64 addr;
  ruint64 offset;
  ruint64 size;
  ruint32 link;
  ruint32 info;
  ruint64 addralign;
  ruint64 entsize;
} RElf64SHdr;

/* Dynamic symbol */
typedef struct {
  rint32    tag;
  union {
    rint32  val;
    ruint32 ptr;
  } un;
} RElf32Dyn;

typedef struct {
  rint64    tag;
  union {
    rint64  val;
    ruint64 ptr;
  } un;
} RElf64Dyn;

/* Relocations */
#define R_ELF32_RELINFO_SYM(info)         ((info) >> 8)
#define R_ELF32_RELINFO_TYPE(info)        ((info) & 0xFF)
#define R_ELF32_RELINFO_CREATE(sym, type) (((sym) << 8) + ((type) & 0xFF))
#define R_ELF64_RELINFO_SYM(info)         ((info) >> 32)
#define R_ELF64_RELINFO_TYPE(info)        ((info) & 0xFFFFFFFF)
#define R_ELF64_RELINFO_CREATE(sym, type) (((sym) << 32) + ((type) & 0xFFFFFFFF))

#define R_ELF_RELTYPE_386_NONE                    0
#define R_ELF_RELTYPE_386_32                      1
#define R_ELF_RELTYPE_386_PC32                    2
#define R_ELF_RELTYPE_386_GOT32                   3
#define R_ELF_RELTYPE_386_PLT32                   4
#define R_ELF_RELTYPE_386_COPY                    5
#define R_ELF_RELTYPE_386_GLOB_DAT                6
#define R_ELF_RELTYPE_386_JUMP_SLOT               7
#define R_ELF_RELTYPE_386_RELATIVE                8
#define R_ELF_RELTYPE_386_GOTOFF                  9
#define R_ELF_RELTYPE_386_GOTPC                   10
#define R_ELF_RELTYPE_386_32PLT                   11
#define R_ELF_RELTYPE_386_TLS_TPOFF               14
#define R_ELF_RELTYPE_386_TLS_IE                  15
#define R_ELF_RELTYPE_386_TLS_GOTIE               16
#define R_ELF_RELTYPE_386_TLS_LE                  17
#define R_ELF_RELTYPE_386_TLS_GD                  18
#define R_ELF_RELTYPE_386_TLS_LDM                 19
#define R_ELF_RELTYPE_386_16                      20
#define R_ELF_RELTYPE_386_PC16                    21
#define R_ELF_RELTYPE_386_8                       22
#define R_ELF_RELTYPE_386_PC8                     23
#define R_ELF_RELTYPE_386_TLS_GD_32               24
#define R_ELF_RELTYPE_386_TLS_GD_PUSH             25
#define R_ELF_RELTYPE_386_TLS_GD_CALL             26
#define R_ELF_RELTYPE_386_TLS_GD_POP              27
#define R_ELF_RELTYPE_386_TLS_LDM_32              28
#define R_ELF_RELTYPE_386_TLS_LDM_PUSH            29
#define R_ELF_RELTYPE_386_TLS_LDM_CALL            30
#define R_ELF_RELTYPE_386_TLS_LDM_POP             31
#define R_ELF_RELTYPE_386_TLS_LDO_32              32
#define R_ELF_RELTYPE_386_TLS_IE_32               33
#define R_ELF_RELTYPE_386_TLS_LE_32               34
#define R_ELF_RELTYPE_386_TLS_DTPMOD32            35
#define R_ELF_RELTYPE_386_TLS_DTPOFF32            36
#define R_ELF_RELTYPE_386_TLS_TPOFF32             37
#define R_ELF_RELTYPE_386_TLS_GOTDESC             39
#define R_ELF_RELTYPE_386_TLS_DESC_CALL           40
#define R_ELF_RELTYPE_386_TLS_DESC                41
#define R_ELF_RELTYPE_386_IRELATIVE               42

#define R_ELF_RELTYPE_X86_64_NONE                 0
#define R_ELF_RELTYPE_X86_64_64                   1
#define R_ELF_RELTYPE_X86_64_PC32                 2
#define R_ELF_RELTYPE_X86_64_GOT32                3
#define R_ELF_RELTYPE_X86_64_PLT32                4
#define R_ELF_RELTYPE_X86_64_COPY                 5
#define R_ELF_RELTYPE_X86_64_GLOB_DAT             6
#define R_ELF_RELTYPE_X86_64_JUMP_SLOT            7
#define R_ELF_RELTYPE_X86_64_RELATIVE             8
#define R_ELF_RELTYPE_X86_64_GOTPCREL             9
#define R_ELF_RELTYPE_X86_64_32                   10
#define R_ELF_RELTYPE_X86_64_32S                  11
#define R_ELF_RELTYPE_X86_64_16                   12
#define R_ELF_RELTYPE_X86_64_PC16                 13
#define R_ELF_RELTYPE_X86_64_8                    14
#define R_ELF_RELTYPE_X86_64_PC8                  15
#define R_ELF_RELTYPE_X86_64_DTPMOD64             16
#define R_ELF_RELTYPE_X86_64_DTPOFF64             17
#define R_ELF_RELTYPE_X86_64_TPOFF64              18
#define R_ELF_RELTYPE_X86_64_TLSGD                19
#define R_ELF_RELTYPE_X86_64_TLSLD                20
#define R_ELF_RELTYPE_X86_64_DTPOFF32             21
#define R_ELF_RELTYPE_X86_64_GOTTPOFF             22
#define R_ELF_RELTYPE_X86_64_TPOFF32              23
#define R_ELF_RELTYPE_X86_64_PC64                 24
#define R_ELF_RELTYPE_X86_64_GOTOFF64             25
#define R_ELF_RELTYPE_X86_64_GOTPC32              26
#define R_ELF_RELTYPE_X86_64_GOT64                27
#define R_ELF_RELTYPE_X86_64_GOTPCREL64           28
#define R_ELF_RELTYPE_X86_64_GOTPC64              29
#define R_ELF_RELTYPE_X86_64_GOTPLT64             30
#define R_ELF_RELTYPE_X86_64_PLTOFF64             31
#define R_ELF_RELTYPE_X86_64_SIZE32               32
#define R_ELF_RELTYPE_X86_64_SIZE64               33
#define R_ELF_RELTYPE_X86_64_GOTPC32_TLSDESC      34
#define R_ELF_RELTYPE_X86_64_TLSDESC_CALL         35
#define R_ELF_RELTYPE_X86_64_TLSDESC              36
#define R_ELF_RELTYPE_X86_64_IRELATIVE            37

#define R_ELF_RELTYPE_ARM_NONE                    0x00
#define R_ELF_RELTYPE_ARM_PC24                    0x01
#define R_ELF_RELTYPE_ARM_ABS32                   0x02
#define R_ELF_RELTYPE_ARM_REL32                   0x03
#define R_ELF_RELTYPE_ARM_LDR_PC_G0               0x04
#define R_ELF_RELTYPE_ARM_ABS16                   0x05
#define R_ELF_RELTYPE_ARM_ABS12                   0x06
#define R_ELF_RELTYPE_ARM_THM_ABS5                0x07
#define R_ELF_RELTYPE_ARM_ABS8                    0x08
#define R_ELF_RELTYPE_ARM_SBREL32                 0x09
#define R_ELF_RELTYPE_ARM_THM_CALL                0x0a
#define R_ELF_RELTYPE_ARM_THM_PC8                 0x0b
#define R_ELF_RELTYPE_ARM_BREL_ADJ                0x0c
#define R_ELF_RELTYPE_ARM_TLS_DESC                0x0d
#define R_ELF_RELTYPE_ARM_THM_SWI8                0x0e
#define R_ELF_RELTYPE_ARM_XPC25                   0x0f
#define R_ELF_RELTYPE_ARM_THM_XPC22               0x10
#define R_ELF_RELTYPE_ARM_TLS_DTPMOD32            0x11
#define R_ELF_RELTYPE_ARM_TLS_DTPOFF32            0x12
#define R_ELF_RELTYPE_ARM_TLS_TPOFF32             0x13
#define R_ELF_RELTYPE_ARM_COPY                    0x14
#define R_ELF_RELTYPE_ARM_GLOB_DAT                0x15
#define R_ELF_RELTYPE_ARM_JUMP_SLOT               0x16
#define R_ELF_RELTYPE_ARM_RELATIVE                0x17
#define R_ELF_RELTYPE_ARM_GOTOFF32                0x18
#define R_ELF_RELTYPE_ARM_BASE_PREL               0x19
#define R_ELF_RELTYPE_ARM_GOT_BREL                0x1a
#define R_ELF_RELTYPE_ARM_PLT32                   0x1b
#define R_ELF_RELTYPE_ARM_CALL                    0x1c
#define R_ELF_RELTYPE_ARM_JUMP24                  0x1d
#define R_ELF_RELTYPE_ARM_THM_JUMP24              0x1e
#define R_ELF_RELTYPE_ARM_BASE_ABS                0x1f
#define R_ELF_RELTYPE_ARM_ALU_PCREL_7_0           0x20
#define R_ELF_RELTYPE_ARM_ALU_PCREL_15_8          0x21
#define R_ELF_RELTYPE_ARM_ALU_PCREL_23_15         0x22
#define R_ELF_RELTYPE_ARM_LDR_SBREL_11_0_NC       0x23
#define R_ELF_RELTYPE_ARM_ALU_SBREL_19_12_NC      0x24
#define R_ELF_RELTYPE_ARM_ALU_SBREL_27_20_CK      0x25
#define R_ELF_RELTYPE_ARM_TARGET1                 0x26
#define R_ELF_RELTYPE_ARM_SBREL31                 0x27
#define R_ELF_RELTYPE_ARM_V4BX                    0x28
#define R_ELF_RELTYPE_ARM_TARGET2                 0x29
#define R_ELF_RELTYPE_ARM_PREL31                  0x2a
#define R_ELF_RELTYPE_ARM_MOVW_ABS_NC             0x2b
#define R_ELF_RELTYPE_ARM_MOVT_ABS                0x2c
#define R_ELF_RELTYPE_ARM_MOVW_PREL_NC            0x2d
#define R_ELF_RELTYPE_ARM_MOVT_PREL               0x2e
#define R_ELF_RELTYPE_ARM_THM_MOVW_ABS_NC         0x2f
#define R_ELF_RELTYPE_ARM_THM_MOVT_ABS            0x30
#define R_ELF_RELTYPE_ARM_THM_MOVW_PREL_NC        0x31
#define R_ELF_RELTYPE_ARM_THM_MOVT_PREL           0x32
#define R_ELF_RELTYPE_ARM_THM_JUMP19              0x33
#define R_ELF_RELTYPE_ARM_THM_JUMP6               0x34
#define R_ELF_RELTYPE_ARM_THM_ALU_PREL_11_0       0x35
#define R_ELF_RELTYPE_ARM_THM_PC12                0x36
#define R_ELF_RELTYPE_ARM_ABS32_NOI               0x37
#define R_ELF_RELTYPE_ARM_REL32_NOI               0x38
#define R_ELF_RELTYPE_ARM_ALU_PC_G0_NC            0x39
#define R_ELF_RELTYPE_ARM_ALU_PC_G0               0x3a
#define R_ELF_RELTYPE_ARM_ALU_PC_G1_NC            0x3b
#define R_ELF_RELTYPE_ARM_ALU_PC_G1               0x3c
#define R_ELF_RELTYPE_ARM_ALU_PC_G2               0x3d
#define R_ELF_RELTYPE_ARM_LDR_PC_G1               0x3e
#define R_ELF_RELTYPE_ARM_LDR_PC_G2               0x3f
#define R_ELF_RELTYPE_ARM_LDRS_PC_G0              0x40
#define R_ELF_RELTYPE_ARM_LDRS_PC_G1              0x41
#define R_ELF_RELTYPE_ARM_LDRS_PC_G2              0x42
#define R_ELF_RELTYPE_ARM_LDC_PC_G0               0x43
#define R_ELF_RELTYPE_ARM_LDC_PC_G1               0x44
#define R_ELF_RELTYPE_ARM_LDC_PC_G2               0x45
#define R_ELF_RELTYPE_ARM_ALU_SB_G0_NC            0x46
#define R_ELF_RELTYPE_ARM_ALU_SB_G0               0x47
#define R_ELF_RELTYPE_ARM_ALU_SB_G1_NC            0x48
#define R_ELF_RELTYPE_ARM_ALU_SB_G1               0x49
#define R_ELF_RELTYPE_ARM_ALU_SB_G2               0x4a
#define R_ELF_RELTYPE_ARM_LDR_SB_G0               0x4b
#define R_ELF_RELTYPE_ARM_LDR_SB_G1               0x4c
#define R_ELF_RELTYPE_ARM_LDR_SB_G2               0x4d
#define R_ELF_RELTYPE_ARM_LDRS_SB_G0              0x4e
#define R_ELF_RELTYPE_ARM_LDRS_SB_G1              0x4f
#define R_ELF_RELTYPE_ARM_LDRS_SB_G2              0x50
#define R_ELF_RELTYPE_ARM_LDC_SB_G0               0x51
#define R_ELF_RELTYPE_ARM_LDC_SB_G1               0x52
#define R_ELF_RELTYPE_ARM_LDC_SB_G2               0x53
#define R_ELF_RELTYPE_ARM_MOVW_BREL_NC            0x54
#define R_ELF_RELTYPE_ARM_MOVT_BREL               0x55
#define R_ELF_RELTYPE_ARM_MOVW_BREL               0x56
#define R_ELF_RELTYPE_ARM_THM_MOVW_BREL_NC        0x57
#define R_ELF_RELTYPE_ARM_THM_MOVT_BREL           0x58
#define R_ELF_RELTYPE_ARM_THM_MOVW_BREL           0x59
#define R_ELF_RELTYPE_ARM_TLS_GOTDESC             0x5a
#define R_ELF_RELTYPE_ARM_TLS_CALL                0x5b
#define R_ELF_RELTYPE_ARM_TLS_DESCSEQ             0x5c
#define R_ELF_RELTYPE_ARM_THM_TLS_CALL            0x5d
#define R_ELF_RELTYPE_ARM_PLT32_ABS               0x5e
#define R_ELF_RELTYPE_ARM_GOT_ABS                 0x5f
#define R_ELF_RELTYPE_ARM_GOT_PREL                0x60
#define R_ELF_RELTYPE_ARM_GOT_BREL12              0x61
#define R_ELF_RELTYPE_ARM_GOTOFF12                0x62
#define R_ELF_RELTYPE_ARM_GOTRELAX                0x63
#define R_ELF_RELTYPE_ARM_GNU_VTENTRY             0x64
#define R_ELF_RELTYPE_ARM_GNU_VTINHERIT           0x65
#define R_ELF_RELTYPE_ARM_THM_JUMP11              0x66
#define R_ELF_RELTYPE_ARM_THM_JUMP8               0x67
#define R_ELF_RELTYPE_ARM_TLS_GD32                0x68
#define R_ELF_RELTYPE_ARM_TLS_LDM32               0x69
#define R_ELF_RELTYPE_ARM_TLS_LDO32               0x6a
#define R_ELF_RELTYPE_ARM_TLS_IE32                0x6b
#define R_ELF_RELTYPE_ARM_TLS_LE32                0x6c
#define R_ELF_RELTYPE_ARM_TLS_LDO12               0x6d
#define R_ELF_RELTYPE_ARM_TLS_LE12                0x6e
#define R_ELF_RELTYPE_ARM_TLS_IE12GP              0x6f
#define R_ELF_RELTYPE_ARM_PRIVATE_0               0x70
#define R_ELF_RELTYPE_ARM_PRIVATE_1               0x71
#define R_ELF_RELTYPE_ARM_PRIVATE_2               0x72
#define R_ELF_RELTYPE_ARM_PRIVATE_3               0x73
#define R_ELF_RELTYPE_ARM_PRIVATE_4               0x74
#define R_ELF_RELTYPE_ARM_PRIVATE_5               0x75
#define R_ELF_RELTYPE_ARM_PRIVATE_6               0x76
#define R_ELF_RELTYPE_ARM_PRIVATE_7               0x77
#define R_ELF_RELTYPE_ARM_PRIVATE_8               0x78
#define R_ELF_RELTYPE_ARM_PRIVATE_9               0x79
#define R_ELF_RELTYPE_ARM_PRIVATE_10              0x7a
#define R_ELF_RELTYPE_ARM_PRIVATE_11              0x7b
#define R_ELF_RELTYPE_ARM_PRIVATE_12              0x7c
#define R_ELF_RELTYPE_ARM_PRIVATE_13              0x7d
#define R_ELF_RELTYPE_ARM_PRIVATE_14              0x7e
#define R_ELF_RELTYPE_ARM_PRIVATE_15              0x7f
#define R_ELF_RELTYPE_ARM_ME_TOO                  0x80
#define R_ELF_RELTYPE_ARM_THM_TLS_DESCSEQ16       0x81
#define R_ELF_RELTYPE_ARM_THM_TLS_DESCSEQ32       0x82
#define R_ELF_RELTYPE_ARM_IRELATIVE               0xa0

typedef struct {
  ruint32 offset;
  ruint32 info;
} RElf32Rel;

typedef struct {
  ruint64 offset;
  ruint64 info;
} RElf64Rel;

typedef struct {
  ruint32 offset;
  ruint32 info;
  rint32  addend;
} RElf32Rela;

typedef struct {
  ruint64 offset;
  ruint64 info;
  rint64  addend;
} RElf64Rela;

/* Symbol table entries */
#define R_ELF_SYMINFO_BIND(info)          ((info) >> 4)
#define R_ELF_SYMINFO_TYPE(info)          ((info) & 0xF)
#define R_ELF_SYMINFO_CREATE(bind, type)  (((bind) << 4) + ((type) & 0xF))

#define R_ELF_SYMTYPE_NOTYPE              0
#define R_ELF_SYMTYPE_OBJECT              1
#define R_ELF_SYMTYPE_FUNC                2
#define R_ELF_SYMTYPE_SECTION             3
#define R_ELF_SYMTYPE_FILE                4
#define R_ELF_SYMTYPE_LOPROC              13
#define R_ELF_SYMTYPE_HIPROC              15

#define R_ELF_SYMBIND_LOCAL               0
#define R_ELF_SYMBIND_GLOBAL              1
#define R_ELF_SYMBIND_WEAK                2
#define R_ELF_SYMBIND_LOPROC              13
#define R_ELF_SYMBIND_HIPROC              15

#define R_ELF_SYMOTHER_DEFAULT            0
#define R_ELF_SYMOTHER_INTERNAL           1
#define R_ELF_SYMOTHER_HIDDEN             2
#define R_ELF_SYMOTHER_PROTECTED          3
#define R_ELF_SYMOTHER_OPTIONAL           4

typedef struct {
  ruint32 name;
  ruint32 value;
  ruint32 size;
  ruint8  info;
  ruint8  other;
  ruint16 shndx;
} RElf32Sym;

typedef struct {
  ruint32 name;
  ruint8  info;
  ruint8  other;
  ruint16 shndx;
  ruint64 value;
  ruint64 size;
} RElf64Sym;

/* Notes header */
#define R_ELF_NTYPE_PRSTATUS          1
#define R_ELF_NTYPE_PRFPREG           2
#define R_ELF_NTYPE_PRPSINFO          3
#define R_ELF_NTYPE_TASKSTRUCT        4
#define R_ELF_NTYPE_AUXV              6
#define R_ELF_NTYPE_SIGINFO           0x53494749
#define R_ELF_NTYPE_FILE              0x46494c45
#define R_ELF_NTYPE_PRXFPREG          0x46e62b7f
#define R_ELF_NTYPE_PPC_VMX           0x100
#define R_ELF_NTYPE_PPC_SPE           0x101
#define R_ELF_NTYPE_PPC_VSX           0x102
#define R_ELF_NTYPE_386_TLS           0x200
#define R_ELF_NTYPE_386_IOPERM        0x201
#define R_ELF_NTYPE_X86_XSTATE        0x202
#define R_ELF_NTYPE_S390_HIGH_GPRS    0x300
#define R_ELF_NTYPE_S390_TIMER        0x301
#define R_ELF_NTYPE_S390_TODCMP       0x302
#define R_ELF_NTYPE_S390_TODPREG      0x303
#define R_ELF_NTYPE_S390_CTRS         0x304
#define R_ELF_NTYPE_S390_PREFIX       0x305
#define R_ELF_NTYPE_S390_LAST_BREAK   0x306
#define R_ELF_NTYPE_S390_SYSTEM_CALL  0x307
#define R_ELF_NTYPE_S390_TDB          0x308
#define R_ELF_NTYPE_S390_VXRS_LOW     0x309
#define R_ELF_NTYPE_S390_VXRS_HIGH    0x30a
#define R_ELF_NTYPE_ARM_VFP           0x400
#define R_ELF_NTYPE_ARM_TLS           0x401
#define R_ELF_NTYPE_ARM_HW_BREAK      0x402
#define R_ELF_NTYPE_ARM_HW_WATCH      0x403
#define R_ELF_NTYPE_ARM_SYSTEM_CALL   0x404
#define R_ELF_NTYPE_METAG_CBUF        0x500
#define R_ELF_NTYPE_METAG_RPIPE       0x501
#define R_ELF_NTYPE_METAG_TLS         0x502

typedef struct {
  ruint32 namesz;
  ruint32 descsz;
  ruint32 type;
} RElf32NHdr;

typedef struct {
  ruint32 namesz;
  ruint32 descsz;
  ruint32 type;
} RElf64NHdr;

R_END_DECLS

#endif /* __R_ELF_H__ */

