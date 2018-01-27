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

#include "config.h"

#include <rlib/rmacho.h>

#include <rlib/rmem.h>
#include <rlib/rstr.h>

rchar *
r_macho_cpu_str (ruint32 cputype, ruint32 cpusubtype)
{
  switch (cputype) {
    case R_MACH_CPU_TYPE_X86_64:
      return r_strprintf ("x86-64 (AMD64) (sub: %x)", cpusubtype);
    case R_MACH_CPU_TYPE_I386:
      return r_strprintf ("x86 (sub: %x)", cpusubtype);
    case R_MACH_CPU_TYPE_ARM64:
      return r_strprintf ("AArch64 (sub: %x)", cpusubtype);
    case R_MACH_CPU_TYPE_ARM:
      return r_strprintf ("AArch32 (sub: %x)", cpusubtype);
    case R_MACH_CPU_TYPE_POWERPC64:
      return r_strprintf ("PowerPC64 (sub: %x)", cpusubtype);
    case R_MACH_CPU_TYPE_POWERPC:
      return r_strprintf ("PowerPC (sub: %x)", cpusubtype);
    case R_MACH_CPU_TYPE_SPARC:
      return r_strprintf ("SPARC (sub: %x)", cpusubtype);
    case R_MACH_CPU_TYPE_MIPS:
      return r_strprintf ("MIPS (sub: %x)", cpusubtype);
    default:
      return r_strprintf ("Unknown %x (sub: %x)", cputype, cpusubtype);
  }
}

const rchar *
r_macho_file_str (ruint32 filetype)
{
  static const rchar * ft[] = {
    "0 (unknown)",
    "Object",
    "Executable",
    "FvmLib",
    "Core",
    "Preload",
    "DyLib",
    "DyLinker",
    "Bundle",
  };

  if (filetype < R_N_ELEMENTS (ft))
    return ft[filetype];
  return "Unknown";
}

const rchar *
r_macho_lc_str (ruint32 cmd)
{
  static const rchar * lct[] = {
    "0 (unknown)",
    "Segment 32bit",
    "Symtab",
    "Symseg",
    "Thread",
    "UnixThread",
    "LoadFvmLib",
    "IdFvmLib",
    "Ident",
    "FvmFile",
    "PrePage",
    "DySymtab",
    "Load DyLib",
    "Id DyLib",
    "Load DyLinker",
    "Id DyLinker",
    "PreBound DyLib",
    "Routines",
    "Sub Framework",
    "Sub Umbrella",
    "Sub Client",
    "Sub Library",
    "TwoLevel Hints",
    "PreBind Cksum",
    "Load Weak DyLib",
    "Segment 64bit",
    "Routines 64bit",
    "UUID",
    "RPath",
    "Code Signature",
    "Segment Split Info",
    "ReExport DyLib",
  };

  cmd = cmd & ~R_MACHO_LC_REQ_DYLD;
  if (cmd < R_N_ELEMENTS (lct))
    return lct[cmd];
  return "Unknown";
}

