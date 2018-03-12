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
#include <rlib/binfmt/rpecoff.h>


RPeImageHdr *
r_pe_image_from_dos_header (const RPeDosHdr * dos)
{
  if (dos != NULL && dos->magic == R_PE_DOS_MAGIC) {
    RPeImageHdr * ret = (RPeImageHdr *)((const ruint8 *)dos + dos->lfanew);

    if (ret->magic == R_PE_IMAGE_MAGIC)
      return ret;
  }

  return NULL;
}

ruint16
r_pe_image_pe32_magic (rconstpointer mem)
{
  const RPeImageHdr * hdr;

  if ((hdr = r_pe_image_from_dos_header (mem)) != NULL) {
    const RPeOptHdr * opt = (const RPeOptHdr *)(hdr + 1);
    return opt->magic;
  }

  return 0;
}

rsize
r_pe_image_size (rconstpointer mem)
{
  const RPeImageHdr * hdr;

  if ((hdr = r_pe_image_from_dos_header (mem)) != NULL) {
    const RPeOptHdr * opt = (const RPeOptHdr *)(hdr + 1);

    if (opt->magic == R_PE_PE32_MAGIC)
      return ((const RPe32ImageHdr *)hdr)->winopt.size_image;
    else if (opt->magic == R_PE_PE32PLUS_MAGIC)
      return ((const RPe32PlusImageHdr *)hdr)->winopt.size_image;
  }

  return 0;
}

#if 0
rsize
r_pe_image_calc_size (rconstpointer mem)
{
}
#endif

const rchar *
r_pe_machine_str (ruint16 machine)
{
  switch (machine) {
    case R_PE_MACHINE_I386:
      return "x86";
    case R_PE_MACHINE_AMD64:
      return "AMD64 / x64";
    case R_PE_MACHINE_IA64:
      return "IA64";
    case R_PE_MACHINE_ARM64:
      return "AArch64";
    case R_PE_MACHINE_ARM:
      return "AArch32";
    case R_PE_MACHINE_ARMNT:
      return "AArch32 (thumb)";
    case R_PE_MACHINE_THUMB:
      return "Thumb";
    case R_PE_MACHINE_POWERPC:
      return "PowerPC";
    case R_PE_MACHINE_MIPSFPU:
      return "MIPS w/FPU";
    case R_PE_MACHINE_MIPSFPU16:
      return "MIPS16 w/FPU";
    case R_PE_MACHINE_R4000:
      return "MIPS";
    case R_PE_MACHINE_UNKNOWN:
    default:
      return "Unknown";
  }
}

