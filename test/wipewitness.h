/* RLIB test helper: allocator hook that snapshots each freed buffer
 * before it reaches system free, so a test can scan the pile for a
 * sentinel byte sequence afterwards. Used to witness "did the
 * destructor wipe its secrets before r_free?" — if the wipe is in
 * place, the sentinel won't appear in the captured pile; if a
 * regression removes the wipe, the sentinel survives in the buffer
 * we copied out, and the test fails. */
#ifndef __R_TEST_WIPE_WITNESS_H__
#define __R_TEST_WIPE_WITNESS_H__

#include <rlib/rlib.h>
#include <stdlib.h>
#include <string.h>

#define R_WIPE_WITNESS_MAX_ALLOCS 4096
#define R_WIPE_WITNESS_MAX_FREED  (1024 * 1024)

typedef struct {
  rpointer ptr;
  rsize    size;
} r_wipe_witness_alloc;

static r_wipe_witness_alloc r_wipe_witness_live[R_WIPE_WITNESS_MAX_ALLOCS];
static rsize r_wipe_witness_live_count;
static ruint8 r_wipe_witness_freed[R_WIPE_WITNESS_MAX_FREED];
static rsize r_wipe_witness_freed_used;
static RMemVTable r_wipe_witness_saved_vtable;

static rpointer
r_wipe_witness_malloc (rsize sz)
{
  rpointer p = malloc (sz);
  if (p != NULL && r_wipe_witness_live_count < R_WIPE_WITNESS_MAX_ALLOCS) {
    r_wipe_witness_live[r_wipe_witness_live_count].ptr = p;
    r_wipe_witness_live[r_wipe_witness_live_count].size = sz;
    r_wipe_witness_live_count++;
  }
  return p;
}

static rpointer
r_wipe_witness_calloc (rsize n, rsize sz)
{
  rpointer p = calloc (n, sz);
  if (p != NULL && r_wipe_witness_live_count < R_WIPE_WITNESS_MAX_ALLOCS) {
    r_wipe_witness_live[r_wipe_witness_live_count].ptr = p;
    r_wipe_witness_live[r_wipe_witness_live_count].size = n * sz;
    r_wipe_witness_live_count++;
  }
  return p;
}

static rpointer
r_wipe_witness_realloc (rpointer p, rsize sz)
{
  rsize i;
  rpointer np = realloc (p, sz);
  for (i = 0; i < r_wipe_witness_live_count; i++) {
    if (r_wipe_witness_live[i].ptr == p) {
      r_wipe_witness_live[i].ptr = np;
      r_wipe_witness_live[i].size = sz;
      return np;
    }
  }
  if (np != NULL && r_wipe_witness_live_count < R_WIPE_WITNESS_MAX_ALLOCS) {
    r_wipe_witness_live[r_wipe_witness_live_count].ptr = np;
    r_wipe_witness_live[r_wipe_witness_live_count].size = sz;
    r_wipe_witness_live_count++;
  }
  return np;
}

static void
r_wipe_witness_free (rpointer p)
{
  rsize i;
  if (p == NULL) { free (p); return; }
  for (i = 0; i < r_wipe_witness_live_count; i++) {
    if (r_wipe_witness_live[i].ptr == p) {
      rsize sz = r_wipe_witness_live[i].size;
      if (r_wipe_witness_freed_used + sz <= R_WIPE_WITNESS_MAX_FREED) {
        memcpy (r_wipe_witness_freed + r_wipe_witness_freed_used, p, sz);
        r_wipe_witness_freed_used += sz;
      }
      r_wipe_witness_live[i] = r_wipe_witness_live[--r_wipe_witness_live_count];
      break;
    }
  }
  free (p);
}

static void
r_wipe_witness_install (void)
{
  RMemVTable v;
  r_wipe_witness_live_count = 0;
  r_wipe_witness_freed_used = 0;
  /* Snapshot the active vtable so uninstall restores the exact
   * pointers rlib was using - locally-typed { malloc, ... } would
   * pick up the test binary's import thunks, which differ from the
   * rlib DLL's on Windows and leave r_mem_using_system_default in
   * a perpetually-FALSE state. */
  r_mem_get_vtable (&r_wipe_witness_saved_vtable);
  v.malloc  = r_wipe_witness_malloc;
  v.calloc  = r_wipe_witness_calloc;
  v.realloc = r_wipe_witness_realloc;
  v.free    = r_wipe_witness_free;
  r_mem_set_vtable (&v);
}

static void
r_wipe_witness_uninstall (void)
{
  r_mem_set_vtable (&r_wipe_witness_saved_vtable);
}

static rboolean
r_wipe_witness_freed_contains (const ruint8 * needle, rsize needle_size)
{
  rsize i;
  if (needle_size == 0 || needle_size > r_wipe_witness_freed_used)
    return FALSE;
  for (i = 0; i + needle_size <= r_wipe_witness_freed_used; i++) {
    if (memcmp (r_wipe_witness_freed + i, needle, needle_size) == 0)
      return TRUE;
  }
  return FALSE;
}

#endif
