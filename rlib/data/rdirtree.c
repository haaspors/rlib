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

#include "config.h"
#include <rlib/data/rdirtree.h>

#include <rlib/data/rhashfuncs.h>
#include <rlib/data/rstring.h>

#include <rlib/rmem.h>
#include <rlib/rstr.h>

struct _RDirTreeNode {
  RDirTreeNode * parent;

  rsize chcount;
  rsize challoc;
  RDirTreeNode ** children;

  RFunc func;
  rpointer data;
  RDestroyNotify notify;

  rsize fullhash; /* Hash of full path */
  rchar name[0];   /* directory name */
};

struct _RDirTree {
  RRef ref;

  rsize nodes;
  RDirTreeNode root;
};


static RDirTreeNode * r_dir_tree_node_new (const rchar * name, rsize nsize) R_ATTR_MALLOC;


static void
r_dir_tree_free (RDirTree * tree)
{
  r_dir_tree_remove_all (tree);
  r_free (tree->root.children);
  r_free (tree);
}

RDirTree *
r_dir_tree_new (void)
{
  RDirTree * ret;

  if ((ret = r_malloc0 (sizeof (RDirTree) + 1)) != NULL) {
    r_ref_init (ret, r_dir_tree_free);

    ret->nodes = 1;
    ret->root.fullhash = r_str_hash (ret->root.name);
  }

  return ret;
}

rsize
r_dir_tree_node_count (const RDirTree * tree)
{
  return tree->nodes;
}

static RDirTreeNode *
r_dir_tree_add_node (RDirTree * tree, RDirTreeNode * node, RDirTreeNode * parent)
{
  if (node != NULL) {
    node->parent = parent;

    if (parent->challoc <= parent->chcount) {
      parent->challoc = MAX ((parent->challoc << 1), 8);

      parent->children = r_realloc (parent->children,
           parent->challoc * sizeof (RDirTreeNode *));
    }

    parent->children[parent->chcount++] = node;
    tree->nodes++;
  }

  return node;
}

static RDirTreeNode *
r_dir_tree_node_find_node (RDirTreeNode * node,
    rsize hash, const rchar * path, rsize psize, RDirTree * tree, rboolean exact)
{
  const rchar * next;
  rsize poff = 0, i, nsize;

  while (psize > 0 && path[psize - 1] == R_DIR_TREE_SEPARATOR) psize--;

  while (node != NULL && psize > poff) {
    if (node->fullhash == hash)
      break;

    while (psize > poff && path[poff] == R_DIR_TREE_SEPARATOR) poff++;
    if ((next = r_str_ptr_of_c (path + poff, psize - poff, R_DIR_TREE_SEPARATOR)) == NULL)
      next = path + psize;
    nsize = RPOINTER_TO_SIZE (next - path) - poff;

    for (i = 0; i < node->chcount; i++) {
      if (r_strncmp (node->children[i]->name, path + poff, nsize) == 0) {
        node = node->children[i];
        poff += nsize;
        break;
      }
    }

    if (i < node->chcount) {
      continue;
    } else if (tree != NULL) {
      node = r_dir_tree_add_node (tree,
          r_dir_tree_node_new (path + poff, nsize), node);
      poff += nsize;
    } else {
      if (exact)
        node = NULL;
      break;
    }
  }

  return node;
}

RDirTreeNode *
r_dir_tree_get (RDirTree * tree, const rchar * path, rssize size)
{
  rsize psize = (size < 0) ? r_strlen (path) : (rsize)size;
  return r_dir_tree_node_find_node (&tree->root,
      r_str_hash_sized (path, psize), path, psize, NULL, TRUE);
}

RDirTreeNode *
r_dir_tree_get_or_any_parent (RDirTree * tree, const rchar * path, rssize size)
{
  rsize psize = (size < 0) ? r_strlen (path) : (rsize)size;
  return r_dir_tree_node_find_node (&tree->root,
      r_str_hash_sized (path, psize), path, psize, NULL, FALSE);
}

RDirTreeNode *
r_dir_tree_create (RDirTree * tree, const rchar * path, rssize size)
{
  rsize psize = (size < 0) ? r_strlen (path) : (rsize)size;
  return r_dir_tree_node_find_node (&tree->root,
      r_str_hash_sized (path, psize), path, psize, tree, TRUE);
}

RDirTreeNode *
r_dir_tree_set_full (RDirTree * tree, const rchar * path, rssize size,
    rpointer data, RDestroyNotify notify, RFunc func)
{
  RDirTreeNode * ret = NULL;
  rsize psize = (size < 0) ? r_strlen (path) : (rsize)size;

  if ((ret = r_dir_tree_node_find_node (&tree->root,
      r_str_hash_sized (path, psize), path, psize, tree, TRUE)) != NULL) {
    r_dir_tree_node_set_full (ret, data, notify, func);
  }

  return ret;
}

static RDirTreeNode *
r_dir_tree_node_new (const rchar * name, rsize nsize)
{
  RDirTreeNode * ret;

  if ((ret = r_malloc0 (sizeof (RDirTreeNode) + nsize + 1)) != NULL) {
    r_memcpy (ret->name, name, nsize);
    ret->fullhash = r_str_hash (ret->name);
  }

  return ret;
}

static void
r_dir_tree_node_free (RDirTreeNode * node)
{
  if (node->notify)
    node->notify (node->data);
  r_free (node->children);
  r_free (node);
}

static void
r_dir_tree_destroy_node (RDirTree * tree, RDirTreeNode * node)
{
  rsize i;

  for (i = 0; i < node->chcount; i++)
    r_dir_tree_destroy_node (tree, node->children[i]);
  tree->nodes--;

  r_dir_tree_node_free (node);
}

void
r_dir_tree_remove_node_full (RDirTree * tree, RDirTreeNode * node)
{
  rsize i;

  if (R_UNLIKELY (node == NULL)) return;

  for (i = 0; i < node->chcount; i++)
    r_dir_tree_destroy_node (tree, node->children[i]);

  if (node != &tree->root) {
    for (i = 0; i < node->parent->chcount; i++) {
      if (node == node->parent->children[i]) {
        r_memmove (&node->parent->children[i], &node->parent->children[i + 1],
            (--node->parent->chcount - i) * sizeof (RDirTreeNode *));
        break;
      }
    }
    tree->nodes--;
    r_dir_tree_node_free (node);
  } else {
    tree->root.chcount = 0;
  }
}

rpointer
r_dir_tree_node_get (RDirTreeNode * node)
{
  return node->data;
}

rpointer
r_dir_tree_node_set_full (RDirTreeNode * node,
    rpointer data, RDestroyNotify notify, RFunc func)
{
  rpointer ret = node->data;

  if (node->notify != NULL)
    node->notify (node->data);
  node->notify = notify;
  node->data = data;
  node->func = func;

  return ret;
}

RFunc
r_dir_tree_node_func (const RDirTreeNode * node)
{
  return node->func;
}

RDirTreeNode *
r_dir_tree_node_parent (const RDirTreeNode * node)
{
  return node->parent;
}

const rchar *
r_dir_tree_node_name (const RDirTreeNode * node)
{
  return node->name;
}


static rsize
r_dir_tree_node_build_path (const RDirTreeNode * node, RString * str)
{
  rsize ret = 0; /* Lets hope the compiler uses a register! */

  if (node->parent != NULL) {
    ret += r_dir_tree_node_build_path (node->parent, str);
    ret += r_string_append_printf (str, "/%s", node->name);
  }

  return ret;
}

rchar *
r_dir_tree_node_path (const RDirTreeNode * node)
{
  RString * str = r_string_new_sized (64);

  if (r_dir_tree_node_build_path (node, str) == 0)
    r_string_append_printf (str, "/");

  return r_string_free_keep (str);
}

