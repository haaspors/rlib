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
#ifndef __R_DIR_TREE_H__
#define __R_DIR_TREE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/rref.h>

#define R_DIR_TREE_SEPARATOR '/'

R_BEGIN_DECLS

typedef struct _RDirTree RDirTree;
typedef struct _RDirTreeNode RDirTreeNode;

R_API RDirTree * r_dir_tree_new (void) R_ATTR_MALLOC;
#define r_dir_tree_ref    r_ref_ref
#define r_dir_tree_unref  r_ref_unref

R_API rsize r_dir_tree_node_count (const RDirTree * tree);

#define r_dir_tree_get_root(tree) r_dir_tree_get (tree, NULL, 0)
R_API RDirTreeNode * r_dir_tree_get (RDirTree * tree, const rchar * path, rssize size);
R_API RDirTreeNode * r_dir_tree_create (RDirTree * tree, const rchar * path, rssize size);
R_API RDirTreeNode * r_dir_tree_set (RDirTree * tree, const rchar * path, rssize size,
    rpointer data, RDestroyNotify notify) R_ATTR_WARN_UNUSED_RESULT;
#define r_dir_tree_clear_node(tree, path) r_dir_tree_set (tree, path, NULL, NULL)

R_API void r_dir_tree_remove_node_full (RDirTree * tree, RDirTreeNode * node);
#define r_dir_tree_remove_sub_tree(tree, path, size) \
  r_dir_tree_remove_node_full (tree, r_dir_tree_get (tree, path, size))
#define r_dir_tree_remove_all(tree) \
  r_dir_tree_remove_node_full (tree, r_dir_tree_get_root (tree))

R_API rpointer r_dir_tree_node_get (RDirTreeNode * node);
R_API rpointer r_dir_tree_node_set (RDirTreeNode * node,
    rpointer data, RDestroyNotify notify);
#define r_dir_tree_node_clear(node) r_dir_tree_node_set (node, NULL, NULL)
R_API RDirTreeNode * r_dir_tree_node_parent (RDirTreeNode * node);
R_API const rchar * r_dir_tree_node_name (RDirTreeNode * node);
R_API rchar * r_dir_tree_node_path (RDirTreeNode * node);

R_END_DECLS

#endif /* __R_DIR_TREE_H__ */


