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

/**
 * @defgroup r_dirtree Directory tree
 * @ingroup r_data
 *
 * @brief Refcounted tree keyed by slash-separated path components,
 * with per-node data and optional destroy / visit functions.
 *
 * Useful for any URL-routing / mount-point / configuration overlay
 * scenario where lookups happen by hierarchical path and the
 * caller cares about resolving partial matches (e.g.
 * @ref r_dir_tree_get_or_any_parent for parent-fallback).
 *
 * @{
 */

/**
 * @file rlib/data/rdirtree.h
 * @brief Path-component-keyed tree with per-node data slots.
 */

#include <rlib/rtypes.h>

#include <rlib/rref.h>

/** @brief Path component separator (@c '/'). */
#define R_DIR_TREE_SEPARATOR '/'

R_BEGIN_DECLS

/** @brief Opaque, refcounted directory tree. */
typedef struct RDirTree RDirTree;
/** @brief Opaque node inside an @ref RDirTree. */
typedef struct RDirTreeNode RDirTreeNode;

/** @brief Allocate an empty tree. */
R_API RDirTree * r_dir_tree_new (void) R_ATTR_MALLOC;
/** @brief Increment the tree's refcount. */
#define r_dir_tree_ref    r_ref_ref
/** @brief Decrement the tree's refcount; frees when it reaches zero. */
#define r_dir_tree_unref  r_ref_unref

/** @brief Total number of nodes in @p tree, including the root. */
R_API rsize r_dir_tree_node_count (const RDirTree * tree);

/** @brief Convenience: return the tree's root node. */
#define r_dir_tree_get_root(tree) r_dir_tree_get (tree, NULL, 0)
/**
 * @brief Look up the node at @p path; @c NULL if the path doesn't
 * exist yet.
 *
 * @param tree  The tree.
 * @param path  Slash-separated path (or @c NULL / empty for root).
 * @param size  Length of @p path, or @c -1 for NUL-terminated.
 */
R_API RDirTreeNode * r_dir_tree_get (RDirTree * tree, const rchar * path, rssize size);
/**
 * @brief Look up @p path; if it doesn't exist, return the deepest
 * existing ancestor.
 *
 * Used for parent-fallback routing patterns.
 */
R_API RDirTreeNode * r_dir_tree_get_or_any_parent (RDirTree * tree, const rchar * path, rssize size);
/**
 * @brief Materialise the node at @p path, creating ancestors as
 * needed; returns the leaf.
 */
R_API RDirTreeNode * r_dir_tree_create (RDirTree * tree, const rchar * path, rssize size);
/** @brief Convenience: @ref r_dir_tree_set_full with no visit function. */
#define r_dir_tree_set(tree, path, size, data, notify) \
  r_dir_tree_set_full (tree, path, size, data, notify, NULL)
/**
 * @brief Create the node at @p path (if needed) and attach
 * @p data with the supplied destroy notifier and optional
 * visit function.
 *
 * @param tree    The tree.
 * @param path    Slash-separated target path.
 * @param size    Length of @p path, or @c -1 for NUL-terminated.
 * @param data    Data pointer to attach.
 * @param notify  Destroy notifier for @p data, or @c NULL.
 * @param func    Visit function attached to the node; consulted by
 *                callers walking the tree, may be @c NULL.
 * @return The (possibly newly created) leaf node.
 */
R_API RDirTreeNode * r_dir_tree_set_full (RDirTree * tree, const rchar * path, rssize size,
    rpointer data, RDestroyNotify notify, RFunc func) R_ATTR_WARN_UNUSED_RESULT;
/** @brief Convenience: drop the data at @p path (destroy notifier runs). */
#define r_dir_tree_clear_node(tree, path) r_dir_tree_set (tree, path, NULL, NULL)

/**
 * @brief Remove @p node and every descendant; destroy notifiers run.
 *
 * The node pointer is invalid after this call.
 */
R_API void r_dir_tree_remove_node_full (RDirTree * tree, RDirTreeNode * node);
/** @brief Convenience: remove the sub-tree rooted at @p path. */
#define r_dir_tree_remove_sub_tree(tree, path, size) \
  r_dir_tree_remove_node_full (tree, r_dir_tree_get (tree, path, size))
/** @brief Convenience: remove every node (the tree itself remains valid). */
#define r_dir_tree_remove_all(tree) \
  r_dir_tree_remove_node_full (tree, r_dir_tree_get_root (tree))

/** @brief Read the data pointer attached to @p node. */
R_API rpointer r_dir_tree_node_get (RDirTreeNode * node);
/** @brief Convenience: @ref r_dir_tree_node_set_full with no visit function. */
#define r_dir_tree_node_set(node, data, notify) r_dir_tree_node_set_full (node, data, notify, NULL)
/**
 * @brief Attach @p data to @p node with optional destroy notifier
 * and visit function; returns the previous data pointer.
 */
R_API rpointer r_dir_tree_node_set_full (RDirTreeNode * node,
    rpointer data, RDestroyNotify notify, RFunc func);
/** @brief Convenience: clear @p node's data (destroy notifier runs). */
#define r_dir_tree_node_clear(node) r_dir_tree_node_set (node, NULL, NULL)
/** @brief Return @p node's visit function, or @c NULL. */
R_API RFunc r_dir_tree_node_func (const RDirTreeNode * node);
/** @brief Parent of @p node, or @c NULL at the root. */
R_API RDirTreeNode * r_dir_tree_node_parent (const RDirTreeNode * node);
/** @brief Last path component of @p node (no slashes). */
R_API const rchar * r_dir_tree_node_name (const RDirTreeNode * node);
/**
 * @brief Reconstruct @p node's full slash-separated path; caller
 * frees with @c r_free.
 */
R_API rchar * r_dir_tree_node_path (const RDirTreeNode * node);

R_END_DECLS

/** @} */

#endif /* __R_DIR_TREE_H__ */


