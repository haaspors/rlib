#include <rlib/rlib.h>


RTEST (rdirtree, set, RTEST_FAST)
{
  RDirTree * tree;

  r_assert_cmpptr ((tree = r_dir_tree_new ()), !=, NULL);

  r_assert_cmpuint (r_dir_tree_node_count (tree), ==, 1);
  r_assert_cmpptr (r_dir_tree_set (tree, "/foo/bar", -1, r_malloc0 (42), r_free), !=, NULL);
  r_assert_cmpuint (r_dir_tree_node_count (tree), ==, 1 + 2);

  r_dir_tree_unref (tree);
}
RTEST_END;

RTEST (rdirtree, get, RTEST_FAST)
{
  RDirTree * tree;
  RDirTreeNode * node;
  rchar * tmp;
  rpointer data;

  r_assert_cmpptr ((tree = r_dir_tree_new ()), !=, NULL);

  r_assert_cmpuint (r_dir_tree_node_count (tree), ==, 1);
  r_assert_cmpptr ((data = r_malloc0 (42)), !=, NULL);
  r_assert_cmpptr ((node = r_dir_tree_set (tree, "/foo/bar", -1, data, r_free)), !=, NULL);
  r_assert_cmpuint (r_dir_tree_node_count (tree), ==, 1 + 2);

  r_assert_cmpptr (r_dir_tree_node_parent (node), !=, NULL);
  r_assert_cmpstr (r_dir_tree_node_name (node), ==, "bar");
  r_assert_cmpstr ((tmp = r_dir_tree_node_path (node)), ==, "/foo/bar"); r_free (tmp);
  r_assert_cmpptr (r_dir_tree_node_get (node), ==, data);

  r_assert_cmpptr ((node = r_dir_tree_get_root (tree)), !=, NULL);
  r_assert_cmpptr (r_dir_tree_node_parent (node), ==, NULL);
  r_assert_cmpstr (r_dir_tree_node_name (node), ==, "");
  r_assert_cmpstr ((tmp = r_dir_tree_node_path (node)), ==, "/"); r_free (tmp);
  r_assert_cmpptr (r_dir_tree_node_get (node), ==, NULL);

  r_assert_cmpptr ((node = r_dir_tree_get (tree, "/foo", -1)), !=, NULL);
  r_assert_cmpstr (r_dir_tree_node_name (node), ==, "foo");
  r_assert_cmpptr (r_dir_tree_node_parent (node), !=, NULL);
  r_assert_cmpstr ((tmp = r_dir_tree_node_path (node)), ==, "/foo"); r_free (tmp);
  r_assert_cmpptr (r_dir_tree_node_get (node), ==, NULL);

  r_dir_tree_unref (tree);
}
RTEST_END;

