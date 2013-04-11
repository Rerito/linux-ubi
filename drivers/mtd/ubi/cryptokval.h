

#include <linux/rbtree.h>
#include <linux/rwsem.h>

struct ubi_kval_tree {
	struct rb_root root;
	struct rw_semaphore sem;
	u8 dying;
};

/**
 * ubi_kval_node - Interval tree node
 * @node: embedded red-black node
 * @d: least element of the integer segment
 * @u: greatest element of the integer segment
 * @u_max: the maximum of the greatest elements of the
 *         node siblings (including the current node)
 */
struct ubi_kval_node {
	struct rb_node node;
	u32 d, u, u_max;
};

int ubi_kval_init_tree(struct ubi_kval_tree *tree);

int ubi_kval_insert(struct ubi_kval_tree *tree, u32 d, u32 u);


