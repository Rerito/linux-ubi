
#ifndef _UBI_CRYPTO_KVAL_H_
#define _UBI_CRYPTO_KVAL_H_

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
 */
struct ubi_kval_node {
	struct rb_node node;
	u32 d, u;
};

int ubi_kval_init_tree(struct ubi_kval_tree *tree);
void ubi_kval_clear_tree(struct ubi_kval_tree *tree);

int ubi_kval_insert(struct ubi_kval_tree *tree, u32 d, u32 u);
int ubi_kval_remove(struct ubi_kval_tree *tree, u32 d, u32 u);
int ubi_kval_is_in_tree(struct ubi_kval_tree *tree, u32 x);
struct ubi_kval_node *ubi_kval_get_rightmost(struct ubi_kval_tree *tree);
int ubi_kval_insert(struct ubi_kval_tree *tree, u32 d, u32 u);
int ubi_kval_dump_tree(struct ubi_kval_tree *tree);

#endif // _UBI_CRYPTO_KVAL_H_





