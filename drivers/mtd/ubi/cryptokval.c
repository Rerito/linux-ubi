

#include "cryptokval.h"
#include <linux/slab.h>

#define BAD_PTR(p) ((IS_ERR((p))) || (NULL == (p)))

struct ubi_kval_lookup_entry {
	struct list_head entry;
	struct ubi_kval_node *node;
};


static inline struct ubi_kval_lookup_entry*
ubi_kval_alloc_lu_entry(struct ubi_kval_node *node);

static inline struct ubi_kval_lookup_entry*
ubi_kval_alloc_lu_entry(struct ubi_kval_node *node)
{
	struct ubi_kval_lookup_entry *e = NULL;
	if (NULL == (e = kzalloc(sizeof(*e), GFP_KERNEL))) {
		return ERR_PTR(-ENOMEM);
	}
	e->node = node;
	return e;
}

static int ubi_kval_insert_no_ovlap(struct ubi_kval_tree *tree, u32 d, u32 u);
static int ubi_kval_insert_unlocked(struct ubi_kval_tree *tree, u32 d, u32 u);

/**
 * ubi_kval_insert_no_ovlap - Insert an interval
 * @tree: The target tree
 * @d: interval's lower bound
 * @u: interval's upper bound
 *
 * This function assumes that the requested interval
 * does not overflow with any of the intervals already
 * stored in the tree.
 * Thus, it simply locates the insertion position, and
 * inserts the requested interval into the tree.
 */
static int ubi_kval_insert_no_ovlap(struct ubi_kval_tree *tree, u32 d, u32 u)
{
	struct ubi_kval_node *node, *i;
	struct rb_node **p, *parent;
	p = &tree->root.rb_node;
	parent = *p;
	if (NULL == (node = kmalloc(sizeof(*node), GFP_KERNEL))) {
		return -ENOMEM;
	}
	node->d = d;
	node->u = u;
	while (*p) {
		parent = *p;
		i = rb_entry(parent, struct ubi_kval_node, node);
		if (d < i->d) {
			p = &((*p)->rb_left);
		} else {
			p = &((*p)->rb_right);
		}
	}

	rb_link_node(&node->node, parent, p);
	rb_insert_color(&node->node, &tree->root);
	return 0;
}


/**
 * ubi_kval_insert_unlocked - Insert an interval into a tree
 * @tree: the target tree
 * @d: the interval's lower bound
 * @u: the interval's upper bound
 *
 * This function scans the tree to find overlapping intervals.
 * When hitting an overlap, @d and @u are updated appropriately.
 * Obsolete nodes are marked as to be deleted. At the end of this
 * look up stage, the function deletes all the conflicting intervals
 * from the tree and then insert the updated requested interval using
 * @ubi_kval_insert_no_ovlap.
 *
 * This function does not acquire the semaphore of @tree,
 * therefore, the caller must ensure the call is surrounded
 * by appropriate locking.
 *
 * It also assumes @tree is a valid pointer.
 */
static int ubi_kval_insert_unlocked(struct ubi_kval_tree *tree, u32 d, u32 u)
{
	int err = 0, free_cur = 0;
	struct ubi_kval_lookup_entry *entry = NULL, *tmp = NULL, *e = NULL;
	struct ubi_kval_node *n = NULL;
	LIST_HEAD(lookup_list);
	LIST_HEAD(del_list);
	if (d > u) {
		return -EINVAL;
	}

	if (NULL != tree->root.rb_node) {
		n = rb_entry(tree->root.rb_node, struct ubi_kval_node, node);
		entry = ubi_kval_alloc_lu_entry(n);
		if (BAD_PTR(entry)) {
			err = PTR_ERR(entry);
			goto exit;
		}
		list_add(&entry->entry, &lookup_list);
	}
	while (!list_empty(&lookup_list)) {
		/* Pop the head of @lookup_list */
		entry = list_first_entry(&lookup_list,
				struct ubi_kval_lookup_entry, entry);
		list_del(&entry->entry);
		n = entry->node;
		free_cur = 1;
		if ((u + 1 >= n->d) &&
				(d <= n->u + 1)) {
			/*
			 * The current node overlaps with the inserted interval
			 */
			u = max(n->u, u);
			d = min(n->d, d);
			if ((u == n->u) && (d == n->d)) {
				/*
				 * The requested interval is totally included
				 * In the current node interval :
				 * We have nothing to do ...
				 */
				kfree(entry);
				goto exit;

			} else {
				/*
				 * We must trigger the current node for deletion.
				 */
				list_add(&entry->entry, &del_list);
				free_cur = 0;
			}
		}

		if (u > n->u) {
			/*
			 * The upper bound of the inserted interval
			 * is higher than the current entry upper bound :
			 * There might be overlapping nodes in the right
			 * sub-tree so we must add the right child of the
			 * current node to the look up list.
			 */
			if (!BAD_PTR(n->node.rb_right)) {
				tmp = ubi_kval_alloc_lu_entry(
					rb_entry(n->node.rb_right,
					struct ubi_kval_node, node));
				if (BAD_PTR(tmp)) {
					err = PTR_ERR(tmp);
					kfree(entry);
					goto exit;
				}
				list_add(&tmp->entry, &lookup_list);
			}
		}
		if (d < n->d) {
			/*
			 * The lower bound of the current node
			 * is greater than the inserted interval
			 * lower bound : there might be overlapping nodes
			 * in the left sub-tree ...
			 */
			if (!BAD_PTR(n->node.rb_left)) {
				tmp = ubi_kval_alloc_lu_entry(
					rb_entry(n->node.rb_left,
					struct ubi_kval_node, node));
				if (BAD_PTR(tmp)) {
					err = PTR_ERR(tmp);
					kfree(entry);
					goto exit;
				}
				list_add(&tmp->entry, &lookup_list);
			}
		}

		if (free_cur) {
			if (!BAD_PTR(entry)) {
				kfree(entry);
			}
			entry = NULL;
		}
	}

	list_for_each_entry_safe(e, tmp, &del_list, entry) {
		rb_erase(&e->node->node, &tree->root);
		kfree(e->node);
	}

	err = ubi_kval_insert_no_ovlap(tree, d, u);

	exit:
	list_for_each_entry_safe(e, tmp, &lookup_list, entry) {
		if (!BAD_PTR(e)) {
			kfree(e);
		}
	}
	list_for_each_entry_safe(e, tmp, &del_list, entry) {
		if (!BAD_PTR(e)) {
			kfree(e);
		}
	}
	return err;
}

/**
 * ubi_kval_insert - Insert an interval into the tree
 * @tree: the target tree
 * @d: interval's lower bound
 * @u: interval's upper bound
 *
 * Locks the tree and checks its sanity before
 * calling @ubi_kval_insert_unlocked to perform
 * the insertion.
 *
 * Possible errors:
 * %EINVAL : @tree is not a valid pointer or d > u
 * %EACCES : @tree is marked as @dying and thus
 *           no node should be inserted into it.
 */
int ubi_kval_insert(struct ubi_kval_tree *tree, u32 d, u32 u)
{
	int err = 0;
	if (BAD_PTR(tree)) {
		return -EINVAL;
	}
	down_write(&tree->sem);
	if (tree->dying) {
		up_write(&tree->sem);
		return -EACCES;
	}
	err = ubi_kval_insert_unlocked(tree, d, u);
	up_write(&tree->sem);
	return err;
}


/*
 * ubi_kval_remove - Remove an interval from the tree
 * @tree: The interval tree
 * @d: lower bound of the interval to remove
 * @u: upper bound of the interval to remove
 *
 * This function will remove all the elements of [|d,u|]
 * that are contained in the interval tree.
 */
int ubi_kval_remove(struct ubi_kval_tree *tree, u32 d, u32 u)
{
	int err = 0;
	u32 tmp_i = 0;
	struct rb_node *n;
	struct ubi_kval_node *node;
	struct ubi_kval_lookup_entry *e, *tmp;
	LIST_HEAD(del_list);
	LIST_HEAD(lu_list);

	if (BAD_PTR(tree) || d > u) {
		return -EINVAL;
	}

	down_write(&tree->sem);
	if (BAD_PTR(tree->root.rb_node)) {
		goto exit;
	}
	n = tree->root.rb_node;
	node = rb_entry(n, struct ubi_kval_node, node);
	e = ubi_kval_alloc_lu_entry(node);
	if (BAD_PTR(e)) {
		err = PTR_ERR(e);
		goto exit;
	}
	list_add(&e->entry, &lu_list);

	while (!list_empty(&lu_list)) {
		e = list_first_entry(
				&lu_list,
				struct ubi_kval_lookup_entry,
				entry);
		node = e->node;
		list_del(&e->entry);
		kfree(e);

		if (d < node->d) {
			if (!BAD_PTR(node->node.rb_left)) {
				tmp = ubi_kval_alloc_lu_entry(
						rb_entry(node->node.rb_left,
						struct ubi_kval_node, node));
				if (BAD_PTR(tmp)) {
					err = PTR_ERR(tmp);
					goto exit;
				}
				list_add(&tmp->entry, &lu_list);
			}
		}
		if (u > node->u) {
			if (!BAD_PTR(node->node.rb_right)) {
				tmp = ubi_kval_alloc_lu_entry(
						rb_entry(node->node.rb_right,
						struct ubi_kval_node, node));
				if (BAD_PTR(tmp)) {
					err = PTR_ERR(tmp);
					goto exit;
				}
				list_add(&tmp->entry, &lu_list);
			}
		}

		if ((d <= node->u) && (u >= node->d)) {
			/* Overlap ! */
			if ((u >= node->u) && (d <= node->d)) {
				/* We must delete the current node */
				rb_erase(&node->node, &tree->root);
				kfree(node);
			} else if ((u < node->u) && (d > node->d)) {
				/* We must delete the current node and add
				 * [node->d, d] and [node->u, u] nodes
				 */
				u32 d2 = node->d, u2 = node->u;
				rb_erase(&node->node, &tree->root);
				kfree(node);
				err = ubi_kval_insert_unlocked(tree, d2, d - 1);
				if (err) {
					printk("Error inserting \"leftover\""
							"node while removing [%u, %u] : %d",
							d, u, err);
					goto exit;
				}
				err = ubi_kval_insert_unlocked(tree, u + 1, u2);
				if (err) {
					printk("Error inserting \"leftover\""
							"node while removing [%u, %u] : %d",
							d, u, err);
					goto exit;
				}
			} else if ((d <= node->d) && (u >= node->d)) {
				tmp_i = u + 1;
				u = node->d;
				node->d = tmp_i;
			} else if ((d <= node->u) && (u >= node->u)) {
				tmp_i = d - 1;
				d = node->u;
				node->u = tmp_i;
			}
		}
	}

	exit:
	up_write(&tree->sem);
	list_for_each_entry_safe(e, tmp, &del_list, entry) {
		kfree(e);
	}
	list_for_each_entry_safe(e, tmp, &lu_list, entry) {
		kfree(e);
	}
	return err;
}

/**
 * ubi_kval_is_in_tree - Check if an integer is in the tree
 * @tree: the tree to look up
 * @x: the integer to find
 *
 * This function returns %1 if it finds @x in the tree,
 * which means that @x is in one of the intervals held
 * by @tree.
 * If the given integer is not found, the function returns
 * %0.
 *
 * Possible errors :
 * %EINVAL : The @tree pointer is invalid.
 */
int ubi_kval_is_in_tree(struct ubi_kval_tree *tree, u32 x)
{
	struct ubi_kval_node *node;
	struct rb_node *p;
	int ret = 0;
	if (BAD_PTR(tree)) {
		return -EINVAL;
	}
	down_read(&tree->sem);
	p = tree->root.rb_node;
	while (NULL != p) {
		node = rb_entry(p, struct ubi_kval_node, node);
		if (node->d > x) {
			p = p->rb_left;
		} else if (node->u < x) {
			p = p->rb_right;
		}
		else {
			ret = 1;
			break;
		}
	}
	up_read(&tree->sem);
	return ret;
}

struct ubi_kval_node *ubi_kval_get_rightmost(struct ubi_kval_tree *tree)
{
	struct rb_node *n = ERR_PTR(-ENODATA);
	struct ubi_kval_node *rmost = NULL;
	if (BAD_PTR(tree)) {
		return ERR_PTR(-EINVAL);
	}
	down_read(&tree->sem);
	if (tree->dying) {
		rmost = ERR_PTR(-EACCES);
		goto exit;
	}
	n = tree->root.rb_node;
	while (NULL != n) {
		rmost = rb_entry(n, struct ubi_kval_node, node);
		n = n->rb_right;
	}
	exit:
	up_read(&tree->sem);
	return rmost;
}

int ubi_kval_dump_tree(struct ubi_kval_tree *tree)
{
	int err = 0;
	struct ubi_kval_node *node = NULL;
	struct ubi_kval_lookup_entry *lu_entry = NULL, *next = NULL;
	LIST_HEAD(stack);
	if (BAD_PTR(tree)) {
		return -EINVAL;
	}
	printk("+----------------------+\n"
			"| Interval Tree Dump : |\n"
			"+----------------------+\n");
	if (!BAD_PTR(tree->root.rb_node)) {
		node = rb_entry(
			tree->root.rb_node,
			struct ubi_kval_node, node);
	}
	while (!list_empty(&stack) || !BAD_PTR(node)) {
		if (!BAD_PTR(node)) {
			lu_entry = ubi_kval_alloc_lu_entry(node);
			if (BAD_PTR(lu_entry)) {
				break;
			}
			list_add(&lu_entry->entry, &stack);
			if (!BAD_PTR(node->node.rb_left)) {
				node = rb_entry(
					node->node.rb_left,
					struct ubi_kval_node, node);
			} else {
				node = NULL;
			}
		} else if (!list_empty(&stack)){
			lu_entry = list_first_entry(&stack,
				struct ubi_kval_lookup_entry,
				entry);
			node = lu_entry->node;
			list_del(&lu_entry->entry);
			kfree(lu_entry);
			/* Dump node here */
			printk("[ %u , %u ]\n", node->d, node->u);
			if (!BAD_PTR(node->node.rb_right)) {
				node = rb_entry(
					node->node.rb_right,
					struct ubi_kval_node, node);
			} else {
				node = NULL;
			}
		}
	}
	/* Free remaining elements in stack here */
	list_for_each_entry_safe(lu_entry, next, &stack, entry) {
		kfree(lu_entry);
	}
	printk("========================\n\n");
	return err;
}

int ubi_kval_init_tree(struct ubi_kval_tree *tree)
{
	if (BAD_PTR(tree)) {
		return -EINVAL;
	}
	tree->root = RB_ROOT;
	tree->dying = 0;
	init_rwsem(&tree->sem);
	return 0;
}

void ubi_kval_clear_tree(struct ubi_kval_tree *tree)
{
	struct rb_node *n;
	struct ubi_kval_node *del;
	if (BAD_PTR(tree)) {
		return;
	}
	down_write(&tree->sem);
	tree->dying = 1;
	while (NULL != (n = tree->root.rb_node)) {
		rb_erase(n, &tree->root);
		del = rb_entry(n, struct ubi_kval_node, node);
		kfree(del);
	}
	up_write(&tree->sem);

}
