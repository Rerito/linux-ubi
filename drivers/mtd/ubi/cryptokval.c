


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
	if (NULL == (e = kmalloc(sizeof(*e), GFP_KERNEL))) {
		return ERR_PTR(-ENOMEM);
	}
	e->node = node;
	return e;
}

static int ubi_kval_insert_no_ovlap(struct ubi_kval_tree *tree, u32 d, u32 u);

static int ubi_kval_insert_no_ovlap(struct ubi_kval_tree *tree, u32 d, u32 u)
{
	struct ubi_kval_node *node, *i;
	struct rb_node **p, *parent;
	*p = tree->root.rb_node;
	parent = *p;
	if (NULL == (kmalloc(sizeof(*node), GFP_KERNEL))) {
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

int ubi_kval_insert_unlocked(struct ubi_kval_tree *tree, u32 d, u32 u)
{
	int err = 0;
	struct ubi_kval_lookup_entry *entry, *tmp;
	struct ubi_kval_node *node = NULL;
	LIST_HEAD(lookup_list);
	LIST_HEAD(del_list);
	if (d > u) {
		return -EINVAL;
	}

	if (NULL != tree->root.rb_node) {
		node = rb_entry(tree->root.rb_node, struct ubi_kval_node, node);
		entry = ubi_kval_alloc_lu_entry(node);
		if (BAD_PTR(entry)) {
			err = PTR_ERR(entry);
			goto exit;
		}
		list_add(&entry->entry, &lookup_list);
	}
	while (!list_empty(lookup_list)) {
		/* Pop the head of @lookup_list */
		entry = lookup_list.next;
		list_del(&entry->entry);

		if ((u + 1 >= node->d) &&
				(d <= node->u + 1)) {
			/*
			 * The current node overlaps with the inserted interval
			 */
			u = max(node->u, u);
			d = min(node->d, d);
			if ((u == node->u) && (d == node->d)) {
				/*
				 * The requested interval is totally included
				 * In the current node interval :
				 * We have nothing to do ...
				 */
				kfree(entry);
				break;

			} else {
				/*
				 * We must trigger the current node for deletion.
				 */
				list_add(&entry->entry, &del_list);
			}
		}

		if (u > entry->node->u) {
			/*
			 * The upper bound of the inserted interval
			 * is higher than the current entry upper bound :
			 * There might be overlapping nodes in the right
			 * sub-tree so we must add the right child of the
			 * current node to the look up list.
			 */
			node = rb_entry(entry->node->node.rb_right,
					struct ubi_kval_node, node);
			tmp = ubi_kval_alloc_lu_entry(node);
			if (BAD_PTR(tmp)) {
				err = PTR_ERR(tmp);
				goto exit;
			}
			list_add(&tmp->entry, &lookup_list);
		}
		if (d < entry->node->d) {
			/*
			 * The lower bound of the current node
			 * is greater than the inserted interval
			 * lower bound : there might be overlapping nodes
			 * in the left sub-tree ...
			 */
			node = rb_entry(entry->node->node.rb_left,
					struct ubi_kval_node, node);
			tmp = ubi_kval_alloc_lu_entry(node);
			if (BAD_PTR(tmp)) {
				err = PTR_ERR(tmp);
				goto exit;
			}
			list_add(&tmp->entry, &lookup_list);
		}
	}

	list_for_each_entry_safe(entry, tmp, &del_list, entry) {
		rb_erase(&entry->node->node, &tree->root);
	}

	err = ubi_kval_insert_no_ovlap(tree, d, u);

	exit:
	list_for_each_entry_safe(entry, tmp, &lookup_list, entry) {
		list_del(&entry->entry);
		kfree(entry);
	}
	list_for_each_entry_safe(entry, tmp, &del_list, entry) {
		list_del(&entry->entry);
		kfree(entry);
	}
	return err;
}

int ubi_kval_insert(struct ubi_kval_tree *tree, u32 d, u32 u)
{
	int err = 0;
	if (BAD_PTR(tree)) {
		return -EINVAL;
	}
	down_write(&tree->sem);
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
	struct rb_node *n;
	struct ubi_kval_node *node;
	struct ubi_kval_lookup_entry *e, *tmp;
	LIST_HEAD(del_list);
	LIST_HEAD(lu_list);

	if (BAD_PTR(tree)) {
		return -EINVAL;
	}

	down_write(&tree->sem);
	if (NULL == tree->root.rb_node) {
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
		e = container_of(
				lu_list.next,
				struct ubi_kval_lookup_entry,
				entry);
		node = e->node;

		if ((d <= node->u) &&
			(u >= node->d)) {
			/* Overlap ! */
			if ((u >= node->u) &&
				(d <= node->d)) {
				/* We must delete the current node */

			}
		}
	}

	exit:
	up_write(&tree->sem);
	list_for_each_entry_safe(e, tmp, &del_list, entry) {
		list_del(&e->entry);
		kfree(e);
	}
	list_for_each_entry_safe(e, tmp, &lu_list, entry) {
		list_del(&e->entry);
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
	if (BAD_PTR(tree)) {
		return -EINVAL;
	}
	p = tree->root.rb_node;
	while (NULL != p) {
		node = rb_entry(p, struct ubi_kval_node, node);
		if (node->d > x) {
			p = p->rb_left;
		} else if (node->u < x) {
			p = p->rb_right;
		}
		else
			return 1;
	}
	return 0;
}

int ubi_kval_init_tree(struct ubi_kval_tree *tree)
{
	if (BAD_PTR(tree)) {
		return -EINVAL;
	}
	tree->dying = 0;
	tree->root = RB_ROOT;
	init_rwsem(&tree->sem);
	return 0;
}
