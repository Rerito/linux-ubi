/*
 * Copyright (c) International Business Machines Corp., 2006
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
 * the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * Author: Remi MARTY
 */

/*
 * This file contains the cryptographic key management features.
 * This includes the volume tree routines.
 */

#include "cryptokmgr.h"
#include <linux/delay.h>

#define BAD_PTR(ptr) ((NULL == (ptr)) || (IS_ERR((ptr))))

struct ubi_key_tree ubi_kmgr_ktree[UBI_MAX_DEVICES];


/* ######################################################################### */
/* ##################### STATIC FUNCTIONS DECLARATIONS ##################### */
/* ######################################################################### */

/*
 * To read these functions documentation, please report to
 * the beginning of their definitions.
 */

static struct ubi_key_entry *ubi_kmgr_alloc_kentry(__be32 vid,
		__u8 *k, size_t key_len,
		__u8 main);

static int ubi_kmgr_free_kentry(struct ubi_key_entry *kentry);

static struct ubi_key_entry *ubi_kmgr_find_kentry(struct ubi_key_tree *tree,
		__be32 vol_id);

static int ubi_kmgr_insert_kentry(struct ubi_key_tree *tree,
		struct ubi_key_entry *kentry);
static int ubi_kmgr_remove_kentry(struct ubi_key_tree *tree,
		struct ubi_key_entry *kentry);

static inline void ubi_kmgr_init_tree(struct ubi_key_tree *tree);
static void ubi_kmgr_clear_tree(struct ubi_key_tree *tree);

/* ######################################################################### */

/* ######################################################################### */
/* ########################  FUNCTIONS DEFINITIONS  ######################## */
/* ######################################################################### */


/**
 * ubi_kmgr_alloc_kentry - Allocate and store a new key entry
 * @vid: the volume id of the kentry
 * @k: a pointer towards the key
 * @key_len: the length of the key in bytes
 *
 * Return a pointer to the newly allocated key entry or an error pointer.
 * Possible errors are :
 * %ENOMEM : Memory allocation failed
 */
static struct ubi_key_entry *ubi_kmgr_alloc_kentry(__be32 vid,
		__u8 *k, size_t key_len,
		__u8 main)
{
	struct ubi_key_entry *kentry = NULL;
	struct ubi_key *key = NULL;
	int err = 0;
	if (NULL == (kentry = kzalloc(sizeof(*kentry), GFP_KERNEL))) {
		err = -ENOMEM;
		goto exit;
	}

	kentry->vol_id = vid;
	key = &kentry->cur;
	if (key_len && !BAD_PTR(k)) {
		if (NULL == (key->key = kzalloc(key_len, GFP_KERNEL))) {
			err = -ENOMEM;
			goto exit;
		}
		memcpy(key->key, k, key_len);
		key->key_len = key_len;
	} else {
		key->key = (IS_ERR(k)) ? k : NULL;
		key->key_len = 0;
	}
	mutex_init(&kentry->mutex);

	exit:
	if (err) {
		if (kentry) {
			if (!BAD_PTR(key)) {
				if (!BAD_PTR(key->key))
					kfree(key->key);
			}
			kfree(kentry);
		}
		kentry = ERR_PTR(err);
	}
	return kentry;
}

/**
 * ubi_kmgr_find_kentry - Find a key in a tree
 * @tree: the tree to look up
 * @vol_id: the requested volume id
 *
 * This function only reads the tree to find the requested kentry.
 * If the tree does not contain any entry for @vol_id, it returns %NULL,
 * otherwise it returns a pointer to the found entry.
 *
 * This function must be called with @tree's @sem hold in read mode.
 *
 * This function returns a pointer to the targeted key entry
 * or %NULL if it was not found in @tree.
 */
static struct ubi_key_entry *ubi_kmgr_find_kentry(struct ubi_key_tree *tree,
		__be32 vol_id)
{
	struct rb_root *r = NULL;
	struct rb_node *n = NULL;
	struct ubi_key_entry *kentry = NULL;

	r = &tree->root;
	n = r->rb_node;

	while (n) {
		kentry = rb_entry(n, struct ubi_key_entry, node);
		if (vol_id < kentry->vol_id) {
			n = n->rb_left;
		} else if (vol_id > kentry->vol_id) {
			n = n->rb_right;
		} else {
			return kentry;
		}
	}
	return NULL;
}

/** ubi_kmgr_get_kentry - Get a kentry from a tree
 * @tree: the tree to look up
 * @vol_id: the requested key's volume id
 *
 * This function finds the key for @vol_id in @tree, using
 * @ubi_kmgr_find_kentry. Then, if the kentry is sane (not @dying),
 * it increases its @in_use counter and returns it to the caller.
 *
 * The caller must then put the kentry back when it is done with it
 * through @ubi_kmgr_put_kentry.
 *
 * Returns a pointer to the targeted key entry or an error pointer.
 * The pointer can hold the following errors :
 * %ESHUTDOWN : @tree is not sane, and is about to be destroyed.
 *              Nothing must be read from or written to it.
 * %EACCES    : The targeted key entry is marked for deletion.
 *              Thus it is about to be removed from the tree.
 * %EINVAL    : @tree is not a valid pointer.
 */
struct ubi_key_entry *ubi_kmgr_get_kentry(struct ubi_key_tree *tree,
		__be32 vol_id)
{
	int err = 0;
	struct ubi_key_entry *kentry = NULL;
	if (unlikely(BAD_PTR(tree))) {
		return ERR_PTR(-EINVAL);
	}
	down_read(&tree->sem);
	if (tree->dying) {
		err = -ESHUTDOWN;
		goto exit;
	}
	kentry = ubi_kmgr_find_kentry(tree, vol_id);
	if (NULL != kentry) {
		mutex_lock(&kentry->mutex);
		if (kentry->dying) {
			err = -EACCES;
		} else {
			kentry->in_use++;
		}
		mutex_unlock(&kentry->mutex);
	}

	exit:
	up_read(&tree->sem);
	if (err) {
		return ERR_PTR(err);
	}
	return kentry;
}

/** ubi_kmgr_put_kentry - put back a used kentry
 * @kentry: the kentry to put back
 *
 * When the caller is done with the @kentry, it puts it back
 * using this function. The function releases the caller's reference
 * by decrementing the @kentry @in_use counter.
 */
void ubi_kmgr_put_kentry(struct ubi_key_entry *kentry)
{
	if(unlikely(BAD_PTR(kentry))) {
		return;
	}

	mutex_lock(&kentry->mutex);
	if (0 < kentry->in_use) {
		kentry->in_use--;
	}
	mutex_unlock(&kentry->mutex);
}

/**
 * ubi_kmgr_insert_kentry - Insert a key entry in a key tree
 * @tree: the host tree
 * @kentry: the key entry to insert
 *
 * This function tries to insert the given key entry into the
 * specified key tree.
 *
 * It returns %0 upon successful execution or a negative
 * error code otherwise. Possible errors :
 * %ESHUTDOWN : The tree is being cleaned and
 *              must not be used anymore.
 *              This should happen when the device that uses
 *              the tree is about to shut down.
 * %EEXIST    : There is already a key entry for the same volume ID
 *              (@vol_id field of @kentry) in @tree.
 * %EINVAL    : Invalid argument was supplied.
 *              (Bad @tree or @kentry pointer)
 */
static int ubi_kmgr_insert_kentry(struct ubi_key_tree *tree,
		struct ubi_key_entry *kentry)
{
	struct ubi_key_entry *k = NULL;
	struct rb_node **p = NULL, *parent = NULL;
	int err = 0;

	if (unlikely(IS_ERR(tree) ||
			IS_ERR(kentry) ||
			NULL == tree ||
			NULL == kentry)) {
		return -EINVAL;
	}

	if (tree->dying) {
		return -ESHUTDOWN;
	}
	p = &(tree->root.rb_node);
	while (*p) {
		parent = *p;
		k = rb_entry(parent, struct ubi_key_entry, node);
		if (k->vol_id > kentry->vol_id) {
			p = &((*p)->rb_left);
		}
		else if (k->vol_id < kentry->vol_id) {
			p = &((*p)->rb_right);
		} else {
			err = -EEXIST;
			break;
		}
	}

	if (!err) {
		rb_link_node(&kentry->node, parent, p);
		rb_insert_color(&kentry->node, &tree->root);
	}
	return err;
}

struct ubi_key *ubi_kmgr_get_mainkey(struct ubi_key_entry *kentry)
{
	if (BAD_PTR(kentry)) {
		return ERR_PTR(-EINVAL);
	}
	return &kentry->cur;
}

/**
 * ubi_kmgr_free_kentry - free an allocated key entry
 * @kentry: the key entry to free
 *
 * This functions frees the memory related to the given @kentry.
 * It marks it as @dying and then waits for its @in_use counter
 * to reach 0. All the resources are then freed.
 *
 * It returns %0 upon successful completion and a negative error
 * code otherwise. Possible errors are found below :
 * %EINVAL : @kentry is a bad pointer (%NULL or IS_ERR(kentry) is true)
 */
static int ubi_kmgr_free_kentry(struct ubi_key_entry *kentry)
{
	if (unlikely(BAD_PTR(kentry))) {
		return -EINVAL;
	}

	mutex_lock(&kentry->mutex);
	kentry->dying = 1;
	while (kentry->in_use) {
		mutex_unlock(&kentry->mutex);
		msleep(50);
		mutex_lock(&kentry->mutex);
	}
	if (kentry->cur.key) {
		kfree(kentry->cur.key);
		memset(&kentry->cur, 0,
				sizeof(kentry->cur));
	}
	mutex_unlock(&kentry->mutex);
	kfree(kentry);
	return 0;
}

/**
 * ubi_kmgr_remove_kentry - Remove a key from a tree
 * @tree: the tree that holds the key
 * @kentry: the key entry to remove
 *
 * This function removes a given key from the given tree.
 * @warning be sure to supply a good (@tree, @kentry) couple :
 * @kentry MUST be in @tree. When the key is removed from the tree,
 * it is then totally freed by @ubi_kmgr_free_kentry.
 */
static int ubi_kmgr_remove_kentry(struct ubi_key_tree *tree,
		struct ubi_key_entry *kentry)
{
	if (NULL == tree || IS_ERR(tree) || NULL == kentry || IS_ERR(kentry)) {
		return -EINVAL;
	}

	down_write(&tree->sem);
	rb_erase(&kentry->node, &tree->root);
	up_write(&tree->sem);

	return ubi_kmgr_free_kentry(kentry);
}

struct ubi_key *ubi_kmgr_get_leb_key(struct ubi_hmac_hdr *hmac_hdr,
		struct ubi_vid_hdr *vid_hdr, struct ubi_key_entry *kentry)
{
	u32 lnum;
	struct ubi_key *key = NULL;
	if (BAD_PTR(kentry) || BAD_PTR(vid_hdr)) {
		return ERR_PTR(-EINVAL);
	}
	lnum = be32_to_cpu(vid_hdr->lnum);
	key = &kentry->cur;
	return key;
}

/**
 * ubi_kmgr_vol_setkey - (Un)set the key for a given UBI volume
 * @tree: The key tree that will hold the key
 * @vol_id: The volume ID
 * @k: A pointer to the key value
 * @len: The length of the key
 * @main: Set to %0 if auxiliary key
 *        (used only if %CONFIG_UBI_CRYPTO_HMAC)
 * @vol: A pointer to the volume descriptor of
 *        the UBI device. Used by the update worker
 *        to recover the UBI data structures.
 *        (only with %CONFIG_UBI_CRYPTO_HMAC enabled)
 *
 * This function will set up the key according to the parameters.
 * If no kentry is found for @vol_id in @tree, then a new one is allocated
 * and filled with the required information.
 * Otherwise, some extra checkings must be done
 *
 * Note that if some data has been written to the volume before a key is set,
 * no update will be performed on the first key set up.
 *
 * If the caller provide a NULL @k pointer or a @len value lesser
 * or equal than %0, the function will unset the key.
 *
 * @warning If the HMAC support is disabled,
 * the module has no way to state if a key is good or not.
 * Therefore, any key will always be marked as @bad.
 * The volume key update process is then never triggered.
 *
 * When the function succeeds, it returns 0.
 * Some errors can occur that are associated to a specific
 * negative value :
 * %EINVAL    : Bad @tree pointer or @k is NULL.
 *              %EINVAL is also returned when trying
 *              to remove a non-existing key from @tree.
 * %ESHUTDOWN : see @ubi_kmgr_insert_kentry. This error
 *              is returned if @tree is marked as being
 *              destroyed, which happens when the device
 *              is about to shut down.
 * %EACCES    : @tree is still sane but the key entry
 *              that should be updated by the call to
 *              @ubi_kmgr_vol_setkey is marked as @dying.
 *              This means the key entry is about to be
 *              destroyed.
 *
 * %EBUSY     : The key entry that must be updated by
 *              the current call is currently being used.
 *              (either by an update work : @upd != 0,
 *               or by external user @in_use > 0)
 */
int ubi_kmgr_vol_setkey(struct ubi_key_tree *tree,
		__be32 vol_id, __u8 *k, unsigned int len,
		__u8 main, void *vol)
{
	struct ubi_key_entry *kentry = NULL;
	int err = 0;
	if (unlikely(BAD_PTR(tree) || IS_ERR(k))) {
		return -EINVAL;
	}

	kentry = ubi_kmgr_get_kentry(tree, vol_id);
	if (NULL == kentry) {
		if (NULL == k || 0 == len) {
			return -EINVAL;
		}
		kentry = ubi_kmgr_alloc_kentry(vol_id, k, len, main);
		if (IS_ERR(kentry)) {
			return PTR_ERR(kentry);
		}
		down_write(&tree->sem);
		err = ubi_kmgr_insert_kentry(tree, kentry);
		if (err) {
			ubi_kmgr_free_kentry(kentry);
		}
		up_write(&tree->sem);
	} else if (IS_ERR(kentry)){
		return PTR_ERR(kentry);
	} else {
		// Update the current key
		mutex_lock(&kentry->mutex);
		if ((1 < kentry->in_use)) {
			err = -EBUSY;
		} else {
			if (NULL == k || 0 == len) {
				/* We want to unset the current key. */
				memset(&kentry->cur, 0, sizeof(kentry->cur));
			}
			else {
				if (NULL == (kentry->cur.key = kmalloc(len, GFP_KERNEL))) {
					mutex_unlock(&kentry->mutex);
					ubi_kmgr_put_kentry(kentry);
					ubi_kmgr_remove_kentry(tree, kentry);
					return -ENOMEM;
				} else {
					memcpy(kentry->cur.key, k, len);
					kentry->cur.key_len = len;
				}
			}
		}
		mutex_unlock(&kentry->mutex);
		ubi_kmgr_put_kentry(kentry);
	}

	return err;
}

/**
 * ubi_kmgr_ack_update - Acknowledge a key ring update
 * @kentry: The updated kentry
 *
 * When a new key is added to the key ring, the @upd field
 * of the kentry takes a non-zero value. Then, when looking
 * for a specific LEB key,
 *
 * @warning This function must be called with @kentry acquired using
 * @ubi_kmgr_get_kentry
 * Otherwise, race conditions may occur between this function and
 * @ubi_kmgr_remove_kentry that may lead to an Oops.
 */
void ubi_kmgr_ack_update(struct ubi_key_entry *kentry)
{
	if (likely(!BAD_PTR(kentry))) {
		mutex_lock(&kentry->mutex);
		kentry->upd = 0;
		mutex_unlock(&kentry->mutex);
	}
}

/**
 * ubi_kmgr_init_tree - initialize the given key tree
 * @tree: the tree to initialize
 */
static inline void ubi_kmgr_init_tree(struct ubi_key_tree *tree)
{
	tree->root = RB_ROOT;
	tree->dying = 0;
	init_rwsem(&tree->sem);
}

/**
 * ubi_kmgr_clear_tree - Release a tree's resources
 * @tree: the tree to clear
 *
 * This function removes all the kentries from the given tree.
 * For atomic key removal see @ubi_kmgr_remove_kentry
 * This function also marks @tree as @dying to prevent another thread
 * to allocate and insert new kentries into it.
 */
static void ubi_kmgr_clear_tree(struct ubi_key_tree *tree)
{
	struct ubi_key_entry *kentry;
	struct rb_node *node;

	if (NULL == tree || IS_ERR(tree)) {
		return;
	}
	down_write(&tree->sem);
	tree->dying = 1;
	up_write(&tree->sem);
	down_read(&tree->sem);
	while (NULL != (node = tree->root.rb_node)) {
		kentry = rb_entry(node, struct ubi_key_entry, node);
		up_read(&tree->sem);
		ubi_kmgr_remove_kentry(tree, kentry);
		down_read(&tree->sem);
	}
	up_read(&tree->sem);
}

/**
 * ubi_kmgr_get_tree - Get a ubi device key tree
 * @ubi_dev: the number of the targetted UBI device
 *
 * This function simply returns a reference to the
 * appropriate key tree for the given device.
 * The result should be put using @ubi_kmgr_put_tree
 * when it is not used any more by the caller.
 */
struct ubi_key_tree *ubi_kmgr_get_tree(int ubi_dev)
{
	if (0 > ubi_dev || UBI_MAX_DEVICES < ubi_dev) {
		return ERR_PTR(-EINVAL);
	}
	return &ubi_kmgr_ktree[ubi_dev];
}

/**
 * ubi_kmgr_put_tree - Put back a ubi key tree
 * @tree: the tree to put back
 *
 * This function releases a reference to the
 * given tree. This function is useless at the time
 * but in the future, someone might turn key tree
 * management from its current static implementation
 * to a dynamic one and it will then be needed.
 */
void ubi_kmgr_put_tree(struct ubi_key_tree *tree)
{
	/*
	 * Does nothing, here only if dynamic key tree
	 * handling was to be added.
	 */
}

void ubi_kmgr_init()
{
	int i = 0;
	for(; i < UBI_MAX_DEVICES; i++) {
		ubi_kmgr_init_tree(&ubi_kmgr_ktree[i]);
	}
}

void ubi_kmgr_term()
{
	int i = 0;
	for(; i < UBI_MAX_DEVICES; i++) {
		ubi_kmgr_clear_tree(&ubi_kmgr_ktree[i]);
	}
}
