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
#include "crypto.h"
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

#ifdef CONFIG_UBI_CRYPTO_HMAC
static inline struct ubi_key *ubi_kmgr_upd_key_refc(
		struct ubi_key *k, int inc);
static void ubi_kmgr_free_key(struct ubi_key *key);
static void ubi_kmgr_free_keyring(struct list_head *head);
static struct ubi_key *ubi_kmgr_probe_leb_key(struct ubi_hmac_hdr *hmac_hdr,
		struct ubi_vid_hdr *vid_hdr, int pnum,
		struct ubi_key_entry *kentry);
#endif // CONFIG_UBI_CRYPTO_HMAC
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


#ifdef CONFIG_UBI_CRYPTO_HMAC

static struct ubi_key *ubi_kmgr_alloc_key(__u8 *k, size_t len)
{
	struct ubi_key *key = NULL;
	int err = 0;
	if (NULL == (key = kzalloc(sizeof(*k), GFP_KERNEL))) {
		return ERR_PTR(-ENOMEM);
	}
	mutex_init(&key->mutex);
	ubi_kval_init_tree(&key->val_tree);
	key->key_len = len;
	if (len && !BAD_PTR(k)) {
		if (NULL == (key->key = kmalloc(len, GFP_KERNEL))) {
			err = -ENOMEM;
			goto exit;
		}
		memcpy(key->key, k, len);
	} else {
		key->key = k;
	}
	err = ubi_kval_init_tree(&key->val_tree);

	exit:
	if (err) {
		if (!BAD_PTR(key->key)) {
			kfree(key->key);
		}
		return ERR_PTR(err);
	}
	return key;
}

#endif // CONFIG_UBI_CRYPTO_HMAC


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
#ifdef CONFIG_UBI_CRYPTO_HMAC
	init_rwsem(&kentry->kr_sem);
	INIT_LIST_HEAD(&kentry->key_ring);
	key = ubi_kmgr_alloc_key(k, key_len);
	if (BAD_PTR(key)) {
		err = PTR_ERR(key);
		goto exit;
	}
	list_add(&key->entry, &kentry->key_ring);
	if (main) {
		kentry->main = key;
	}
	// FIXME : Prepare the update worker
#else
	key = &kentry->cur;
#endif // CONFIG_UBI_CRYPTO_HMAC
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
#ifdef CONFIG_UBI_CRYPTO_HMAC
				kfree(key);
#endif
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
#ifdef CONFIG_UBI_CRYPTO_HMAC
	struct ubi_key *k = NULL;
#endif // CONFIG_UBI_CRYPTO_HMAC
	if (BAD_PTR(kentry)) {
		return ERR_PTR(-EINVAL);
	}
#ifdef CONFIG_UBI_CRYPTO_HMAC
	down_read(&kentry->kr_sem);
	if (!BAD_PTR(kentry->main)) {
		ubi_kmgr_get_key(kentry->main);
		k = kentry->main;
	} else {
		k = ERR_PTR(-ENODATA);
	}
	up_read(&kentry->kr_sem);
	return k;
#else
	return &kentry->cur;
#endif // CONFIG_UBI_CRYPTO_HMAC
}


#ifdef CONFIG_UBI_CRYPTO_HMAC

static inline struct ubi_key *ubi_kmgr_upd_key_refc(struct ubi_key *k,
		int inc)
{
	if (!BAD_PTR(k)) {
		mutex_lock(&k->mutex);
		if (inc)
			k->refcount++;
		else if (k->refcount)
			k->refcount--;
		mutex_unlock(&k->mutex);
	}
	return k;
}

inline struct ubi_key *ubi_kmgr_get_key(struct ubi_key *k)
{
	return ubi_kmgr_upd_key_refc(k, 1);
}

inline struct ubi_key *ubi_kmgr_put_key(struct ubi_key *k)
{
	return ubi_kmgr_upd_key_refc(k, 0);
}

/**
 * ubi_kmgr_key_lookup - Look up for a specific key
 * @kentry: the key ring
 * @lookup: the lookup function
 * @private: additionnal data to feed to the lookup function.
 *
 * This function returns the first key in the key ring that matches
 * the given private data according the given look up function.
 * If no key match is found, the function returns %ENODATA
 *
 * It may also returns %EINVAL if @kentry is not a valid pointer
 */
struct ubi_key *ubi_kmgr_key_lookup(struct ubi_key_entry *kentry,
		ubi_kmgr_key_lu_func lookup, void *private)
{
	struct ubi_key *k = NULL;
	if (BAD_PTR(kentry)) {
		return ERR_PTR(-EINVAL);
	}
	down_read(&kentry->kr_sem);
	list_for_each_entry(k, &kentry->key_ring, entry) {
		ubi_kmgr_get_key(k);
		if (lookup(k, private)) {
			up_read(&kentry->kr_sem);
			return k;
		}
		ubi_kmgr_put_key(k);
	}
	up_read(&kentry->kr_sem);
	return ERR_PTR(-ENODATA);
}

static int ubi_kmgr_value_lookup(struct ubi_key *k, void *private)
{
	int i;
	struct ubi_key_value *val = private;
	if (BAD_PTR(val) || val->len != k->key_len) {
		return 0;
	}

	for (i=0; i < val->len; i++) {
		if (val->k[i] != k->key[i]) {
			return 0;
		}
	}
	return 1;
}

/**
 * ubi_kmgr_key_lu_by_value - Find a key given its value
 * @kentry: the key entry holding the ring
 * @raw_key: a pointer to the raw key value (bit string)
 * @len: the length of @raw_key in bytes
 *
 * This function simply returns the ubi_key object corresponding
 * to the given @raw_key key value. If there is no such key registered
 * in the ring, the function returns %ENODATA.
 */
struct ubi_key *ubi_kmgr_key_lu_by_value(struct ubi_key_entry *kentry,
		__u8 *raw_key, size_t len)
{
	struct ubi_key_value val = {.k = raw_key, .len = len};
	return ubi_kmgr_key_lookup(
			kentry, ubi_kmgr_value_lookup, &val);
}

/**
 * ubi_kmgr_free_key - Free a key
 * @key: the key to free
 *
 * This function waits for the refcount of the key to reach 0.
 * When no reference is held anywhere, the memory for the key is freed.
 * @key must not be contained in any key ring at this moment or
 * oops may occur.
 */
static void ubi_kmgr_free_key(struct ubi_key *key) {
	if (!BAD_PTR(key) && !BAD_PTR(key->key)) {
		mutex_lock(&key->mutex);
		while (key->refcount) {
			mutex_unlock(&key->mutex);
			msleep(50);
			mutex_lock(&key->mutex);
		}
		if (!BAD_PTR(key->key)) {
			kfree(key->key);
			key->key = NULL;
		}
		ubi_kval_clear_tree(&key->val_tree);
	}
}

/**
 * ubi_kmgr_free_keyring - Free a key ring
 * @head: The head of the key ring
 *
 * This function clears the given list of keys.
 * It must be called within appropriate locking protection.
 * In particular, the @kr_sem semaphore must be held in write mode
 * during this function.
 */
static void ubi_kmgr_free_keyring(struct list_head *head)
{
	struct ubi_key *key, *next;
	list_for_each_entry_safe (key, next, head, entry) {
		list_del(&key->entry);
		ubi_kmgr_free_key(key);
	}
}
#endif // CONFIG_UBI_CRYPTO_HMAC

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
#ifdef CONFIG_UBI_CRYPTO_HMAC
	/*
	 * We must clear the key ring
	 */
	down_write(&kentry->kr_sem);
	ubi_kmgr_free_keyring(&kentry->key_ring);
	up_write(&kentry->kr_sem);
#else
	if (kentry->cur.key) {
		kfree(kentry->cur.key);
		memset(&kentry->cur, 0,
				sizeof(kentry->cur));
	}
#endif // CONFIG_UBI_CRYPTO_HMAC
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

#ifdef CONFIG_UBI_CRYPTO_HMAC
static struct ubi_key *ubi_kmgr_probe_leb_key(struct ubi_hmac_hdr *hmac_hdr,
		struct ubi_vid_hdr *vid_hdr, int pnum,
		struct ubi_key_entry *kentry)
{
	struct ubi_key *key = NULL;
	u32 lnum = be32_to_cpu(vid_hdr->lnum);
	__u8 *hmac_tag = NULL;
	__be32 be_pnum = cpu_to_be32(pnum);
	struct ubi_crypto_unit *u = NULL;
	int err = -ENODATA;
	unsigned int comp_len = 0;
	if (BAD_PTR(hmac_hdr)) {
		err = -EINVAL;
		goto exit;
	}
	u = ubi_cru_acquire_unit(&ubi_cru_upool);
	if (BAD_PTR(u)) {
		printk("%s - Failed to acquire crypto unit from the pool : %ld\n", __func__, PTR_ERR(u));
		err = PTR_ERR(u);
		goto exit;
	}
	mutex_lock(&u->hmac.mutex);
	comp_len = crypto_hash_digestsize((struct crypto_hash*)u->hmac.tfm);
	comp_len = min(comp_len, sizeof(hmac_hdr->htag));
	mutex_unlock(&u->hmac.mutex);
	printk("%s - Comparison length for probing keys : %d\n", __func__, comp_len);

	list_for_each_entry(key, &kentry->key_ring, entry) {
		ubi_kmgr_get_key(key);
		hmac_tag = ubi_crypto_compute_hash(u, key, vid_hdr,
				be_pnum, NULL, 0);
		if (IS_ERR(hmac_tag)) {
			err = PTR_ERR(hmac_tag);
			ubi_kmgr_put_key(key);
			break;
		}

		if (!memcmp(hmac_tag, hmac_hdr->htag, comp_len)) {
			ubi_kval_insert(&key->val_tree, lnum, lnum);
			ubi_kval_remove(&kentry->unknown, lnum, lnum);
			err = 0;
			break;
		}
		kfree(hmac_tag);
		hmac_tag = NULL;
		ubi_kmgr_put_key(key);
	}

	exit:
	if (!BAD_PTR(u))
		ubi_cru_put_unit(u, &ubi_cru_upool);

	if (!BAD_PTR(hmac_tag))
		kfree(hmac_tag);

	if (err)
		return ERR_PTR(err);

	return key;
}

#endif // CONFIG_UBI_CRYPTO_HMAC

/**
 * ubi_kmgr_get_leb_key - Get the crypto key of a LEB
 * @hmac_hdr: The HMAC header of the LEB
 * @vid_hdr: The VID header of the LEB
 * @pnum: The PEB on which the LEB is written
 * @kentry: The volume key entry
 * @probe: Does the caller want to probe the key if unknown ?
 *
 * This function will look up the key ring of @kentry to find
 * the key that was used to encrypt the given LEB.
 * It first searches for the LEB number in the interval tree
 * of each key. If not found, depending on @probe, it will then
 * try to guess which key is used by trying to "open the door
 * with all the keys in the ring". Here opening the door means
 * compute the HMAC tag and compare it to the one in @hmac_hdr.
 */
struct ubi_key *ubi_kmgr_get_leb_key(struct ubi_hmac_hdr *hmac_hdr,
		struct ubi_vid_hdr *vid_hdr, int pnum,
		struct ubi_key_entry *kentry,
		int probe)
{
	u32 lnum;
	struct ubi_key *key = NULL;
	if (BAD_PTR(kentry) || BAD_PTR(vid_hdr)) {
		return ERR_PTR(-EINVAL);
	}
	lnum = be32_to_cpu(vid_hdr->lnum);
#ifdef CONFIG_UBI_CRYPTO_HMAC
	if (!kentry->tagged || NULL == hmac_hdr) {
		return ubi_kmgr_get_mainkey(kentry);
	}
	down_read(&kentry->kr_sem);
	list_for_each_entry(key, &kentry->key_ring, entry) {
		printk("%s - Checking key val tree :\n", __func__);
		if (ubi_kval_is_in_tree(&key->val_tree, lnum)) {
			up_read(&kentry->kr_sem);
			return key;
		}
	}

	printk("%s - Key ring checked, target not found ...\n"
			"Checking unknown LEB tree ...\n", __func__);

	if (probe) {
//		if (kentry->upd) {
//			ubi_kmgr_ack_update(kentry);
//			ubi_kval_clear_tree(&kentry->unknown);
//			kentry->unknown.dying = 0;
//		}
		printk("%s - The LEB is not registered in any key domain"
				"... Probing\n", __func__);
		key = ubi_kmgr_probe_leb_key(hmac_hdr, vid_hdr, pnum, kentry);
		if (BAD_PTR(key)) {
			ubi_kval_insert(&kentry->unknown, lnum, lnum);
		} else {
			ubi_kval_remove(&kentry->unknown, lnum, lnum);
			ubi_kval_insert(&key->val_tree, lnum, lnum);
		}
	} else {
		key = ERR_PTR(-ENODATA);
		ubi_kval_insert(&kentry->unknown, lnum, lnum);
	}
	up_read(&kentry->kr_sem);
#else
	key = &kentry->cur;
#endif // CONFIG_UBI_CRYPTO_HMAC
	return key;
}

/**
 * ubi_kmgr_setvolkey - (Un)set the key for a given UBI volume
 * @tree: The key tree that will hold the key
 * @req: A pointer to the information structure
 *
 * The @req structure contains several fields:
 * @vol_id: The volume ID
 *        (used only if %CONFIG_UBI_CRYPTO_HMAC)
 * @vol: A pointer to the volume descriptor of
 *        the UBI device. Used by the update worker
 *        to recover the UBI data structures.
 *        (only with %CONFIG_UBI_CRYPTO_HMAC enabled)
 * @tagged: Is the volume tagged with HMAC headers ?
 * @key: The pair (key, key length)
 * @main: Set to %0 if auxiliary key
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
 *
 * %EPERM     : The volume does not support HMAC headers but
 *              the user supplies an auxiliary key.
 *              Since no key checking can be performed,
 *              storing an auxiliary becomes pointless and
 *              @ubi_kmgr_setvolkey will automatically abort
 *              the execution and return this error.
 */
int ubi_kmgr_setvolkey(struct ubi_key_tree *tree,
		struct ubi_kmgr_set_vol_key_req *req)
{
	struct ubi_key_entry *kentry = NULL;
	__be32 vol_id;
	__u8 main;
	__u8 *k;
	size_t len;
	void *vol;
	struct ubi_key *key = NULL;
	int err = 0;
	k = req->key.k;
	len = req->key.len;
	if (unlikely(BAD_PTR(tree) || (BAD_PTR(k) && 0 != len))) {
		return -EINVAL;
	}
#ifdef CONFIG_UBI_CRYPTO_HMAC
	if (!req->tagged && !req->main) {
		/*
		 * If the volume is not tag and
		 * the key is an auxiliary key, since this volume
		 * does not support HMAC headers, we cannot establish
		 * key integrity and thus, we act like in the raw version.
		 *
		 * Hence there is no need to store any auxiliary key
		 * we return %EPERM to signal that this is pointless
		 */
		return -EPERM;
	}
#endif // CONFIG_UBI_CRYPTO_HMAC
	vol_id = req->vol_id;
	vol = req->vol;
	len = req->key.len;
	main = req->main;

	kentry = ubi_kmgr_get_kentry(tree, vol_id);
	if (NULL == kentry) {
		kentry = ubi_kmgr_alloc_kentry(vol_id, k, len, main);
		if (IS_ERR(kentry)) {
			return PTR_ERR(kentry);
		}
#ifdef CONFIG_UBI_CRYPTO_HMAC
		kentry->tagged = req->tagged;
#endif
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
#ifdef CONFIG_UBI_CRYPTO_HMAC
		/* If %UBI_CRYPTO_HMAC is enabled :
		 * We must see if the key is already in the key ring.
		 * If so, we simply update the "main" status of the key.
		 * If not, we add it and update the "main" key if needed.
		 *
		 * When the main key is changed, the update worker must
		 * be reset and start again from the beginning of the volume.
		 */
		if (vol != kentry->vol) {
			/*
			 * Error : Not valid volume descriptor.
			 */
		}
		if (req->tagged) {
			key = ubi_kmgr_key_lu_by_value(kentry, k, len);
			if (BAD_PTR(key)) {
				/* We must allocate a new key */
				key = ubi_kmgr_alloc_key(k, len);
				if (BAD_PTR(key)) {
					mutex_unlock(&kentry->mutex);
					ubi_kmgr_put_kentry(kentry);
					return PTR_ERR(key);
				}

				down_write(&kentry->kr_sem);
				list_add(&key->entry, &kentry->key_ring);
				up_write(&kentry->kr_sem);

			}

			if (main && (key != kentry->main)) {
				/* TODO :
				 * Update main status for the key
				 * trigger/reset update worker
				 */
			} else if (!main && (key == kentry->main)) {
				/*
				 * TODO : trigger/reset update worker
				 */
			}
			/* Else, nothing to do */
		} else {
			if (main) {
				/*
				 * We must replace the current key
				 * Since there is no HMAC tagging, we remove
				 * the key without any further checking.
				 *
				 * We act just like if %CONFIG_UBI_CRYPTO_HMAC
				 * was undefined.
				 *
				 * In this case, we can shortcut the usual path
				 * since there will be only one key in the ring
				 * -> kentry->main will always point to that key
				 */
				key = kentry->main;
				if (BAD_PTR(key)) {
					mutex_unlock(&kentry->mutex);
					ubi_kmgr_put_kentry(kentry);
					return -ENODATA;
				}
#else
		key = &kentry->cur;
#endif // CONFIG_UBI_CRYPTO_HMAC
		if ((1 < kentry->in_use)) {
			err = -EBUSY;
		} else {
			if (BAD_PTR(k) || 0 == len) {
				/* We want to unset the current key. */
				if(!BAD_PTR(key->key)) {
					kfree(key->key);
				}
				key->key = NULL;
				key->key_len = 0;
			}
			else {
				if (NULL ==
					(key->key = kmalloc(
							len, GFP_KERNEL))) {
					mutex_unlock(&kentry->mutex);
					ubi_kmgr_put_kentry(kentry);
					ubi_kmgr_remove_kentry(tree, kentry);
					return -ENOMEM;
				} else {
					memcpy(key->key, k, len);
					key->key_len = len;
				}
			}
		}
#ifdef CONFIG_UBI_CRYPTO_HMAC

			}
			/* Else we have nothing to do */
		}
#endif // CONFIG_UBI_CRYPTO_HMAC
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
