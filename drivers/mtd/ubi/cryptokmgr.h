
#ifndef _CRYPTO_KEY_MGR_H_
#define _CRYPTO_KEY_MGR_H_

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/rwsem.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include "ubi.h"

#ifdef CONFIG_UBI_CRYPTO_HMAC
#include "cryptokval.h"
struct ubi_volume;
#endif

/**
 * struct ubi_key_tree - A UBI device's key tree
 * @root: The root of the key tree
 * @sem: A R/W semaphore to protect the tree
 * @dying: Marker to state if the tree is sane
 *
 * When @dying is marked as true, the tree is not sane anymore
 * It becomes impossible to insert new keys into it.
 * Doing so will prevent a late call to
 * @ubi_kmgr_vol_setkey to be performed while the module is exiting,
 * as this should lead to memory leaks.
 */
struct ubi_key_tree {
	struct rb_root root;
	struct rw_semaphore sem;
	u8 dying;
};

/**
 * struct ubi_key
 * @key: the key value
 * @key_len: the length of the key (in bytes)
 * @entry: embedded list structure (for key ring)
 * @val_tree: validity tree
 * @obsolete: is this key obsolete ?
 *
 * The 3 last fields are only present if %UBI_CRYPTO_HMAC
 * is enabled. Multiple keys can coexist on the same volume
 * due to unclean reboots. With HMAC support turned on,
 * it is possible for UBI to check the validity of a given
 * key on a per-LEB basis.
 *
 * When the user sets up the key, he will be able to *add*
 * keys to the volume @key_ring.
 * UBI will then try to figure out which key must be applied
 * for the operation on a given LEB.
 *
 * A main key must be defined. UBI will run a background
 * thread to get rid of the secondary keys of the key ring by
 * scheduling LEB atomic re-writes.
 *
 * Each key has a validity domain (a set of doors it can open).
 * At first set up, this domain is unknown and thus the @val_tree
 * is empty. Each time UBI will figure out that a LEB is ciphered
 * using a particular key, it will add the corresponding LEB number
 * to the key validity tree.
 *
 * If @val_tree is empty and if there is no unknown LEB left,
 * the key is marked as obsolete and will be removed from the key ring.
 */
struct ubi_key {
	__u8 *key;
	size_t key_len;
#ifdef CONFIG_UBI_CRYPTO_HMAC
	__u32 refcount;
	struct list_head entry;
	struct ubi_kval_tree val_tree;
	__u8 obsolete;
	struct mutex mutex;
#endif // CONFIG_UBI_CRYPTO_HMAC
};

struct ubi_key_value {
	__u8 *k;
	size_t len;
};

/**
 * struct ubi_key_entry - Ciphered volume key entry
 * @node: Embedded rb_node structure to build the tree
 * @vol_id: Volume ID of the entry
 * @cur: key in use for the volume
 * @old: the previous key
 * @in_use: the number of running users for the kentry
 * @dying: a value that says if the key is being destroyed
 * @upd: update marker
 * @mutex: a mutex to protect the node
 * @tagged: are the volume LEBs HMAC tagged ?
 * @key_ring: list of the volume keys
 * @main: main key for the volume
 * @kr_sem: r/w semaphore to protect access to @key_ring
 * @unknown: the interval tree of unresolved LEB's
 * @upd_worker: the worker that performs main key updates
 * @cur: key in use for the volume
 */
struct ubi_key_entry {
	struct rb_node node;
	__be32 vol_id;
	__u32 in_use;
	__u8 dying, upd;
	struct mutex mutex;
#ifdef CONFIG_UBI_CRYPTO_HMAC
	__u8 tagged;
	struct ubi_volume *vol;
	struct list_head key_ring;
	struct ubi_key *main;
	struct rw_semaphore kr_sem;
	struct ubi_kval_tree unknown;
	__u32 reserved_ebs;
	struct work_struct upd_worker;
	__u8 reset_upd;
#else
	struct ubi_key cur;
#endif // CONFIG_UBI_CRYPTO_HMAC
};

struct ubi_kmgr_set_vol_key_req {
	__be32 vol_id;
	void *vol;
	u8 tagged;
	struct ubi_key_value key;
	u8 main;
};

extern struct ubi_key_tree ubi_kmgr_ktree[UBI_MAX_DEVICES];

#ifdef CONFIG_UBI_CRYPTO_HMAC
inline struct ubi_key *ubi_kmgr_get_key(struct ubi_key *k);
inline struct ubi_key *ubi_kmgr_put_key(struct ubi_key *k);

typedef int (*ubi_kmgr_key_lu_func)(struct ubi_key*,
		void*);

/*
 * Look up functions
 */
struct ubi_key *ubi_kmgr_key_lookup(struct ubi_key_entry *kentry,
		ubi_kmgr_key_lu_func lookup, void *private);
struct ubi_key *ubi_kmgr_key_lu_by_value(struct ubi_key_entry *kentry,
		__u8 *raw_key, size_t len);

#endif // CONFIG_UBI_CRYPTO_HMAC

struct ubi_key_entry *ubi_kmgr_get_kentry(struct ubi_key_tree *tree,
		__be32 vol_id);
void ubi_kmgr_put_kentry(struct ubi_key_entry *kentry);

int ubi_kmgr_setvolkey(struct ubi_key_tree *tree,
		struct ubi_kmgr_set_vol_key_req *req);
#ifdef CONFIG_UBI_CRYPTO_HMAC
struct ubi_key *ubi_kmgr_get_leb_key(struct ubi_hmac_hdr *hmac_hdr,
		struct ubi_vid_hdr *vid_hdr, int pnum,
		struct ubi_key_entry *kentry,
		int probe);
#endif // CONFIG_UBI_CRYPTO_HMAC
struct ubi_key *ubi_kmgr_get_mainkey(struct ubi_key_entry *kentry);

void ubi_kmgr_ack_update(struct ubi_key_entry *kentry);

struct ubi_key_tree *ubi_kmgr_get_tree(int ubi_dev);
void ubi_kmgr_put_tree(struct ubi_key_tree *tree);


void ubi_kmgr_init(void);
void ubi_kmgr_term(void);

#endif // _CRYPTO_KEY_MGR_H_
