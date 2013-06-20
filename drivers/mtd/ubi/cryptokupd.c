
#include "ubi.h"
#include "cryptokmgr.h"

#define BAD_PTR(p) ((IS_ERR((p))) || (NULL == (p)))

/**
 * ubi_upd_work - self-contained structure for update work
 * @upd_tree: The LEBs that must be updated
 * @err_tree: A tree to keep track of the LEBs where
 *            the update work failed.
 * @d: lesser bound of the current interval
 */
struct ubi_upd_work {
	struct ubi_kval_tree upd_tree;
	struct ubi_kval_tree err_tree;
	u32 d, u, s;
};

static u32 ubi_kupd_get_next_leb(struct ubi_upd_work *upd_w)
{
	u32 next = 0;
	int err = 0;
	struct ubi_kval_node *n;
	if (upd_w->d > upd_w->u) {
		err = ubi_kval_remove(
			&upd_w->upd_tree, upd_w->s, upd_w->u);
		if (err) {
			return err;
		}
		down_read(&upd_w->upd_tree.sem);
		n = ubi_kval_get_leftmost(&upd_w->upd_tree);
		if (!BAD_PTR(n)) {
			upd_w->s = n->d;
			upd_w->d = n->d;
			upd_w->u = n->u;
			next = upd_w->d++;
		} else {
			next = -1;
		}
		up_read(&upd_w->upd_tree.sem);
	} else {
		next = upd_w->d++;
	}
	return next;
}

int ubi_kmgr_upd(void *p_kentry)
{
	struct ubi_key_entry *kentry = p_kentry;
	struct ubi_key *main = NULL;
	struct ubi_upd_work upd_data;
	struct ubi_volume *vol;
	struct ubi_device *ubi;
	u32 leb = 0;
	u32 reserved_ebs;
	int err = 0;
	if (BAD_PTR(kentry)) {
		return PTR_ERR(kentry);
	}

	ubi_kval_init_tree(&upd_data.upd_tree);
	ubi_kval_init_tree(&upd_data.err_tree);
	while (1) {
		err = 0;
		if (kthread_should_stop()) {
			break;
		}
		main = ubi_kmgr_get_mainkey(kentry);
		if (BAD_PTR(main)) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule();
		} else {
			mutex_lock(&kentry->mutex);
			vol = kentry->vol;
			if (BAD_PTR(vol)) {
				ubi_err("%s - Bad UBI volume descriptor", __func__);
				break;
			}
			reserved_ebs = vol->reserved_pebs;
			if (kentry->dying) {
				mutex_unlock(&kentry->mutex);
				ubi_kmgr_put_key(main);
				break;
			} else if (kentry->reset_upd) {
				/*
				 * Reset the upd tree to its initial state
				 * ( [0, reserved_pebs] )
				 */
				ubi_kval_clear_tree(&upd_data.upd_tree);
				upd_data.upd_tree.dying = 0;
				ubi_kval_clear_tree(&upd_data.err_tree);
				upd_data.err_tree.dying = 0;
				err = ubi_kval_insert(&upd_data.upd_tree,
						0, reserved_ebs);
				if (0 > err) {
					/*
					 * Since upd_data is a stack variable,
					 * It is impossible to get EACCES errors,
					 * or EINVAL error due to invalid pointer.
					 *
					 * Moreover, since we insert unsigned integer,
					 * any value won't match 0 > value.
					 *
					 * This should never fail, so if we have an
					 * error, that would be memory corruption.
					 */
					ubi_err(KERN_ALERT "Error on ubi_kval_insert()"
							"(err = %d)\n"
							"Possible memory corruption,"
							"aborting update\n", err);
					mutex_unlock(&kentry->mutex);
					ubi_kmgr_put_key(main);
					break;
				} else {
					kentry->reset_upd = 0;
				}
			}
			mutex_unlock(&kentry->mutex);
			leb = ubi_kupd_get_next_leb(&upd_data);
			if ((u32)(-1) == leb) {
				/* No more update to perform.
				 * Clean up the key ring to erase
				 * obsolete entries. */
				ubi_kval_insert_tree(&upd_data.upd_tree, &upd_data.err_tree);
				ubi_kmgr_put_key(main);
				continue;
			} else if (IS_ERR(leb)) {
				/*
				 * An error occured ...
				 */
				ubi_kmgr_put_key(main);
				continue;
			}
			/*
			 * Perform the update :
			 * 1. Retrieve the current key settings for the LEB
			 * 2. Decipher the data (read)
			 * 3. Update key trees so that ubi_crypto_cipher will
			 *    use the main key instead of the previous one.
			 * 4. If an error has occured ...
			 */
			ubi = vol->ubi;
			err = ubi_eba_update_leb(ubi, vol, leb);

			/*
			 * FIXME
			 * The clean up is a little tricky if it is a copy failure
			 * (and not a key identification failure) :
			 * We must undo the key validity trees update performed in
			 * step 3.
			 */
			if (err) {
				switch (err) {
				case -ENODATA:
					err = 0;
					break;
				default:
					ubi_kval_insert(&upd_data.err_tree, leb, leb);
					break;
				}
			}
		}
		ubi_kmgr_put_key(main);
	} // end while (1)
	ubi_kmgr_put_kentry(kentry);
	ubi_kval_clear_tree(&upd_data.upd_tree);
	ubi_kval_clear_tree(&upd_data.err_tree);
	return err;
}

