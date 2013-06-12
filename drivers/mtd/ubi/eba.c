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
 * Author: Artem Bityutskiy (Битюцкий Артём)
 */

/*
 * The UBI Eraseblock Association (EBA) sub-system.
 *
 * This sub-system is responsible for I/O to/from logical eraseblock.
 *
 * Although in this implementation the EBA table is fully kept and managed in
 * RAM, which assumes poor scalability, it might be (partially) maintained on
 * flash in future implementations.
 *
 * The EBA sub-system implements per-logical eraseblock locking. Before
 * accessing a logical eraseblock it is locked for reading or writing. The
 * per-logical eraseblock locking is implemented by means of the lock tree. The
 * lock tree is an RB-tree which refers all the currently locked logical
 * eraseblocks. The lock tree elements are &struct ubi_ltree_entry objects.
 * They are indexed by (@vol_id, @lnum) pairs.
 *
 * EBA also maintains the global sequence counter which is incremented each
 * time a logical eraseblock is mapped to a physical eraseblock and it is
 * stored in the volume identifier header. This means that each VID header has
 * a unique sequence number. The sequence number is only increased an we assume
 * 64 bits is enough to never overflow.
 */

#include <linux/slab.h>
#include <linux/crc32.h>
#include <linux/err.h>
#include "ubi.h"

#ifdef CONFIG_MTD_UBI_CRYPTO
#include "crypto.h"
#endif

/* Number of physical eraseblocks reserved for atomic LEB change operation */
#define EBA_RESERVED_PEBS 1

#ifdef CONFIG_UBI_CRYPTO_HMAC
static int convert_io_error(int err);

static int convert_io_error(int err)
{
	if (err <= 0)
		return err;

	switch (err) {
	case UBI_IO_FF:
	case UBI_IO_FF_BITFLIPS:
		return -ENODATA;
		break;
	case UBI_IO_BAD_HDR:
	case UBI_IO_BAD_HDR_EBADMSG:
		return -EBADMSG;
		break;
	case UBI_IO_BITFLIPS:
		return 0;
		break;
	}
	return err;
}
#endif // CONFIG_UBI_CRYPTO_HMAC

/**
 * next_sqnum - get next sequence number.
 * @ubi: UBI device description object
 *
 * This function returns next sequence number to use, which is just the current
 * global sequence counter value. It also increases the global sequence
 * counter.
 */
unsigned long long ubi_next_sqnum(struct ubi_device *ubi)
{
	unsigned long long sqnum;

	spin_lock(&ubi->ltree_lock);
	sqnum = ubi->global_sqnum++;
	spin_unlock(&ubi->ltree_lock);

	return sqnum;
}

/**
 * ubi_get_compat - get compatibility flags of a volume.
 * @ubi: UBI device description object
 * @vol_id: volume ID
 *
 * This function returns compatibility flags for an internal volume. User
 * volumes have no compatibility flags, so %0 is returned.
 */
static int ubi_get_compat(const struct ubi_device *ubi, int vol_id)
{
	if (vol_id == UBI_LAYOUT_VOLUME_ID)
		return UBI_LAYOUT_VOLUME_COMPAT;
	return 0;
}

/**
 * ltree_lookup - look up the lock tree.
 * @ubi: UBI device description object
 * @vol_id: volume ID
 * @lnum: logical eraseblock number
 *
 * This function returns a pointer to the corresponding &struct ubi_ltree_entry
 * object if the logical eraseblock is locked and %NULL if it is not.
 * @ubi->ltree_lock has to be locked.
 */
static struct ubi_ltree_entry *ltree_lookup(struct ubi_device *ubi, int vol_id,
					    int lnum)
{
	struct rb_node *p;

	p = ubi->ltree.rb_node;
	while (p) {
		struct ubi_ltree_entry *le;

		le = rb_entry(p, struct ubi_ltree_entry, rb);

		if (vol_id < le->vol_id)
			p = p->rb_left;
		else if (vol_id > le->vol_id)
			p = p->rb_right;
		else {
			if (lnum < le->lnum)
				p = p->rb_left;
			else if (lnum > le->lnum)
				p = p->rb_right;
			else
				return le;
		}
	}

	return NULL;
}

/**
 * ltree_add_entry - add new entry to the lock tree.
 * @ubi: UBI device description object
 * @vol_id: volume ID
 * @lnum: logical eraseblock number
 *
 * This function adds new entry for logical eraseblock (@vol_id, @lnum) to the
 * lock tree. If such entry is already there, its usage counter is increased.
 * Returns pointer to the lock tree entry or %-ENOMEM if memory allocation
 * failed.
 */
static struct ubi_ltree_entry *ltree_add_entry(struct ubi_device *ubi,
					       int vol_id, int lnum)
{
	struct ubi_ltree_entry *le, *le1, *le_free;

	le = kmalloc(sizeof(struct ubi_ltree_entry), GFP_NOFS);
	if (!le)
		return ERR_PTR(-ENOMEM);

	le->users = 0;
	init_rwsem(&le->mutex);
	le->vol_id = vol_id;
	le->lnum = lnum;

	spin_lock(&ubi->ltree_lock);
	le1 = ltree_lookup(ubi, vol_id, lnum);

	if (le1) {
		/*
		 * This logical eraseblock is already locked. The newly
		 * allocated lock entry is not needed.
		 */
		le_free = le;
		le = le1;
	} else {
		struct rb_node **p, *parent = NULL;

		/*
		 * No lock entry, add the newly allocated one to the
		 * @ubi->ltree RB-tree.
		 */
		le_free = NULL;

		p = &ubi->ltree.rb_node;
		while (*p) {
			parent = *p;
			le1 = rb_entry(parent, struct ubi_ltree_entry, rb);

			if (vol_id < le1->vol_id)
				p = &(*p)->rb_left;
			else if (vol_id > le1->vol_id)
				p = &(*p)->rb_right;
			else {
				ubi_assert(lnum != le1->lnum);
				if (lnum < le1->lnum)
					p = &(*p)->rb_left;
				else
					p = &(*p)->rb_right;
			}
		}

		rb_link_node(&le->rb, parent, p);
		rb_insert_color(&le->rb, &ubi->ltree);
	}
	le->users += 1;
	spin_unlock(&ubi->ltree_lock);

	kfree(le_free);
	return le;
}

/**
 * leb_read_lock - lock logical eraseblock for reading.
 * @ubi: UBI device description object
 * @vol_id: volume ID
 * @lnum: logical eraseblock number
 *
 * This function locks a logical eraseblock for reading. Returns zero in case
 * of success and a negative error code in case of failure.
 */
static int leb_read_lock(struct ubi_device *ubi, int vol_id, int lnum)
{
	struct ubi_ltree_entry *le;

	le = ltree_add_entry(ubi, vol_id, lnum);
	if (IS_ERR(le))
		return PTR_ERR(le);
	down_read(&le->mutex);
	return 0;
}

/**
 * leb_read_unlock - unlock logical eraseblock.
 * @ubi: UBI device description object
 * @vol_id: volume ID
 * @lnum: logical eraseblock number
 */
static void leb_read_unlock(struct ubi_device *ubi, int vol_id, int lnum)
{
	struct ubi_ltree_entry *le;

	spin_lock(&ubi->ltree_lock);
	le = ltree_lookup(ubi, vol_id, lnum);
	le->users -= 1;
	ubi_assert(le->users >= 0);
	up_read(&le->mutex);
	if (le->users == 0) {
		rb_erase(&le->rb, &ubi->ltree);
		kfree(le);
	}
	spin_unlock(&ubi->ltree_lock);
}

/**
 * leb_write_lock - lock logical eraseblock for writing.
 * @ubi: UBI device description object
 * @vol_id: volume ID
 * @lnum: logical eraseblock number
 *
 * This function locks a logical eraseblock for writing. Returns zero in case
 * of success and a negative error code in case of failure.
 */
static int leb_write_lock(struct ubi_device *ubi, int vol_id, int lnum)
{
	struct ubi_ltree_entry *le;

	le = ltree_add_entry(ubi, vol_id, lnum);
	if (IS_ERR(le))
		return PTR_ERR(le);
	down_write(&le->mutex);
	return 0;
}

/**
 * leb_write_lock - lock logical eraseblock for writing.
 * @ubi: UBI device description object
 * @vol_id: volume ID
 * @lnum: logical eraseblock number
 *
 * This function locks a logical eraseblock for writing if there is no
 * contention and does nothing if there is contention. Returns %0 in case of
 * success, %1 in case of contention, and and a negative error code in case of
 * failure.
 */
static int leb_write_trylock(struct ubi_device *ubi, int vol_id, int lnum)
{
	struct ubi_ltree_entry *le;

	le = ltree_add_entry(ubi, vol_id, lnum);
	if (IS_ERR(le))
		return PTR_ERR(le);
	if (down_write_trylock(&le->mutex))
		return 0;

	/* Contention, cancel */
	spin_lock(&ubi->ltree_lock);
	le->users -= 1;
	ubi_assert(le->users >= 0);
	if (le->users == 0) {
		rb_erase(&le->rb, &ubi->ltree);
		kfree(le);
	}
	spin_unlock(&ubi->ltree_lock);

	return 1;
}

/**
 * leb_write_unlock - unlock logical eraseblock.
 * @ubi: UBI device description object
 * @vol_id: volume ID
 * @lnum: logical eraseblock number
 */
static void leb_write_unlock(struct ubi_device *ubi, int vol_id, int lnum)
{
	struct ubi_ltree_entry *le;

	spin_lock(&ubi->ltree_lock);
	le = ltree_lookup(ubi, vol_id, lnum);
	le->users -= 1;
	ubi_assert(le->users >= 0);
	up_write(&le->mutex);
	if (le->users == 0) {
		rb_erase(&le->rb, &ubi->ltree);
		kfree(le);
	}
	spin_unlock(&ubi->ltree_lock);
}

/**
 * ubi_eba_unmap_leb - un-map logical eraseblock.
 * @ubi: UBI device description object
 * @vol: volume description object
 * @lnum: logical eraseblock number
 *
 * This function un-maps logical eraseblock @lnum and schedules corresponding
 * physical eraseblock for erasure. Returns zero in case of success and a
 * negative error code in case of failure.
 */
int ubi_eba_unmap_leb(struct ubi_device *ubi, struct ubi_volume *vol,
		      int lnum)
{
	int err, pnum, vol_id = vol->vol_id;

	if (ubi->ro_mode)
		return -EROFS;

	err = leb_write_lock(ubi, vol_id, lnum);
	if (err)
		return err;

	pnum = vol->eba_tbl[lnum];
	if (pnum < 0)
		/* This logical eraseblock is already unmapped */
		goto out_unlock;

	dbg_eba("erase LEB %d:%d, PEB %d", vol_id, lnum, pnum);

	down_read(&ubi->fm_sem);
	vol->eba_tbl[lnum] = UBI_LEB_UNMAPPED;
	up_read(&ubi->fm_sem);
	err = ubi_wl_put_peb(ubi, vol_id, lnum, pnum, 0);

out_unlock:
	leb_write_unlock(ubi, vol_id, lnum);
	return err;
}

/**
 * ubi_eba_read_leb - read data.
 * @ubi: UBI device description object
 * @vol: volume description object
 * @lnum: logical eraseblock number
 * @buf: buffer to store the read data
 * @offset: offset from where to read
 * @len: how many bytes to read
 * @check: data CRC check flag
 *
 * If the logical eraseblock @lnum is unmapped, @buf is filled with 0xFF
 * bytes. The @check flag only makes sense for static volumes and forces
 * eraseblock data CRC checking.
 *
 * In case of success this function returns zero. In case of a static volume,
 * if data CRC mismatches - %-EBADMSG is returned. %-EBADMSG may also be
 * returned for any volume type if an ECC error was detected by the MTD device
 * driver. Other negative error cored may be returned in case of other errors.
 */
int ubi_eba_read_leb(struct ubi_device *ubi, struct ubi_volume *vol, int lnum,
		     void *buf, int offset, int len, int check)
{
	int err, pnum, scrub = 0, vol_id = vol->vol_id;
	struct ubi_vid_hdr *vid_hdr = NULL;
#ifdef CONFIG_MTD_UBI_CRYPTO
	int data_size = len, err_cipher = 0;
	void *crypt = NULL;
	struct ubi_crypto_cipher_info info = {.offset = offset,
                                             .ubi = ubi
                                            };
#endif // CONFIG_MTD_UBI_CRYPTO
	uint32_t uninitialized_var(crc);

	err = leb_read_lock(ubi, vol_id, lnum);
	if (err)
		return err;

	pnum = vol->eba_tbl[lnum];
	if (pnum < 0) {
		/*
		 * The logical eraseblock is not mapped, fill the whole buffer
		 * with 0xFF bytes. The exception is static volumes for which
		 * it is an error to read unmapped logical eraseblocks.
		 */
		dbg_eba("read %d bytes from offset %d of LEB %d:%d (unmapped)",
			len, offset, vol_id, lnum);
		leb_read_unlock(ubi, vol_id, lnum);
		ubi_assert(vol->vol_type != UBI_STATIC_VOLUME);
		memset(buf, 0xFF, len);
		return 0;
	}

	dbg_eba("read %d bytes from offset %d of LEB %d:%d, PEB %d",
		len, offset, vol_id, lnum, pnum);

	if (vol->vol_type == UBI_DYNAMIC_VOLUME)
		check = 0;

retry:
	if (check) {
		vid_hdr = ubi_zalloc_vid_hdr(ubi, GFP_NOFS);
		if (!vid_hdr) {
			err = -ENOMEM;
			goto out_unlock;
		}

		err = ubi_io_read_vid_hdr(ubi, pnum, vid_hdr, 1);
		if (err && err != UBI_IO_BITFLIPS) {
			if (err > 0) {
				/*
				 * The header is either absent or corrupted.
				 * The former case means there is a bug -
				 * switch to read-only mode just in case.
				 * The latter case means a real corruption - we
				 * may try to recover data. FIXME: but this is
				 * not implemented.
				 */
				if (err == UBI_IO_BAD_HDR_EBADMSG ||
				    err == UBI_IO_BAD_HDR) {
					ubi_warn("corrupted VID header at PEB %d, LEB %d:%d",
						 pnum, vol_id, lnum);
					err = -EBADMSG;
				} else
					ubi_ro_mode(ubi);
			}
			goto out_free;
		} else if (err == UBI_IO_BITFLIPS)
			scrub = 1;

		ubi_assert(lnum < be32_to_cpu(vid_hdr->used_ebs));
		ubi_assert(len == be32_to_cpu(vid_hdr->data_size));

		crc = be32_to_cpu(vid_hdr->data_crc);
		ubi_free_vid_hdr(ubi, vid_hdr);
	}
#ifdef CONFIG_MTD_UBI_CRYPTO
	if (!crypt) {
		if (len > 2*PAGE_SIZE) {
			crypt = vmalloc(len);
		} else {
			crypt = kmalloc(len, GFP_NOFS);
		}
	}
	if (!crypt) {
		err = -ENOMEM;
		goto out_unlock;
	}
	vid_hdr = ubi_zalloc_vid_hdr(ubi, GFP_NOFS);
	if (!vid_hdr) {
		err = -ENOMEM;
		goto out_unlock;
	}
	err = ubi_io_read_vid_hdr(ubi, pnum, vid_hdr, 0);
	if (err) {
		err = convert_io_error(err);
		goto out_free;
	}

#ifdef CONFIG_UBI_CRYPTO_HMAC
	if (ubi->hmac) {
		info.hmac_hdr = ubi_zalloc_hmac_hdr(ubi, GFP_NOFS);
		if (!info.hmac_hdr) {
			err = -ENOMEM;
			ubi_free_vid_hdr(ubi, vid_hdr);
			goto out_unlock;
		}
		err = ubi_io_read_hmac_hdr(ubi, pnum, info.hmac_hdr, 0);
		if (err) {
			err = convert_io_error(err);
			goto out_free;
		}
	} else {
		info.hmac_hdr = NULL;
	}
#endif
	err = ubi_io_read_data(ubi, crypt, pnum, offset, len);
	if (UBI_IO_BITFLIPS == err) {
		err = 0;
		scrub = 1;
	}

	if (!err) {
		if (!(len & (ubi->min_io_size - 1))) {
			data_size = ubi_calc_data_len(ubi, crypt, len);
		}
		if (data_size < len) {
			memset(buf+data_size, 0xFF, len - data_size);
		}
		info.pnum = pnum;
		info.vid_hdr = vid_hdr;
		info.dst = buf;
		info.src = crypt;
		info.len = data_size;
		err_cipher = ubi_crypto_decipher(
				&info);
		if (0 > err_cipher) {
			err = err_cipher;
			goto out_free;
		}
	}
	ubi_free_vid_hdr(ubi, vid_hdr);
	vid_hdr = NULL;
#else
	err = ubi_io_read_data(ubi, buf, pnum, offset, len);
#endif // CONFIG_MTD_UBI_CRYPTO
	if (err) {
		if (err == UBI_IO_BITFLIPS) {
			scrub = 1;
			err = 0;
		} else if (mtd_is_eccerr(err)) {
			if (vol->vol_type == UBI_DYNAMIC_VOLUME)
				goto out_unlock;

			scrub = 1;
			if (!check) {
				ubi_msg("force data checking");
				check = 1;
				goto retry;
			}
		} else
			goto out_unlock;
	}

	if (check) {
		uint32_t crc1 = crc32(UBI_CRC32_INIT, buf, len);
		if (crc1 != crc) {
			ubi_warn("CRC error: calculated %#08x, must be %#08x",
				 crc1, crc);
			err = -EBADMSG;
			goto out_unlock;
		}
	}

	if (scrub)
		err = ubi_wl_scrub_peb(ubi, pnum);

	leb_read_unlock(ubi, vol_id, lnum);
	return err;

out_free:
#ifdef CONFIG_UBI_CRYPTO_HMAC
	ubi_free_hmac_hdr(ubi, info.hmac_hdr);
#endif
	ubi_free_vid_hdr(ubi, vid_hdr);
out_unlock:
#ifdef 	CONFIG_MTD_UBI_CRYPTO
	SAFE_FREE(crypt);
#endif
	leb_read_unlock(ubi, vol_id, lnum);
	return err;
}

/**
 * recover_peb - recover from write failure.
 * @ubi: UBI device description object
 * @pnum: the physical eraseblock to recover
 * @vol_id: volume ID
 * @lnum: logical eraseblock number
 * @buf: data which was not written because of the write failure
 * @offset: offset of the failed write
 * @len: how many bytes should have been written
 *
 * This function is called in case of a write failure and moves all good data
 * from the potentially bad physical eraseblock to a good physical eraseblock.
 * This function also writes the data which was not written due to the failure.
 * Returns new physical eraseblock number in case of success, and a negative
 * error code in case of failure.
 */
static int recover_peb(struct ubi_device *ubi, int pnum, int vol_id, int lnum,
		       const void *buf, int offset, int len)
{
	int err, idx = vol_id2idx(ubi, vol_id), new_pnum, data_size, tries = 0;
	struct ubi_volume *vol = ubi->volumes[idx];
	struct ubi_vid_hdr *vid_hdr;
#ifdef CONFIG_MTD_UBI_CRYPTO
	void *crypt = NULL;
	__be64 old_sqnum, new_sqnum;
	struct ubi_crypto_cipher_info info = {.ubi = ubi,
	                                      .offset = offset,
	                                      .dst = buf
	                                     };
#ifdef CONFIG_UBI_CRYPTO_HMAC
	struct ubi_hmac_hdr *hmac_hdr = NULL;
#endif
#endif
	vid_hdr = ubi_zalloc_vid_hdr(ubi, GFP_NOFS);
	if (!vid_hdr)
		return -ENOMEM;

retry:
	new_pnum = ubi_wl_get_peb(ubi);
	if (new_pnum < 0) {
		ubi_free_vid_hdr(ubi, vid_hdr);
		return new_pnum;
	}

	ubi_msg("recover PEB %d, move data to PEB %d", pnum, new_pnum);

	err = ubi_io_read_vid_hdr(ubi, pnum, vid_hdr, 1);
	if (err && err != UBI_IO_BITFLIPS) {
		if (err > 0)
			err = -EIO;
		goto out_put;
	}
#ifdef CONFIG_UBI_CRYPTO_HMAC
	if (ubi->hmac) {
		hmac_hdr = ubi_zalloc_hmac_hdr(ubi, GFP_NOFS);
		if (!hmac_hdr) {
			err = -ENOMEM;
			goto out_put;
		}
		err = ubi_io_read_hmac_hdr(ubi, pnum, hmac_hdr, 1);
		if (err) {
			goto out_put;
		}
	}
#endif // CONFIG_UBI_CRYPTO_HMAC
#ifdef CONFIG_MTD_UBI_CRYPTO
	old_sqnum = vid_hdr->sqnum;
#endif
	vid_hdr->sqnum = cpu_to_be64(ubi_next_sqnum(ubi));
	err = ubi_io_write_vid_hdr(ubi, new_pnum, vid_hdr);
	if (err)
		goto write_error;

	data_size = offset + len;
	mutex_lock(&ubi->buf_mutex);
	memset(ubi->peb_buf + offset, 0xFF, len);
#ifdef CONFIG_MTD_UBI_CRYPTO
	info.vid_hdr = vid_hdr;
	info.hmac_hdr = hmac_hdr;
	info.len = len;
	info.src = buf;
	info.dst = ubi->peb_buf + offset;
	info.pnum = new_pnum;
	err = ubi_crypto_cipher(&info);
	if (err && -ENODATA != err) {
		goto out_unlock;
	}
#endif
	/* Read everything before the area where the write failure happened */
	if (offset > 0) {
#ifdef CONFIG_MTD_UBI_CRYPTO
		if (!crypt) {
			if (offset > 2*PAGE_SIZE) {
				crypt = vmalloc(offset);
			} else {
				crypt = kmalloc(offset, GFP_NOFS);
			}
		}
		if (!crypt) {
			err = -ENOMEM;
			goto out_unlock;
		}
		err = ubi_io_read_data(ubi, crypt, pnum, 0, offset);
#else
		err = ubi_io_read_data(ubi, ubi->peb_buf, pnum, 0, offset);
#endif
		if (err && err != UBI_IO_BITFLIPS)
			goto out_unlock;
	}
#ifdef CONFIG_MTD_UBI_CRYPTO
	/* Swap the old and new sqnum */
	new_sqnum = vid_hdr->sqnum;
	vid_hdr->sqnum = old_sqnum;
	info.pnum = pnum;
	info.offset = 0;
	info.len = offset;
	info.src = crypt;
	info.dst = ubi->peb_buf;
	err = ubi_crypto_decipher(&info);
	if (err) {
		goto out_unlock;
	}
	vid_hdr->sqnum = new_sqnum;
	info.src = ubi->peb_buf;
	info.pnum = new_pnum;
	err = ubi_crypto_compute_hmac_hdr(
			ubi, hmac_hdr, vid_hdr, new_pnum,
			ubi->peb_buf, data_size
			);
	if (err) {
		goto out_unlock;
	}
	err = ubi_crypto_cipher(&info);
	if (err) {
		goto out_unlock;
	}

#endif

	memcpy(ubi->peb_buf + offset, buf, len);

	err = ubi_io_write_data(ubi, ubi->peb_buf, new_pnum, 0, data_size);
	if (err) {
		mutex_unlock(&ubi->buf_mutex);
		goto write_error;
	}


	mutex_unlock(&ubi->buf_mutex);
	ubi_free_vid_hdr(ubi, vid_hdr);

	down_read(&ubi->fm_sem);
	vol->eba_tbl[lnum] = new_pnum;
	up_read(&ubi->fm_sem);
	ubi_wl_put_peb(ubi, vol_id, lnum, pnum, 1);
#ifdef CONFIG_UBI_MTD_CRYPTO
	SAFE_FREE(crypt);
#endif

	ubi_msg("data was successfully recovered");
	return 0;

out_unlock:
	mutex_unlock(&ubi->buf_mutex);
out_put:
	ubi_wl_put_peb(ubi, vol_id, lnum, new_pnum, 1);
	ubi_free_vid_hdr(ubi, vid_hdr);
#ifdef CONFIG_UBI_CRYPTO_HMAC
	if (!hmac_hdr)
		ubi_free_hmac_hdr(ubi, hmac_hdr);
#endif
#ifdef CONFIG_UBI_MTD_CRYPTO
	SAFE_FREE(crypt);
#endif
	return err;

write_error:
	/*
	 * Bad luck? This physical eraseblock is bad too? Crud. Let's try to
	 * get another one.
	 */
	ubi_warn("failed to write to PEB %d", new_pnum);
	ubi_wl_put_peb(ubi, vol_id, lnum, new_pnum, 1);
	if (++tries > UBI_IO_RETRIES) {
		ubi_free_vid_hdr(ubi, vid_hdr);
#ifdef CONFIG_UBI_MTD_CRYPTO
		SAFE_FREE(crypt);
#endif
		return err;
	}
	ubi_msg("try again");
	goto retry;
}

/**
 * ubi_eba_write_leb - write data to dynamic volume.
 * @ubi: UBI device description object
 * @vol: volume description object
 * @lnum: logical eraseblock number
 * @buf: the data to write
 * @offset: offset within the logical eraseblock where to write
 * @len: how many bytes to write
 *
 * This function writes data to logical eraseblock @lnum of a dynamic volume
 * @vol. Returns zero in case of success and a negative error code in case
 * of failure. In case of error, it is possible that something was still
 * written to the flash media, but may be some garbage.
 */
int ubi_eba_write_leb(struct ubi_device *ubi, struct ubi_volume *vol, int lnum,
		      const void *buf, int offset, int len)
{
	int err, pnum, tries = 0, vol_id = vol->vol_id;
	struct ubi_vid_hdr *vid_hdr;
#ifdef CONFIG_MTD_UBI_CRYPTO
#ifdef CONFIG_UBI_CRYPTO_HMAC
	struct ubi_hmac_hdr *hmac_hdr = NULL;
#endif // CONFIG_UBI_CRYPTO_HMAC
	void *crypt = NULL;
	struct ubi_crypto_cipher_info info = {.ubi = ubi,
                                           .offset = offset,
                                           .src = buf,
                                           .len = len,
                                           .hmac_hdr = NULL
                                          };
#endif
	if (ubi->ro_mode)
		return -EROFS;
	err = leb_write_lock(ubi, vol_id, lnum);
	if (err)
		return err;

	pnum = vol->eba_tbl[lnum];
	if (pnum >= 0) {
		dbg_eba("write %d bytes at offset %d of LEB %d:%d, PEB %d",
			len, offset, vol_id, lnum, pnum);
#ifdef CONFIG_MTD_UBI_CRYPTO
		vid_hdr = ubi_zalloc_vid_hdr(ubi, GFP_NOFS);
		if (!vid_hdr) {
			err = -ENOMEM;
		}
		err = ubi_io_read_vid_hdr(ubi, pnum, vid_hdr, 0);
		if (err && UBI_IO_BITFLIPS != err) {
			ubi_free_vid_hdr(ubi, vid_hdr);
			return convert_io_error(err);
		} else {
			err = 0;
		}
#ifdef CONFIG_UBI_CRYPTO_HMAC
		if (ubi->hmac) {
			hmac_hdr = ubi_zalloc_hmac_hdr(ubi, GFP_NOFS);
			if (BAD_PTR(hmac_hdr)) {
				ubi_free_vid_hdr(ubi, vid_hdr);
				leb_write_unlock(ubi, vol_id, lnum);
				return -ENOMEM;
			}
			err = ubi_io_read_hmac_hdr(ubi, pnum, hmac_hdr, 0);
			if (err && err != UBI_IO_BITFLIPS) {
				ubi_free_vid_hdr(ubi, vid_hdr);
				ubi_free_hmac_hdr(ubi, hmac_hdr);
				leb_write_unlock(ubi, vol_id, lnum);
				return convert_io_error(err);
			} else {
				err = 0;
			}
			info.hmac_hdr = hmac_hdr;
		}
#endif // CONFIG_UBI_CRYPTO_HMAC
		if (len > 2*PAGE_SIZE) {
			crypt = vmalloc(len);
		} else {
			crypt = kzalloc(len, GFP_NOFS);
		}
		if (!crypt) {
			ubi_free_vid_hdr(ubi, vid_hdr);
			leb_write_unlock(ubi, vol_id, lnum);
			return -ENOMEM;
		}
		info.vid_hdr = vid_hdr;
		info.dst = crypt;
		info.pnum = pnum;
		err = ubi_crypto_cipher(&info);
		if (err) {
			printk("Error on ubi_crypto_cipher : %d\n", err);
		}
		ubi_free_hmac_hdr(ubi, info.hmac_hdr);
		ubi_free_vid_hdr(ubi, vid_hdr);
		vid_hdr = NULL;
		err = ubi_io_write_data(ubi, crypt, pnum, offset, len);
		SAFE_FREE(crypt);
#else
		err = ubi_io_write_data(ubi, buf, pnum, offset, len);
#endif // CONFIG_MTD_UBI_CRYPTO
		if (err) {
			ubi_warn("failed to write data to PEB %d", pnum);
			if (err == -EIO && ubi->bad_allowed)
				err = recover_peb(ubi, pnum, vol_id, lnum, buf,
						offset, len);
			if (err)
				ubi_ro_mode(ubi);
		}
		leb_write_unlock(ubi, vol_id, lnum);
		return err;
	}

	/*
	 * The logical eraseblock is not mapped. We have to get a free physical
	 * eraseblock and write the volume identifier header there first.
	 */
	vid_hdr = ubi_zalloc_vid_hdr(ubi, GFP_NOFS);
	if (!vid_hdr) {
		leb_write_unlock(ubi, vol_id, lnum);
		return -ENOMEM;
	}

	vid_hdr->vol_type = UBI_VID_DYNAMIC;
	vid_hdr->sqnum = cpu_to_be64(ubi_next_sqnum(ubi));
	vid_hdr->vol_id = cpu_to_be32(vol_id);
	vid_hdr->lnum = cpu_to_be32(lnum);
	vid_hdr->compat = ubi_get_compat(ubi, vol_id);
	vid_hdr->data_pad = cpu_to_be32(vol->data_pad);

#ifdef CONFIG_UBI_CRYPTO_HMAC
	if (ubi->hmac) {
		hmac_hdr = ubi_zalloc_hmac_hdr(ubi, GFP_NOFS);
		if (!hmac_hdr) {
			ubi_free_vid_hdr(ubi, vid_hdr);
			leb_write_unlock(ubi, vol_id, lnum);
			return -ENOMEM;
		}
	}
#endif // CONFIG_UBI_CRYPTO_HMAC

retry:
	pnum = ubi_wl_get_peb(ubi);
	if (pnum < 0) {
		ubi_free_vid_hdr(ubi, vid_hdr);
#ifdef CONFIG_UBI_CRYPTO_HMAC
		if (hmac_hdr) {
			ubi_free_hmac_hdr(ubi, hmac_hdr);
		}
#endif // CONFIG_UBI_CRYPTO_HMAC
		leb_write_unlock(ubi, vol_id, lnum);
		return pnum;
	}

	dbg_eba("write VID hdr and %d bytes at offset %d of LEB %d:%d, PEB %d",
		len, offset, vol_id, lnum, pnum);

	err = ubi_io_write_vid_hdr(ubi, pnum, vid_hdr);
	if (err) {
		ubi_warn("failed to write VID header to LEB %d:%d, PEB %d",
			 vol_id, lnum, pnum);
		goto write_error;
	}

#ifdef CONFIG_UBI_CRYPTO_HMAC
	if (ubi->hmac) {
		err = ubi_crypto_compute_hmac_hdr(
			ubi, hmac_hdr, vid_hdr, pnum, NULL, 0
			);
		if (err) {
			ubi_free_hmac_hdr(ubi, hmac_hdr);
			ubi_free_vid_hdr(ubi, vid_hdr);
			leb_write_unlock(ubi, vol_id, lnum);
			return err;
		}
		err = ubi_io_write_hmac_hdr(ubi, pnum, hmac_hdr);
		if (err) {
			ubi_warn("failed to write HMAC hdr to LEB %d:%d, PEB %d",
				vol_id, lnum, pnum);
			goto write_error;
		}
	}
#endif // CONFIG_UBI_CRYPTO_HMAC

	if (len) {
#ifdef CONFIG_MTD_UBI_CRYPTO
		if (!crypt) {
			if (len > 2*PAGE_SIZE) {
				crypt = vmalloc(len);
			} else {
				crypt = kzalloc(len, GFP_NOFS);
			}
		}
		if (!crypt) {
			ubi_free_vid_hdr(ubi, vid_hdr);
			return -ENOMEM;
		}
		info.hmac_hdr = NULL;
		info.src = buf;
		info.pnum = pnum;
		info.dst = crypt;
		info.vid_hdr = vid_hdr;
		err = ubi_crypto_cipher(&info);
		if (err) {
			ubi_free_vid_hdr(ubi, vid_hdr);
			printk("error on ubi_crypto_cipher : %d\n",err);
			SAFE_FREE(buf);
			return err;
		}
		err = ubi_io_write_data(ubi, crypt, pnum, offset, len);
#else
		err = ubi_io_write_data(ubi, buf, pnum, offset, len);
#endif // CONFIG_MTD_UBI_CRYPTO
		if (err) {
			ubi_warn("failed to write %d bytes at offset %d of LEB %d:%d, PEB %d",
				 len, offset, vol_id, lnum, pnum);
			goto write_error;
		}
	}

	down_read(&ubi->fm_sem);
	vol->eba_tbl[lnum] = pnum;
	up_read(&ubi->fm_sem);

#ifdef CONFIG_MTD_UBI_CRYPTO
	SAFE_FREE(crypt);
#endif
	leb_write_unlock(ubi, vol_id, lnum);
	ubi_free_vid_hdr(ubi, vid_hdr);
	return 0;

write_error:
	if (err != -EIO || !ubi->bad_allowed) {
		ubi_ro_mode(ubi);
		leb_write_unlock(ubi, vol_id, lnum);
		ubi_free_vid_hdr(ubi, vid_hdr);
#ifdef CONFIG_MTD_UBI_CRYPTO
		SAFE_FREE(crypt);
#endif
		return err;
	}

	/*
	 * Fortunately, this is the first write operation to this physical
	 * eraseblock, so just put it and request a new one. We assume that if
	 * this physical eraseblock went bad, the erase code will handle that.
	 */
	err = ubi_wl_put_peb(ubi, vol_id, lnum, pnum, 1);
	if (err || ++tries > UBI_IO_RETRIES) {
		ubi_ro_mode(ubi);
		leb_write_unlock(ubi, vol_id, lnum);
		ubi_free_vid_hdr(ubi, vid_hdr);
#ifdef CONFIG_MTD_UBI_CRYPTO
		SAFE_FREE(crypt);
#endif
		return err;
	}

	vid_hdr->sqnum = cpu_to_be64(ubi_next_sqnum(ubi));
	ubi_msg("try another PEB");
	goto retry;
}

/**
 * ubi_eba_write_leb_st - write data to static volume.
 * @ubi: UBI device description object
 * @vol: volume description object
 * @lnum: logical eraseblock number
 * @buf: data to write
 * @len: how many bytes to write
 * @used_ebs: how many logical eraseblocks will this volume contain
 *
 * This function writes data to logical eraseblock @lnum of static volume
 * @vol. The @used_ebs argument should contain total number of logical
 * eraseblock in this static volume.
 *
 * When writing to the last logical eraseblock, the @len argument doesn't have
 * to be aligned to the minimal I/O unit size. Instead, it has to be equivalent
 * to the real data size, although the @buf buffer has to contain the
 * alignment. In all other cases, @len has to be aligned.
 *
 * It is prohibited to write more than once to logical eraseblocks of static
 * volumes. This function returns zero in case of success and a negative error
 * code in case of failure.
 */
int ubi_eba_write_leb_st(struct ubi_device *ubi, struct ubi_volume *vol,
			 int lnum, const void *buf, int len, int used_ebs)
{
	int err, pnum, tries = 0, data_size = len, vol_id = vol->vol_id;
	struct ubi_vid_hdr *vid_hdr;
	uint32_t crc;
#ifdef CONFIG_MTD_UBI_CRYPTO
	void *crypt = NULL;
	struct ubi_crypto_cipher_info info = {.ubi = ubi,
                                           .src = buf,
                                           .len = len,
                                           .offset = 0,
                                           .hmac_hdr = NULL
                                          };
#ifdef CONFIG_UBI_CRYPTO_HMAC
	struct ubi_hmac_hdr *hmac_hdr = NULL;
#endif // CONFIG_UBI_CRYPTO_HMAC
#endif // CONFIG_MTD_UBI_CRYPTO
	if (ubi->ro_mode)
		return -EROFS;

	if (lnum == used_ebs - 1)
		/* If this is the last LEB @len may be unaligned */
		len = ALIGN(data_size, ubi->min_io_size);
	else
		ubi_assert(!(len & (ubi->min_io_size - 1)));

	vid_hdr = ubi_zalloc_vid_hdr(ubi, GFP_NOFS);
	if (!vid_hdr)
		return -ENOMEM;

#ifdef CONFIG_UBI_CRYPTO_HMAC
	if (ubi->hmac) {
		hmac_hdr = ubi_zalloc_hmac_hdr(ubi, GFP_NOFS);
		if (!hmac_hdr) {
			ubi_free_vid_hdr(ubi, vid_hdr);
			return -ENOMEM;
		}
	}
#endif // CONFIG_UBI_CRYPTO_HMAC

	err = leb_write_lock(ubi, vol_id, lnum);
	if (err) {
		ubi_free_vid_hdr(ubi, vid_hdr);
#ifdef CONFIG_UBI_CRYPTO_HMAC
		if (hmac_hdr)
			ubi_free_hmac_hdr(ubi, hmac_hdr);
#endif // CONFIG_UBI_CRYPTO_HMAC
		return err;
	}

#ifdef CONFIG_MTD_UBI_CRYPTO
	if (len > 2*PAGE_SIZE) {
		crypt = vmalloc(len);
	} else {
		crypt = kmalloc(len, GFP_NOFS);
	}
	if (NULL == crypt) {
		ubi_free_vid_hdr(ubi, vid_hdr);
		return -ENOMEM;
	}
	info.vid_hdr = vid_hdr;
#endif // CONFIG_MTD_UBI_CRYPTO

	vid_hdr->sqnum = cpu_to_be64(ubi_next_sqnum(ubi));
	vid_hdr->vol_id = cpu_to_be32(vol_id);
	vid_hdr->lnum = cpu_to_be32(lnum);
	vid_hdr->compat = ubi_get_compat(ubi, vol_id);
	vid_hdr->data_pad = cpu_to_be32(vol->data_pad);
#ifndef CONFIG_MTD_UBI_CRYPTO
	crc = crc32(UBI_CRC32_INIT, buf, data_size);
#endif
	vid_hdr->vol_type = UBI_VID_STATIC;
	vid_hdr->data_size = cpu_to_be32(data_size);
	vid_hdr->used_ebs = cpu_to_be32(used_ebs);
#ifndef CONFIG_MTD_UBI_CRYPTO
	vid_hdr->data_crc = cpu_to_be32(crc);
#endif

retry:
	pnum = ubi_wl_get_peb(ubi);
	if (pnum < 0) {
		ubi_free_vid_hdr(ubi, vid_hdr);
#ifdef CONFIG_UBI_CRYPTO_HMAC
		if (hmac_hdr)
			ubi_free_hmac_hdr(ubi, hmac_hdr);
#endif // CONFIG_UBI_CRYPTO_HMAC
		leb_write_unlock(ubi, vol_id, lnum);
#ifdef CONFIG_MTD_UBI_CRYPTO
		SAFE_FREE(crypt);
#endif // CONFIG_MTD_UBI_CRYPTO
		return pnum;
	}
#ifdef CONFIG_MTD_UBI_CRYPTO
	info.pnum = pnum;
	info.dst = crypt;
	err = ubi_crypto_cipher(&info);
	if (err) {
		dbg_eba("Error while ciphering the data : %d", err);
		leb_write_unlock(ubi, vol_id, lnum);
		ubi_free_vid_hdr(ubi, vid_hdr);
#ifdef CONFIG_UBI_CRYPTO_HMAC
		if (hmac_hdr)
			ubi_free_hmac_hdr(ubi, hmac_hdr);
#endif // CONFIG_UBI_CRYPTO_HMAC
		SAFE_FREE(crypt);
		return err;
	}
	crc = crc32(UBI_CRC32_INIT, crypt, data_size);
	vid_hdr->data_crc = cpu_to_be32(crc);
#ifdef CONFIG_UBI_CRYPTO_HMAC
	if (ubi->hmac) {
		err = ubi_crypto_compute_hmac_hdr(
				ubi, hmac_hdr, vid_hdr,
				pnum, buf, len);
		if (err) {
			dbg_eba("Error while computing the HMAC header : %d",
					err);
			leb_write_unlock(ubi, vol_id, lnum);
			ubi_free_vid_hdr(ubi, vid_hdr);
			ubi_free_hmac_hdr(ubi, hmac_hdr);
			SAFE_FREE(crypt);
			return err;
		}
	}
#endif // CONFIG_UBI_CRYPTO_HMAC
#endif // CONFIG_MTD_UBI_CRYPTO
	dbg_eba("write VID hdr and %d bytes at LEB %d:%d, PEB %d, used_ebs %d",
		len, vol_id, lnum, pnum, used_ebs);

	err = ubi_io_write_vid_hdr(ubi, pnum, vid_hdr);
	if (err) {
		ubi_warn("failed to write VID header to LEB %d:%d, PEB %d",
			 vol_id, lnum, pnum);
		goto write_error;
	}

#ifdef CONFIG_UBI_CRYPTO_HMAC
	if (ubi->hmac) {
		err = ubi_io_write_hmac_hdr(ubi, pnum, hmac_hdr);
		if (err) {
			ubi_warn("failed to write HMAC hdr to LEB %d:%d, PEB %d",
				vol_id, lnum, pnum);
			goto write_error;
		}
	}
#endif // CONFIG_UBI_CRYPTO_HMAC
	err = ubi_io_write_data(ubi, buf, pnum, 0, len);
	if (err) {
		ubi_warn("failed to write %d bytes of data to PEB %d",
			 len, pnum);
		goto write_error;
	}

	ubi_assert(vol->eba_tbl[lnum] < 0);
	down_read(&ubi->fm_sem);
	vol->eba_tbl[lnum] = pnum;
	up_read(&ubi->fm_sem);

	leb_write_unlock(ubi, vol_id, lnum);
	ubi_free_vid_hdr(ubi, vid_hdr);
#ifdef CONFIG_UBI_CRYPTO_HMAC
	if (hmac_hdr)
		ubi_free_hmac_hdr(ubi, hmac_hdr);
#endif // CONFIG_UBI_CRYPTO_HMAC
#ifdef CONFIG_MTD_UBI_CRYPTO
	SAFE_FREE(crypt);
#endif // CONFIG_MTD_UBI_CRYPTO
	return 0;

write_error:
	if (err != -EIO || !ubi->bad_allowed) {
		/*
		 * This flash device does not admit of bad eraseblocks or
		 * something nasty and unexpected happened. Switch to read-only
		 * mode just in case.
		 */
		ubi_ro_mode(ubi);
		leb_write_unlock(ubi, vol_id, lnum);
#ifdef CONFIG_MTD_UBI_CRYPTO
		SAFE_FREE(crypt);
#endif // CONFIG_MTD_UBI_CRYPTO
#ifdef CONFIG_UBI_CRYPTO_HMAC
		if (hmac_hdr)
			ubi_free_hmac_hdr(ubi, hmac_hdr);
#endif // CONFIG_UBI_CRYPTO_HMAC
		ubi_free_vid_hdr(ubi, vid_hdr);
		return err;
	}

	err = ubi_wl_put_peb(ubi, vol_id, lnum, pnum, 1);
	if (err || ++tries > UBI_IO_RETRIES) {
		ubi_ro_mode(ubi);
		leb_write_unlock(ubi, vol_id, lnum);
		ubi_free_vid_hdr(ubi, vid_hdr);
#ifdef CONFIG_UBI_CRYPTO_HMAC
		if (hmac_hdr)
			ubi_free_hmac_hdr(ubi, hmac_hdr);
#endif // CONFIG_UBI_CRYPTO_HMAC
#ifdef CONFIG_MTD_UBI_CRYPTO
		SAFE_FREE(crypt);
#endif // CONFIG_MTD_UBI_CRYPTO
		return err;
	}

	vid_hdr->sqnum = cpu_to_be64(ubi_next_sqnum(ubi));
	ubi_msg("try another PEB");
	goto retry;
}
#ifdef CONFIG_UBI_CRYPTO_HMAC

struct ubi_hmac_lu_data {
	struct ubi_crypto_unit *unit;
	struct ubi_vid_hdr *vid_hdr;
	struct ubi_hmac_hdr *hmac_hdr;
	__be32 pnum;
};

static int hmac_tag_lookup(struct ubi_key *key, void *p)
{
	int err = 0, i = 0;
	u8 hmac_tag_out[16];
	u8 hmac_tag_in[20];
	u8 hmac_key[20];
	struct scatterlist sg_in;
	struct hash_desc desc;
	size_t len = min(sizeof(hmac_key), key->key_len);
	struct ubi_hmac_lu_data *d = p;

	memset(hmac_key, 0, sizeof(hmac_key));
	if (BAD_PTR(d) || BAD_PTR(d->unit)) {
		return 0;
	}

	desc.tfm = (struct crypto_hash*)d->unit->hmac.tfm;
	sg_init_table(&sg_in, 1);
	sg_set_buf(&sg_in, hmac_tag_in, sizeof(hmac_tag_in));

	memcpy(&hmac_tag_in[i], &d->vid_hdr->vol_id,
			sizeof(d->vid_hdr->vol_id));
	i += sizeof(d->vid_hdr->vol_id);
	memcpy(&hmac_tag_in[i], &d->vid_hdr->lnum,
			sizeof(d->vid_hdr->lnum));
	i += sizeof(d->vid_hdr->lnum);
	memcpy(&hmac_tag_in[i], &d->vid_hdr->sqnum,
			sizeof(d->vid_hdr->sqnum));
	i += sizeof(d->vid_hdr->sqnum);
	memcpy(&hmac_tag_in[i], &d->pnum, sizeof(d->pnum));
	memcpy(hmac_key, key->key, len);
	memcpy(hmac_key + sizeof(hmac_key) - sizeof(d->pnum),
			&d->pnum, sizeof(d->pnum));
	mutex_lock(&d->unit->hmac.mutex);
	crypto_hash_setkey((struct crypto_hash*)d->unit->hmac.tfm,
			hmac_key, sizeof(hmac_key));

	crypto_hash_digest(&desc, &sg_in, sizeof(hmac_tag_in),
			hmac_tag_out);
	mutex_unlock(&d->unit->hmac.mutex);
}

int ubi_eba_update_leb(struct ubi_device *ubi, struct ubi_volume *vol,
		int lnum)
{
	int err = 0;
	int pnum;
	struct ubi_vid_hdr *vid_hdr = NULL;
	struct ubi_hmac_hdr *hmac_hdr = NULL;
	struct ubi_key *cur_key = NULL;

	if (BAD_PTR(ubi) || BAD_PTR(vol))
		return -EINVAL;

	if (ubi->ro_mode)
		return -EROFS;

	vid_hdr = ubi_zalloc_vid_hdr(ubi, GFP_NOFS);
	if (!vid_hdr)
		return -ENOMEM;

	err = leb_write_lock(ubi, vol->vol_id, lnum);
	if (err) {
		goto out_free;
	}
	if (-1 == (pnum = vol->eba_tbl[lnum])) {
		goto out_unlock;
	}
	err = ubi_io_read_vid_hdr(ubi, pnum, vid_hdr, 1);
	if (err) {

	}

	/*
	 *  3. Read HMAC hdr
	 *  4. Find the key in use
	 *  5. Lock LEB buffer
	 *  6. Read LEB data
	 *  7. Cipher them to the dest key
	 *  8. Write headers
	 *  9. Write buffer
	 * 10. Unlock
	 */


	out_unlock:
	leb_write_unlock(ubi, vol->vol_id, lnum);
	out_free:
	ubi_free_vid_hdr(ubi, vid_hdr);
	return err;
}
#endif // CONFIG_UBI_CRYPTO_HMAC

/*
 * ubi_eba_atomic_leb_change - change logical eraseblock atomically.
 * @ubi: UBI device description object
 * @vol: volume description object
 * @lnum: logical eraseblock number
 * @buf: data to write
 * @len: how many bytes to write
 *
 * This function changes the contents of a logical eraseblock atomically. @buf
 * has to contain new logical eraseblock data, and @len - the length of the
 * data, which has to be aligned. This function guarantees that in case of an
 * unclean reboot the old contents is preserved. Returns zero in case of
 * success and a negative error code in case of failure.
 *
 * UBI reserves one LEB for the "atomic LEB change" operation, so only one
 * LEB change may be done at a time. This is ensured by @ubi->alc_mutex.
 */
int ubi_eba_atomic_leb_change(struct ubi_device *ubi, struct ubi_volume *vol,
			      int lnum, const void *buf, int len)
{
	int err, pnum, tries = 0, vol_id = vol->vol_id;
	struct ubi_vid_hdr *vid_hdr;
	uint32_t crc;
#ifdef CONFIG_MTD_UBI_CRYPTO
#ifdef CONFIG_UBI_CRYPTO_HMAC
	struct ubi_hmac_hdr *hmac_hdr = NULL;
#endif // CONFIG_UBI_CRYPTO_HMAC
	void *crypt = NULL;
	struct ubi_crypto_cipher_info info = {.ubi = ubi,
                                           .len = len,
	                                       .src = buf,
	                                       .offset = 0,
	                                       .hmac_hdr = NULL
	                                      };
#endif // CONFIG_MTD_UBI_CRYPTO
	if (ubi->ro_mode)
		return -EROFS;

	if (len == 0) {
		/*
		 * Special case when data length is zero. In this case the LEB
		 * has to be unmapped and mapped somewhere else.
		 */
		err = ubi_eba_unmap_leb(ubi, vol, lnum);
		if (err)
			return err;
		return ubi_eba_write_leb(ubi, vol, lnum, NULL, 0, 0);
	}

	vid_hdr = ubi_zalloc_vid_hdr(ubi, GFP_NOFS);
	if (!vid_hdr)
		return -ENOMEM;
#ifdef CONFIG_UBI_CRYPTO_HMAC
	if (NULL == (
		hmac_hdr = ubi_zalloc_hmac_hdr(ubi, GFP_NOFS))) {
		ubi_free_vid_hdr(ubi, vid_hdr);
		return -ENOMEM;
	}
#endif

	mutex_lock(&ubi->alc_mutex);
	err = leb_write_lock(ubi, vol_id, lnum);
	if (err)
		goto out_mutex;

	vid_hdr->sqnum = cpu_to_be64(ubi_next_sqnum(ubi));
	vid_hdr->vol_id = cpu_to_be32(vol_id);
	vid_hdr->lnum = cpu_to_be32(lnum);
	vid_hdr->compat = ubi_get_compat(ubi, vol_id);
	vid_hdr->data_pad = cpu_to_be32(vol->data_pad);

#ifndef CONFIG_MTD_UBI_CRYPTO
	crc = crc32(UBI_CRC32_INIT, buf, len);
#endif
	vid_hdr->vol_type = UBI_VID_DYNAMIC;
	vid_hdr->data_size = cpu_to_be32(len);
	vid_hdr->copy_flag = 1;
#ifndef CONFIG_MTD_UBI_CRYPTO
	vid_hdr->data_crc = cpu_to_be32(crc);
#endif

retry:
	pnum = ubi_wl_get_peb(ubi);
	if (pnum < 0) {
		err = pnum;
		goto out_leb_unlock;
	}

	dbg_eba("change LEB %d:%d, PEB %d, write VID hdr to PEB %d",
		vol_id, lnum, vol->eba_tbl[lnum], pnum);
#ifdef CONFIG_MTD_UBI_CRYPTO
	if (len > 2*PAGE_SIZE) {
		crypt = vmalloc(len);
	} else {
		crypt = kmalloc(len, GFP_NOFS);
	}
	if (NULL == crypt) {
		err = -ENOMEM;
		goto out_leb_unlock;
	}
	info.vid_hdr = vid_hdr;
	info.dst = crypt;
	info.pnum = pnum;
	err = ubi_crypto_cipher(&info);
	if (err) {
		goto out_leb_unlock;
	}
	err = ubi_crypto_compute_hmac_hdr(
			ubi, hmac_hdr, vid_hdr, pnum, crypt, len
			);
	if (err) {
		goto out_leb_unlock;
	}
	crc = crc32(UBI_CRC32_INIT, crypt, len);
	vid_hdr->data_crc = cpu_to_be32(crc);
#endif // CONFIG_MTD_UBI_CRYPTO
	err = ubi_io_write_vid_hdr(ubi, pnum, vid_hdr);
	if (err) {
		ubi_warn("failed to write VID header to LEB %d:%d, PEB %d",
			 vol_id, lnum, pnum);
		goto write_error;
	}
#ifdef CONFIG_UBI_CRYPTO_HMAC
	err = ubi_io_write_hmac_hdr(ubi, pnum, hmac_hdr);
	if (err) {
		ubi_warn("Failed to write HMAC hdr to LEB %d:%d, PEB %d",
			 vol_id, lnum, pnum);
		goto write_error;
	}
#endif // CONFIG_UBI_CRYPTO_HMAC
#ifdef CONFIG_MTD_UBI_CRYPTO
	err = ubi_io_write_data(ubi, crypt, pnum, 0, len);
#else
	err = ubi_io_write_data(ubi, buf, pnum, 0, len);
#endif // CONFIG_MTD_UBI_CRYPTO
	if (err) {
		ubi_warn("failed to write %d bytes of data to PEB %d",
			 len, pnum);
		goto write_error;
	}

	if (vol->eba_tbl[lnum] >= 0) {
		err = ubi_wl_put_peb(ubi, vol_id, lnum, vol->eba_tbl[lnum], 0);
		if (err)
			goto out_leb_unlock;
	}

	down_read(&ubi->fm_sem);
	vol->eba_tbl[lnum] = pnum;
	up_read(&ubi->fm_sem);

out_leb_unlock:
	leb_write_unlock(ubi, vol_id, lnum);
out_mutex:
	mutex_unlock(&ubi->alc_mutex);
#ifdef CONFIG_UBI_CRYPTO_HMAC
	ubi_free_hmac_hdr(ubi, hmac_hdr);
#endif
	ubi_free_vid_hdr(ubi, vid_hdr);
#ifdef CONFIG_MTD_UBI_CRYPTO
	SAFE_FREE(crypt);
#endif // CONFIG_MTD_UBI_CRYPTO
	return err;

write_error:
	if (err != -EIO || !ubi->bad_allowed) {
		/*
		 * This flash device does not admit of bad eraseblocks or
		 * something nasty and unexpected happened. Switch to read-only
		 * mode just in case.
		 */
		ubi_ro_mode(ubi);
		goto out_leb_unlock;
	}

	err = ubi_wl_put_peb(ubi, vol_id, lnum, pnum, 1);
	if (err || ++tries > UBI_IO_RETRIES) {
		ubi_ro_mode(ubi);
		goto out_leb_unlock;
	}

	vid_hdr->sqnum = cpu_to_be64(ubi_next_sqnum(ubi));
	ubi_msg("try another PEB");
	goto retry;
}

/**
 * is_error_sane - check whether a read error is sane.
 * @err: code of the error happened during reading
 *
 * This is a helper function for 'ubi_eba_copy_leb()' which is called when we
 * cannot read data from the target PEB (an error @err happened). If the error
 * code is sane, then we treat this error as non-fatal. Otherwise the error is
 * fatal and UBI will be switched to R/O mode later.
 *
 * The idea is that we try not to switch to R/O mode if the read error is
 * something which suggests there was a real read problem. E.g., %-EIO. Or a
 * memory allocation failed (-%ENOMEM). Otherwise, it is safer to switch to R/O
 * mode, simply because we do not know what happened at the MTD level, and we
 * cannot handle this. E.g., the underlying driver may have become crazy, and
 * it is safer to switch to R/O mode to preserve the data.
 *
 * And bear in mind, this is about reading from the target PEB, i.e. the PEB
 * which we have just written.
 */
static int is_error_sane(int err)
{
	if (err == -EIO || err == -ENOMEM || err == UBI_IO_BAD_HDR ||
	    err == UBI_IO_BAD_HDR_EBADMSG || err == -ETIMEDOUT)
		return 0;
	return 1;
}

/**
 * ubi_eba_copy_leb - copy logical eraseblock.
 * @ubi: UBI device description object
 * @from: physical eraseblock number from where to copy
 * @to: physical eraseblock number where to copy
 * @vid_hdr: VID header of the @from physical eraseblock
 *
 * This function copies logical eraseblock from physical eraseblock @from to
 * physical eraseblock @to. The @vid_hdr buffer may be changed by this
 * function. Returns:
 *   o %0 in case of success;
 *   o %MOVE_CANCEL_RACE, %MOVE_TARGET_WR_ERR, %MOVE_TARGET_BITFLIPS, etc;
 *   o a negative error code in case of failure.
 */
int ubi_eba_copy_leb(struct ubi_device *ubi, int from, int to,
		     struct ubi_vid_hdr *vid_hdr)
{
	int err, vol_id, lnum, data_size, aldata_size, idx;
	struct ubi_volume *vol;
	uint32_t crc;
#ifdef CONFIG_MTD_UBI_CRYPTO
	void *crypt = NULL;
	struct ubi_crypto_cipher_info info = {.ubi = ubi,
                                           .vid_hdr = vid_hdr,
                                           .offset = 0,
                                           .hmac_hdr = NULL
                                          };
#endif
	vol_id = be32_to_cpu(vid_hdr->vol_id);
	lnum = be32_to_cpu(vid_hdr->lnum);
	dbg_wl("copy LEB %d:%d, PEB %d to PEB %d", vol_id, lnum, from, to);

	if (vid_hdr->vol_type == UBI_VID_STATIC) {
		data_size = be32_to_cpu(vid_hdr->data_size);
		aldata_size = ALIGN(data_size, ubi->min_io_size);
	} else
#ifdef CONFIG_UBI_CRYPTO_HMAC
		if (ubi->hmac) {
			data_size = aldata_size =
			ubi->hmac_leb_size - be32_to_cpu(vid_hdr->data_pad);
			info.hmac_hdr = ubi_zalloc_hmac_hdr(ubi, GFP_NOFS);
			if (!info.hmac_hdr)
				return -ENOMEM;
		} else {
#endif // CONFIG_UBI_CRYPTO_HMAC
		data_size = aldata_size =
			    ubi->leb_size - be32_to_cpu(vid_hdr->data_pad);
#ifdef CONFIG_UBI_CRYPTO_HMAC
		}
#endif // CONFIG_UBI_CRYPTO_HMAC
	idx = vol_id2idx(ubi, vol_id);
	spin_lock(&ubi->volumes_lock);
	/*
	 * Note, we may race with volume deletion, which means that the volume
	 * this logical eraseblock belongs to might be being deleted. Since the
	 * volume deletion un-maps all the volume's logical eraseblocks, it will
	 * be locked in 'ubi_wl_put_peb()' and wait for the WL worker to finish.
	 */
	vol = ubi->volumes[idx];
	spin_unlock(&ubi->volumes_lock);
	if (!vol) {
		/* No need to do further work, cancel */
		dbg_wl("volume %d is being removed, cancel", vol_id);
		return MOVE_CANCEL_RACE;
	}

	/*
	 * We do not want anybody to write to this logical eraseblock while we
	 * are moving it, so lock it.
	 *
	 * Note, we are using non-waiting locking here, because we cannot sleep
	 * on the LEB, since it may cause deadlocks. Indeed, imagine a task is
	 * unmapping the LEB which is mapped to the PEB we are going to move
	 * (@from). This task locks the LEB and goes sleep in the
	 * 'ubi_wl_put_peb()' function on the @ubi->move_mutex. In turn, we are
	 * holding @ubi->move_mutex and go sleep on the LEB lock. So, if the
	 * LEB is already locked, we just do not move it and return
	 * %MOVE_RETRY. Note, we do not return %MOVE_CANCEL_RACE here because
	 * we do not know the reasons of the contention - it may be just a
	 * normal I/O on this LEB, so we want to re-try.
	 */
	err = leb_write_trylock(ubi, vol_id, lnum);
	if (err) {
		dbg_wl("contention on LEB %d:%d, cancel", vol_id, lnum);
		return MOVE_RETRY;
	}

	/*
	 * The LEB might have been put meanwhile, and the task which put it is
	 * probably waiting on @ubi->move_mutex. No need to continue the work,
	 * cancel it.
	 */
	if (vol->eba_tbl[lnum] != from) {
		dbg_wl("LEB %d:%d is no longer mapped to PEB %d, mapped to PEB %d, cancel",
		       vol_id, lnum, from, vol->eba_tbl[lnum]);
		err = MOVE_CANCEL_RACE;
		goto out_unlock_leb;
	}

	/*
	 * OK, now the LEB is locked and we can safely start moving it. Since
	 * this function utilizes the @ubi->peb_buf buffer which is shared
	 * with some other functions - we lock the buffer by taking the
	 * @ubi->buf_mutex.
	 */
#ifdef CONFIG_UBI_CRYPTO_HMAC
	err = ubi_io_read_hmac_hdr(ubi, from, info.hmac_hdr, 0);
	if (err)
		goto out_unlock_leb;
#endif // CONFIG_UBI_CRYPTO_HMAC
	mutex_lock(&ubi->buf_mutex);
	dbg_wl("read %d bytes of data", aldata_size);
	err = ubi_io_read_data(ubi, ubi->peb_buf, from, 0, aldata_size);
	if (err && err != UBI_IO_BITFLIPS) {
		ubi_warn("error %d while reading data from PEB %d",
			 err, from);
		err = MOVE_SOURCE_RD_ERR;
		goto out_unlock_buf;
	}

	/*
	 * Now we have got to calculate how much data we have to copy. In
	 * case of a static volume it is fairly easy - the VID header contains
	 * the data size. In case of a dynamic volume it is more difficult - we
	 * have to read the contents, cut 0xFF bytes from the end and copy only
	 * the first part. We must do this to avoid writing 0xFF bytes as it
	 * may have some side-effects. And not only this. It is important not
	 * to include those 0xFFs to CRC because later the they may be filled
	 * by data.
	 */
	if (vid_hdr->vol_type == UBI_VID_DYNAMIC)
		aldata_size = data_size =
			ubi_calc_data_len(ubi, ubi->peb_buf, data_size);

#ifdef CONFIG_MTD_UBI_CRYPTO
	if (0 >= data_size) {
#endif
	cond_resched();
	crc = crc32(UBI_CRC32_INIT, ubi->peb_buf, data_size);
	cond_resched();
#ifdef CONFIG_MTD_UBI_CRYPTO
	}
#endif

	/*
	 * It may turn out to be that the whole @from physical eraseblock
	 * contains only 0xFF bytes. Then we have to only write the VID header
	 * and do not write any data. This also means we should not set
	 * @vid_hdr->copy_flag, @vid_hdr->data_size, and @vid_hdr->data_crc.
	 */
	if (data_size > 0) {
#ifdef CONFIG_MTD_UBI_CRYPTO
		if (data_size > 2*PAGE_SIZE) {
			crypt = vmalloc(data_size);
		} else {
			crypt = kmalloc(data_size, GFP_NOFS);
		}
		if (NULL == crypt) {
			err = MOVE_RETRY;
			goto out_unlock_buf;
		}
#ifdef CONFIG_UBI_CRYPTO_HMAC

#endif
		info.pnum = from;
		info.src = ubi->peb_buf;
		info.dst = crypt;
		info.len = data_size;

		err = ubi_crypto_decipher(&info);
		if (err) {
			err = MOVE_TARGET_WR_ERR;
			goto out_unlock_buf;
		}
#endif // CONFIG_MTD_UBI_CRYPTO
	}

	vid_hdr->sqnum = cpu_to_be64(ubi_next_sqnum(ubi));
#ifdef CONFIG_MTD_UBI_CRYPTO
	info.dst = ubi->peb_buf;
	info.src = crypt;
	info.pnum = to;
	info.hmac_hdr = NULL;
	if (data_size > 0) {
		err = ubi_crypto_cipher(&info);
		if (err) {
			err = MOVE_TARGET_WR_ERR;
			goto out_unlock_buf;
		}
		cond_resched();
		crc = crc32(UBI_CRC32_INIT, crypt, data_size);
		cond_resched();
	}

	err = ubi_crypto_compute_hmac_hdr(
			ubi, info.hmac_hdr, vid_hdr, to,
			ubi->peb_buf, data_size
			);
	if (err) {
		err = MOVE_TARGET_WR_ERR;
		goto out_unlock_buf;
	}
#endif // CONFIG_MTD_UBI_CRYPTO
	vid_hdr->copy_flag = 1;
	vid_hdr->data_size = cpu_to_be32(data_size);
	vid_hdr->data_crc = cpu_to_be32(crc);
	err = ubi_io_write_vid_hdr(ubi, to, vid_hdr);
	if (err) {
		if (err == -EIO)
			err = MOVE_TARGET_WR_ERR;
		goto out_unlock_buf;
	}

	cond_resched();

	/* Read the VID header back and check if it was written correctly */
	err = ubi_io_read_vid_hdr(ubi, to, vid_hdr, 1);
	if (err) {
		if (err != UBI_IO_BITFLIPS) {
			ubi_warn("error %d while reading VID header back from PEB %d",
				 err, to);
			if (is_error_sane(err))
				err = MOVE_TARGET_RD_ERR;
		} else
			err = MOVE_TARGET_BITFLIPS;
		goto out_unlock_buf;
	}

#ifdef CONFIG_UBI_CRYPTO_HMAC
	if (ubi->hmac) {
		err = ubi_io_write_hmac_hdr(ubi, to, info.hmac_hdr);
		if (err) {
			if (err == -EIO)
				err = MOVE_TARGET_WR_ERR;
			goto out_unlock_buf;
		}

		cond_resched();

		/*
		 * We've written the hmac hdr, now we read it back
		 * to ensure it was written correctly
		 */

		err = ubi_io_read_hmac_hdr(ubi, to, info.hmac_hdr, 1);
		if (err) {
			if (err != UBI_IO_BITFLIPS) {
				ubi_warn("error %d while reading VID header back from PEB %d",
					 err, to);
				if (is_error_sane(err))
					err = MOVE_TARGET_RD_ERR;
			} else
				err = MOVE_TARGET_BITFLIPS;
			goto out_unlock_buf;
		}
	}
#endif

	if (data_size > 0) {
		err = ubi_io_write_data(ubi, ubi->peb_buf, to, 0, aldata_size);
		if (err) {
			if (err == -EIO)
				err = MOVE_TARGET_WR_ERR;
			goto out_unlock_buf;
		}

		cond_resched();

		/*
		 * We've written the data and are going to read it back to make
		 * sure it was written correctly.
		 */
		memset(ubi->peb_buf, 0xFF, aldata_size);
		err = ubi_io_read_data(ubi, ubi->peb_buf, to, 0, aldata_size);
		if (err) {
			if (err != UBI_IO_BITFLIPS) {
				ubi_warn("error %d while reading data back from PEB %d",
					 err, to);
				if (is_error_sane(err))
					err = MOVE_TARGET_RD_ERR;
			} else
				err = MOVE_TARGET_BITFLIPS;
			goto out_unlock_buf;
		}

		cond_resched();

		if (crc != crc32(UBI_CRC32_INIT, ubi->peb_buf, data_size)) {
			ubi_warn("read data back from PEB %d and it is different",
				 to);
			err = -EINVAL;
			goto out_unlock_buf;
		}
	}

	ubi_assert(vol->eba_tbl[lnum] == from);
	down_read(&ubi->fm_sem);
	vol->eba_tbl[lnum] = to;
	up_read(&ubi->fm_sem);

out_unlock_buf:
	mutex_unlock(&ubi->buf_mutex);
out_unlock_leb:
	leb_write_unlock(ubi, vol_id, lnum);
#ifdef CONFIG_MTD_UBI_CRYPTO
	SAFE_FREE(crypt);
#endif
	return err;
}

/**
 * print_rsvd_warning - warn about not having enough reserved PEBs.
 * @ubi: UBI device description object
 *
 * This is a helper function for 'ubi_eba_init()' which is called when UBI
 * cannot reserve enough PEBs for bad block handling. This function makes a
 * decision whether we have to print a warning or not. The algorithm is as
 * follows:
 *   o if this is a new UBI image, then just print the warning
 *   o if this is an UBI image which has already been used for some time, print
 *     a warning only if we can reserve less than 10% of the expected amount of
 *     the reserved PEB.
 *
 * The idea is that when UBI is used, PEBs become bad, and the reserved pool
 * of PEBs becomes smaller, which is normal and we do not want to scare users
 * with a warning every time they attach the MTD device. This was an issue
 * reported by real users.
 */
static void print_rsvd_warning(struct ubi_device *ubi,
			       struct ubi_attach_info *ai)
{
	/*
	 * The 1 << 18 (256KiB) number is picked randomly, just a reasonably
	 * large number to distinguish between newly flashed and used images.
	 */
	if (ai->max_sqnum > (1 << 18)) {
		int min = ubi->beb_rsvd_level / 10;

		if (!min)
			min = 1;
		if (ubi->beb_rsvd_pebs > min)
			return;
	}

	ubi_warn("cannot reserve enough PEBs for bad PEB handling, reserved %d, need %d",
		 ubi->beb_rsvd_pebs, ubi->beb_rsvd_level);
	if (ubi->corr_peb_count)
		ubi_warn("%d PEBs are corrupted and not used",
			 ubi->corr_peb_count);
}

/**
 * self_check_eba - run a self check on the EBA table constructed by fastmap.
 * @ubi: UBI device description object
 * @ai_fastmap: UBI attach info object created by fastmap
 * @ai_scan: UBI attach info object created by scanning
 *
 * Returns < 0 in case of an internal error, 0 otherwise.
 * If a bad EBA table entry was found it will be printed out and
 * ubi_assert() triggers.
 */
int self_check_eba(struct ubi_device *ubi, struct ubi_attach_info *ai_fastmap,
		   struct ubi_attach_info *ai_scan)
{
	int i, j, num_volumes, ret = 0;
	int **scan_eba, **fm_eba;
	struct ubi_ainf_volume *av;
	struct ubi_volume *vol;
	struct ubi_ainf_peb *aeb;
	struct rb_node *rb;

	num_volumes = ubi->vtbl_slots + UBI_INT_VOL_COUNT;

	scan_eba = kmalloc(sizeof(*scan_eba) * num_volumes, GFP_KERNEL);
	if (!scan_eba)
		return -ENOMEM;

	fm_eba = kmalloc(sizeof(*fm_eba) * num_volumes, GFP_KERNEL);
	if (!fm_eba) {
		kfree(scan_eba);
		return -ENOMEM;
	}

	for (i = 0; i < num_volumes; i++) {
		vol = ubi->volumes[i];
		if (!vol)
			continue;

		scan_eba[i] = kmalloc(vol->reserved_pebs * sizeof(**scan_eba),
				      GFP_KERNEL);
		if (!scan_eba[i]) {
			ret = -ENOMEM;
			goto out_free;
		}

		fm_eba[i] = kmalloc(vol->reserved_pebs * sizeof(**fm_eba),
				    GFP_KERNEL);
		if (!fm_eba[i]) {
			ret = -ENOMEM;
			goto out_free;
		}

		for (j = 0; j < vol->reserved_pebs; j++)
			scan_eba[i][j] = fm_eba[i][j] = UBI_LEB_UNMAPPED;

		av = ubi_find_av(ai_scan, idx2vol_id(ubi, i));
		if (!av)
			continue;

		ubi_rb_for_each_entry(rb, aeb, &av->root, u.rb)
			scan_eba[i][aeb->lnum] = aeb->pnum;

		av = ubi_find_av(ai_fastmap, idx2vol_id(ubi, i));
		if (!av)
			continue;

		ubi_rb_for_each_entry(rb, aeb, &av->root, u.rb)
			fm_eba[i][aeb->lnum] = aeb->pnum;

		for (j = 0; j < vol->reserved_pebs; j++) {
			if (scan_eba[i][j] != fm_eba[i][j]) {
				if (scan_eba[i][j] == UBI_LEB_UNMAPPED ||
					fm_eba[i][j] == UBI_LEB_UNMAPPED)
					continue;

				ubi_err("LEB:%i:%i is PEB:%i instead of %i!",
					vol->vol_id, i, fm_eba[i][j],
					scan_eba[i][j]);
				ubi_assert(0);
			}
		}
	}

out_free:
	for (i = 0; i < num_volumes; i++) {
		if (!ubi->volumes[i])
			continue;

		kfree(scan_eba[i]);
		kfree(fm_eba[i]);
	}

	kfree(scan_eba);
	kfree(fm_eba);
	return ret;
}

/**
 * ubi_eba_init - initialize the EBA sub-system using attaching information.
 * @ubi: UBI device description object
 * @ai: attaching information
 *
 * This function returns zero in case of success and a negative error code in
 * case of failure.
 */
int ubi_eba_init(struct ubi_device *ubi, struct ubi_attach_info *ai)
{
	int i, j, err, num_volumes;
	struct ubi_ainf_volume *av;
	struct ubi_volume *vol;
	struct ubi_ainf_peb *aeb;
	struct rb_node *rb;

	dbg_eba("initialize EBA sub-system");

	spin_lock_init(&ubi->ltree_lock);
	mutex_init(&ubi->alc_mutex);
	ubi->ltree = RB_ROOT;

	ubi->global_sqnum = ai->max_sqnum + 1;
	num_volumes = ubi->vtbl_slots + UBI_INT_VOL_COUNT;

	for (i = 0; i < num_volumes; i++) {
		vol = ubi->volumes[i];
		if (!vol)
			continue;

		cond_resched();

		vol->eba_tbl = kmalloc(vol->reserved_pebs * sizeof(int),
				       GFP_KERNEL);
		if (!vol->eba_tbl) {
			err = -ENOMEM;
			goto out_free;
		}

		for (j = 0; j < vol->reserved_pebs; j++)
			vol->eba_tbl[j] = UBI_LEB_UNMAPPED;

		av = ubi_find_av(ai, idx2vol_id(ubi, i));
		if (!av)
			continue;

		ubi_rb_for_each_entry(rb, aeb, &av->root, u.rb) {
			if (aeb->lnum >= vol->reserved_pebs)
				/*
				 * This may happen in case of an unclean reboot
				 * during re-size.
				 */
				ubi_move_aeb_to_list(av, aeb, &ai->erase);
			vol->eba_tbl[aeb->lnum] = aeb->pnum;
		}
	}

	if (ubi->avail_pebs < EBA_RESERVED_PEBS) {
		ubi_err("no enough physical eraseblocks (%d, need %d)",
			ubi->avail_pebs, EBA_RESERVED_PEBS);
		if (ubi->corr_peb_count)
			ubi_err("%d PEBs are corrupted and not used",
				ubi->corr_peb_count);
		err = -ENOSPC;
		goto out_free;
	}
	ubi->avail_pebs -= EBA_RESERVED_PEBS;
	ubi->rsvd_pebs += EBA_RESERVED_PEBS;

	if (ubi->bad_allowed) {
		ubi_calculate_reserved(ubi);

		if (ubi->avail_pebs < ubi->beb_rsvd_level) {
			/* No enough free physical eraseblocks */
			ubi->beb_rsvd_pebs = ubi->avail_pebs;
			print_rsvd_warning(ubi, ai);
		} else
			ubi->beb_rsvd_pebs = ubi->beb_rsvd_level;

		ubi->avail_pebs -= ubi->beb_rsvd_pebs;
		ubi->rsvd_pebs  += ubi->beb_rsvd_pebs;
	}

	dbg_eba("EBA sub-system is initialized");
	return 0;

out_free:
	for (i = 0; i < num_volumes; i++) {
		if (!ubi->volumes[i])
			continue;
		kfree(ubi->volumes[i]->eba_tbl);
		ubi->volumes[i]->eba_tbl = NULL;
	}
	return err;
}
