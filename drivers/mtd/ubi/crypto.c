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
 * Herein are the LEB-related cryptographic routines :
 * - Data (de)ciphering with AES-CTR
 * - HMAC LEB authentication
 */

#include "crypto.h"
#include "ubi.h"
#include "ubi-media.h"
#include "debug.h"
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <crypto/algapi.h>

/* Alignment macro for HMAC */
#define UPDIV(a,b) ((a) + (b) - 1)/(b)
#define ALIGN_UP(a,b) (UPDIV(a,b))*(b)

static inline __u8 *ubi_crypto_compute_iv(__be64 sqnum, int offset, int klen);

static int ubi_crypto_get_sg(struct scatterlist **sg,
		void *ptr, unsigned int len,
		unsigned int lpad, unsigned int blk_size);

static void ubi_crypto_sg_recover(struct scatterlist *pad_sg, void *buf,
		unsigned int len, unsigned int blk_size, unsigned int lpad);
void ubi_crypto_sg_free_pad(struct scatterlist *sg);
static void fill_sg(struct scatterlist *sg, u8 *data, unsigned int len);

static int __ubi_crypto_cipher(void *src, void *dst, size_t len, int offset,
		int pnum, struct ubi_key *key, __u8 *iv);

#ifdef CONFIG_UBI_CRYPTO_HMAC
static void compute_hmac_prefix(u8 *prefix,
		struct ubi_vid_hdr *vid_hdr, __be32 len);
static int compute_hmac_key(u8 *hmac_key, unsigned int ksize,
		struct ubi_key *k, __be32 pnum);

static void compute_hmac_prefix(u8 *prefix,
		struct ubi_vid_hdr *vid_hdr, __be32 len)
{
	int i = 0;
	/* Computation of the HMAC tag prefix */
	/*
	 * VID || lnum || sqnum
	 */
	memcpy(prefix, &vid_hdr->vol_id, sizeof(vid_hdr->vol_id));
	i += sizeof(vid_hdr->vol_id);
	memcpy(prefix + i, &vid_hdr->lnum, sizeof(vid_hdr->lnum));
	i += sizeof(vid_hdr->lnum);
	memcpy(prefix + i, &vid_hdr->sqnum, sizeof(vid_hdr->sqnum));
	i += sizeof(vid_hdr->sqnum);
	memcpy(prefix + i, &len, sizeof(len));
}

static int compute_hmac_key(u8 *hmac_key, unsigned int ksize,
		struct ubi_key *k, __be32 pnum)
{
	unsigned int len = min(ksize - sizeof(pnum), k->key_len);

	if (ksize < sizeof(pnum))
		return -EINVAL;

	if (!BAD_PTR(k->key)) {
		memcpy(hmac_key, k->key, len);
	}
	memcpy(hmac_key + ksize - sizeof(pnum), &pnum, sizeof(pnum));
	return 0;
}

/**
 * ubi_crypto_compute_hash - Compute an HMAC tag
 * @unit: The crypto unit that will perform the hash
 * @key: The key used within the HMAC computing
 * @vid_hdr: The VID header object of the target LEB
 * @pnum: The targeted PEB's number
 * @data: Extra data to integrate into the hash
 * @len: Length of @data
 *
 * This function assumes @unit is already acquired and
 * does not perform any pointer checking on it. It needs
 * the @vid_hdr to establish the HMAC prefix using
 * the LEB's sqnum, lnum and volume id. The @pnum is
 * also required since it is used to tweak the key.
 *
 * Finally, the function accepts additionnal data through @data.
 * This way, the same function can be used to compute all the
 * HMAC tags of a particular HMAC header. The caller just
 * has to parse and feed this function the LEB's data appropriately.
 */
u8 *ubi_crypto_compute_hash(struct ubi_crypto_unit *unit,
		struct ubi_key *key, struct ubi_vid_hdr *vid_hdr, __be32 pnum,
		u8 *data, unsigned int len)
{
	int err = 0, nb_sg = 0;
	unsigned int digest_len = 0, prefix_len = 0, key_len = 0;
	u8 *htag_key = NULL, *htag_prefix = NULL, *htag_out = NULL;
	struct scatterlist *sg = NULL;
	struct crypto_hash *hash = (struct crypto_hash*)unit->hmac.tfm;
	struct hash_desc desc = {.tfm = hash, .flags = 0};

	if (BAD_PTR(unit) || BAD_PTR(vid_hdr)) {
		err = -EINVAL;
		goto exit;
	}
	if (!BAD_PTR(key) && !BAD_PTR(key->key)) {
		key_len = key->key_len;
	}
	mutex_lock(&unit->hmac.mutex);
	digest_len = crypto_hash_digestsize(hash);
	prefix_len = ALIGN_UP(UBI_HMAC_PREFIX_LEN, digest_len);

	if (NULL == (htag_out = kzalloc(digest_len, GFP_NOFS))) {
		err = -ENOMEM;
		goto exit_unlock;
	}

	if (!key_len)
		goto exit_unlock;

	key_len = ALIGN_UP(key_len + sizeof(pnum), digest_len);

	if (NULL == (htag_key = kzalloc(key_len, GFP_NOFS))) {
		err = -ENOMEM;
		goto exit_unlock;
	}

	if (NULL == (htag_prefix = kzalloc(prefix_len, GFP_NOFS))) {
		err = - ENOMEM;
		goto exit_unlock;
	}


	if (!BAD_PTR(data) && len) {
		nb_sg = UPDIV(len, PAGE_SIZE) + 1;
		sg = kzalloc(sizeof(struct scatterlist)*nb_sg, GFP_NOFS);
		fill_sg(sg+1, data, len);
	} else {
		len = 0;
		sg = kzalloc(sizeof(struct scatterlist), GFP_NOFS);
		if (NULL == sg) {
			err = -ENOMEM;
			goto exit_unlock;
		}
	}
	sg_set_buf(sg, htag_prefix, prefix_len);

	compute_hmac_prefix(htag_prefix, vid_hdr, len);
	err = compute_hmac_key(htag_key, key_len, key, pnum);
	if (err) {
		/*
		 * Should never ever happen !
		 * Editing the key pointer would have lead
		 * to a segfault hence the %EFAULT error value.
		 */
		err = -EFAULT;
		goto exit_unlock;
	}

	crypto_hash_digest(&desc, sg, len + prefix_len, htag_out);
	exit_unlock:
	mutex_unlock(&unit->hmac.mutex);
	exit:
	if (htag_key)
		kfree(htag_key);

	if (htag_prefix)
		kfree(htag_key);

	if (sg)
		kfree(sg);

	if (err) {
		if (htag_out) {
			kfree(htag_out);
			return ERR_PTR(err);
		}
	}
	return htag_out;
}
#endif // CONFIG_UBI_CRYPTO_HMAC

/**
 * ubi_crypto_compute_iv - Compute the IV for a R/W operation
 * @sqnum: the sequence number of the LEB
 * @offset: the offset of the data to process in the LEB
 * @klen: the cipher key length
 *
 * This function returns a dynamically allocated IV,
 * Remember to free it after usage.
 */
static inline __u8 *ubi_crypto_compute_iv(__be64 sqnum, int offset, int klen)
{
	__u8 *iv = NULL, *p;
	u64 ctr_blk = offset/klen;
	__be64 nonce = sqnum, ctr = cpu_to_be64(ctr_blk);
	if (NULL == (iv = kzalloc(klen, GFP_KERNEL))) {
		return ERR_PTR(-ENOMEM);
	}
	p = iv + klen - sizeof(ctr);
	memcpy(p, &ctr, sizeof(ctr));
	p = p - sizeof(nonce);
	memcpy(p, &nonce, sizeof(nonce));
	return iv;
}

static void fill_sg(struct scatterlist *sg, u8 *data, unsigned int len)
{
	int vmalloced = IS_VMALLOC(data);
	struct page *pg = NULL;
	int offs, shift;

	if (!len || BAD_PTR(data))
		return;

	while (len) {
		offs = offset_in_page(data);
		shift = min(len, PAGE_SIZE - offs);
		if (vmalloced) {
			pg = vmalloc_to_page(data);
		} else {
			pg = virt_to_page(data);
		}
		sg_set_page(sg, pg, shift, offs);
		len -= shift;
		data += shift;
		sg++;
	}
	sg_mark_end(--sg);
}

static int ubi_crypto_get_sg(struct scatterlist **sg,
		void *ptr, unsigned int len,
		unsigned int lpad, unsigned int blk_size)
{
	unsigned int sg_nb = len/PAGE_SIZE +
			(0 != (len%PAGE_SIZE)) +
			(0 != lpad);
	unsigned long to_cpy = 0;
	struct scatterlist *tmp;
	int err = 0;
	void *pad = NULL;

	if (BAD_PTR(ptr) || BAD_PTR(sg) || 0 == len) {
		return -EINVAL;
	}

	*sg = kzalloc(sizeof(struct scatterlist)*sg_nb,
			GFP_KERNEL);
	if (NULL == *sg) {
		return -ENOMEM;
	}
	sg_init_table(*sg, sg_nb);
	if (lpad) {
		to_cpy = min(len, blk_size - lpad);
		pad = kmalloc(blk_size, GFP_KERNEL);
		if (NULL == pad) {
			kfree(*sg);
			*sg = NULL;
			return -ENOMEM;
		}
		memcpy(pad+lpad, ptr, to_cpy);
		sg_set_buf(*sg, pad, blk_size);
		err = to_cpy;
		len -= to_cpy;
		ptr += to_cpy;
	} else {
		to_cpy = 0;
	}
	tmp = (*sg + (0 != lpad));
	fill_sg(tmp, ptr, len);

	return err;
}

static void ubi_crypto_sg_recover(struct scatterlist *pad_sg, void *buf,
		unsigned int len, unsigned int blk_size, unsigned int lpad)
{
	void *pad = sg_virt(pad_sg);
	if (NULL != pad) {
		memcpy(buf, pad + lpad, len);
	}
}

void ubi_crypto_sg_free_pad(struct scatterlist *sg)
{
	void *pad = NULL;
	if (!BAD_PTR(sg)) {
		pad = sg_virt(sg);
		kfree(pad);
	}
}

/**
 * __ubi_crypto_cipher - Perform the ciphering loop
 * @src: input data (plaintext)
 * @dst: memory area to store the ciphertext
 * @len: number of bytes in @src
 * @offset: offset in the LEB
 * @kentry: the key entry of the volume that owns the LEB
 * @iv: the computed IV for the R/W operation
 *
 * Here, @offset is needed to know how many padding bytes must be
 * attached before and after the actual @src data.
 */
static int __ubi_crypto_cipher(void *src, void *dst, size_t len, int offset,
		int pnum, struct ubi_key *key, __u8 *iv)
{
	int err = 0, crypt, to_cpy;
	struct blkcipher_desc desc;
	struct scatterlist *sg_in = NULL, *sg_out = NULL;
	struct ubi_crypto_unit *unit = NULL;
	unsigned int lpad, n, blk_size = key->key_len;
	u8 *tweaked_key = NULL;
	lpad = offset % blk_size;
	n = lpad + len;
	if (!len) {
		return 0;
	}
	if (NULL == (tweaked_key = kzalloc(
			key->key_len, GFP_KERNEL))) {
		return -ENOMEM;
	}
	memcpy(tweaked_key, key->key, key->key_len);
	crypto_xor(tweaked_key, (u8*)&pnum, sizeof(pnum));
	to_cpy = ubi_crypto_get_sg(&sg_in, src, len,
			lpad, blk_size);
	if (0 > to_cpy) {
		err = to_cpy;
		goto exit;
	}
	to_cpy = ubi_crypto_get_sg(&sg_out, dst, len,
			lpad, blk_size);
	if (0 > to_cpy) {
		err = to_cpy;
		goto exit;
	}
	unit = ubi_cru_acquire_unit(&ubi_cru_upool);
	if (!BAD_PTR(unit)) {
		mutex_lock(&unit->aes.mutex);
		desc.tfm = (struct crypto_blkcipher*)unit->aes.tfm;
		desc.flags = 0;
		crypto_blkcipher_set_iv(desc.tfm, iv, key->key_len);
		crypto_blkcipher_setkey(desc.tfm, tweaked_key, key->key_len);
		crypt = crypto_blkcipher_encrypt(
				&desc, sg_out, sg_in, n
				);
		mutex_unlock(&unit->aes.mutex);
		ubi_cru_put_unit(unit, &ubi_cru_upool);
	} else {
		err = PTR_ERR(unit);
	}
	exit:
	if (!err && lpad) {
		/* Recover the beginning of dst buffer */
		ubi_crypto_sg_recover(sg_out, dst, to_cpy, blk_size, lpad);
	}
	if (lpad) {
		ubi_crypto_sg_free_pad(sg_out);
		ubi_crypto_sg_free_pad(sg_in);
	}
	SAFE_FREE(tweaked_key);
	SAFE_FREE(sg_in);
	SAFE_FREE(sg_out);
	return err;
}


/**
 * ubi_crypto_cipher - Cipher the given buffer
 * @ubi_dev: The targeted UBI device
 * @vhdr: A pointer to the VID header of the targeted LEB
 * @src: The source pointer, i.e. the plaintext
 * @dst: The destination pointer, i.e. the place to store the ciphertext
 * @len: The length of the data in @src
 * @offset: The offset in the LEB
 *
 * The @ubi_dev device ID is required to get the good cipher key.
 * This is because multiple UBI devices can be used at the same time.
 * Thus, the volume ID is related to a particular UBI device, hence this dependency.
 * Then, @vhdr contains information used for the ciphering settings (the sqnum)
 */
int ubi_crypto_cipher(struct ubi_crypto_cipher_info *info)
{
	int err = 0;
	int ubi_dev = 0, vol_id = 0;
	struct ubi_key_entry *k = NULL;
	struct ubi_key *key = NULL;
	struct ubi_key_tree *tree = NULL;
	struct ubi_volume *vol;
	__u8 *iv = NULL;
	if (BAD_PTR(info->vid_hdr) ||
			BAD_PTR(info->ubi)) {
		return -EINVAL;
	}
	vol_id = be32_to_cpu(info->vid_hdr->vol_id);
	ubi_dev = info->ubi->ubi_num;
	vol = info->ubi->volumes[vol_id2idx(info->ubi, vol_id)];
	dbg_crypto("len : %u | vol_id : %u | LEB : %u off : %d | sqnum : %llu\n",
			info->len, be32_to_cpu(info->vid_hdr->vol_id),
			be32_to_cpu(info->vid_hdr->lnum), info->offset,
			be64_to_cpu(info->vid_hdr->sqnum));
	if (0 > ubi_dev || UBI_MAX_DEVICES < ubi_dev) {
		err = -EINVAL;
		goto exit;
	}

	/*
	 * Step 1:
	 * Retrieve the key for the volume and mark it as in use.
	 * If %UBI_CRYPTO_HMAC is enabled,
	 * we also have to figure out which key
	 * has to be used for the current LEB.
	 */
	tree = ubi_kmgr_get_tree(ubi_dev);
	if (BAD_PTR(tree)) {
		err = PTR_ERR(tree);
		goto exit;
	}
	/*
	 * FIXME : When HMAC support will be deployed,
	 * We must determine which key has to be used.
	 */
#ifndef CONFIG_UBI_CRYPTO_HMAC
	k = ubi_kmgr_get_kentry(tree, info->vid_hdr->vol_id);
	if (BAD_PTR(k) || 0 == k->cur.key_len || NULL == k->cur.key) {
		if (likely(!((info->dst < info->src + info->len) &&
				(info->dst + info->len > info->src)))) {
			memcpy(info->dst, info->src, info->len);
		}
		err = 0;
		goto exit;
	}
	key = &k->cur;
#else
	while (BAD_PTR(k)) {
#ifdef CONFIG_UBI_CRYPTO_HMAC
		struct ubi_kmgr_set_vol_key_req req = {
				.vol_id = info->vid_hdr->vol_id,
				.vol = vol,
				.tagged = info->ubi->hmac,
				.key = {.k = NULL, .len = 0},
				.main = 1
		};
#endif // CONFIG_UBI_CRYPTO_HMAC
		k = ubi_kmgr_get_kentry(tree, info->vid_hdr->vol_id);

		/*
		 * If k = NULL there is no registered key entry, but we want
		 * to have LEB key information in interval trees, so we
		 * ask for its creation through @ubi_kmgr_setvolkey
		 *
		 * This is a bit inelegant and should be changed
		 */
		if (IS_ERR(k)) {
			err = PTR_ERR(k);
			goto exit;
		} else if (NULL == k) {
			err = ubi_kmgr_setvolkey(tree, &req);
			if (err) {
				dbg_crypto("An error occured while initializing an empty kentry");
				goto exit;
			} else {

			}
		}
	}
	printk("%s - We got the kentry !\n", __func__);
	key = ubi_kmgr_get_leb_key(info->hmac_hdr, info->vid_hdr,
			info->pnum, k, 1);
	if (BAD_PTR(key)) {
		if (-ENODATA == (err = PTR_ERR(key))) {
			dbg_crypto("No matching key found !");
		}
		err = -EACCES;
		goto exit;
	}
	if (!key->key_len) {
		dbg_crypto("<NULL> key : no ciphering");
		if (likely(!((info->dst < info->src + info->len) &&
				(info->dst + info->len > info->src)))) {
			memcpy(info->dst, info->src, info->len);
		} else {
			err = -EINVAL;
		}
		goto exit;
	}
#endif
	/*
	 * TODO : Add HMAC checkings
	 * If the checking fails, simply memcpy the data
	 * without ciphering it.
	 *
	 * We will return a specific error code caught by the UBI layer
	 * UBI will react to preserve data integrity but will not show
	 * any error to the user.
	 *
	 * The key must be marked as bad to prevent volume update if
	 * a new key is set for the same volume later on.
	 */

	/*
	 * Step 2:
	 * Set up the IV
	 */
	iv = ubi_crypto_compute_iv(info->vid_hdr->sqnum,
			info->offset, key->key_len);
	if (unlikely(IS_ERR(iv))) {
		err = PTR_ERR(iv);
		goto exit;
	}
	/*
	 * Step 3:
	 * Do the ciphering
	 */
	if (0 > (err = __ubi_crypto_cipher(info->src, info->dst,
			info->len, info->offset,
			info->pnum, key, iv))) {
		dbg_crypto("Error while ciphering : %d", err);
	}
	exit:
	ubi_kmgr_put_kentry(k);
	ubi_kmgr_put_tree(tree);
	if (likely(!IS_ERR(iv))) {
		kfree(iv);
	}
	return err;
}

/**
 * ubi_crypto_decipher - Decipher the given data
 * @ubi_dev: The targeted UBI device
 * @vhdr: A pointer to the VID header of the targeted LEB
 * @hmac_hdr: A pointer to the HMAC header of the LEB
 * @src: The source pointer, i.e. the ciphertext
 * @dst: The destination pointer, i.e. the place to store the plaintext
 * @len: The length of the data in @src
 * @offset: The offset of @src in the LEB
 *
 * This function is the same as @ubi_crypto_cipher since CTR mode
 * is symmetric. It is declared to make the code clearer.
 * Please, use this function when you intend to decipher data.
 */
inline int ubi_crypto_decipher(struct ubi_crypto_cipher_info *info)
{
	return ubi_crypto_cipher(info);
}
#ifdef CONFIG_UBI_CRYPTO_HMAC
/**
 * ubi_crypto_compute_hmac_hdr - Fills the HMAC tags of a HMAC header
 * @ubi: The ubi device
 * @hmac_hdr: The header to fill
 * @vid_hdr: The VID header of the targeted LEB
 * @data: The data that is about to be written
 * @len: The length of @data
 *
 * This function will be called when a HMAC header
 * will have to be written on the flash (mapping of a new LEB
 * with data, copy of LEB ...).
 *
 * Depending on the context, @data may be %NULL. If so, set
 * @len to %0 for the sake of consistency (otherwise the function
 * returns %EINVAL).
 *
 * It fills the HMAC tags in @hmac_hdr according to the
 * LEB <-> PEB mapping and does not touch the remaining fields
 * of the structure.
 *
 * First, the function searches for the suitable cryptographic key
 * through @ubi_kmgr_get_leb. If that fails, that means the LEB was
 * not mapped before the call to this function. Since this function
 * is called only when something is about to be written on the flash
 * the function retrieves the key registered as the main key for the volume.
 *
 * Possible error values :
 * %ENOMEM: Could not allocate the required resources.
 * %EINVAL: One of the parameters was invalid
 *
 */
int ubi_crypto_compute_hmac_hdr(struct ubi_device *ubi,
		struct ubi_hmac_hdr *hmac_hdr, struct ubi_vid_hdr *vid_hdr,
		int pnum, u8 *data, unsigned int len) {
	int err = 0;
	unsigned int shift = 0, tag_len = 0;
	u32 lnum = 0;
	u8 *hmac = NULL, *dest = NULL;
	__be32 be_pnum = cpu_to_be32(pnum);
	struct ubi_key *key = NULL;
	struct ubi_key_tree *tree = NULL;
	struct ubi_key_entry *kentry = NULL;
	struct ubi_crypto_unit *u = NULL;

	if (BAD_PTR(hmac_hdr) || BAD_PTR(vid_hdr)
		|| (BAD_PTR(data) && len))
		return -EINVAL;
	shift = ubi->hmac_leb_size/2;
	lnum = be32_to_cpu(vid_hdr->lnum);
	len = min(len, (unsigned int)ubi->hmac_leb_size);
	tree = ubi_kmgr_get_tree(ubi->ubi_num);
	kentry = ubi_kmgr_get_kentry(tree, vid_hdr->vol_id);
	if (BAD_PTR(kentry)) {
		err = PTR_ERR(kentry);
		goto exit;
	}
	key = ubi_kmgr_get_leb_key(NULL, vid_hdr, pnum, kentry, 0);
	if (BAD_PTR(key)) {
		if (-ENODATA == (err = PTR_ERR(key))) {
			/*
			 * If the LEB is not registered in any key,
			 * We can still try out with the main key.
			 * This function will only be called when about
			 * to write something to the flash. In this case,
			 * if the key is not found, it's because the LEB
			 * was not on the flash before, thus we use the mainkey.
			 */
			key = ubi_kmgr_get_mainkey(kentry);
			if (-ENODATA == (err = PTR_ERR(key))) {
				goto exit;
			}
			ubi_kval_insert(&key->val_tree, lnum, lnum);
		} else {
			goto exit;
		}
	}
	u = ubi_cru_acquire_unit(&ubi_cru_upool);
	if (BAD_PTR(u)) {
		err = PTR_ERR(u);
		dbg_crypto("Error acquiring unit for HMAC computing : %d",
				err);
		goto exit;
	}
	hmac = ubi_crypto_compute_hash(u, key, vid_hdr,
			be_pnum, NULL, 0);
	if (BAD_PTR(hmac)) {
		err = PTR_ERR(hmac);
		goto exit;
	}
	memcpy(hmac_hdr->htag, hmac, sizeof(hmac_hdr->htag));
	kfree(hmac);
	hmac_hdr->data_len = cpu_to_be32(len);
	dest = hmac_hdr->top_hmac;
	tag_len = sizeof(hmac_hdr->top_hmac);
	/*
	 * Too lazy to write twice the same thing ...
	 * I exploited the __attribute__((packed)) of
	 * hmac_hdr structure to simply compute the two tags
	 *
	 * Please note that this would have to be edited if
	 * the structure was to be modified.
	 */
	while (len) {
		if (shift > len) {
			shift = len;
		}
		hmac = ubi_crypto_compute_hash(u, key, vid_hdr,
				be_pnum, data, shift);
		if (BAD_PTR(hmac)) {
			err = PTR_ERR(hmac);
			break;
		}
		memcpy(dest, hmac, tag_len);
		dest += tag_len;
		data += shift;
		len -= shift;
		kfree(hmac);
	}
	/*
	 * We don't care about the CRC nor the magic number
	 * as they will be appended by default when the header
	 * will be written on the flash.
	 */
	exit:
	if (!BAD_PTR(u)) {
		ubi_cru_put_unit(u, &ubi_cru_upool);
	}
	if (!BAD_PTR(key)) {
		ubi_kmgr_put_key(key);
	}
	if (!BAD_PTR(kentry)) {
		ubi_kmgr_put_kentry(kentry);
	}
	ubi_kmgr_put_tree(tree);
	return err;
}
#endif // CONFIG_UBI_CRYPTO_HMAC

/**
 * ubi_crypto_init - Initialize the UBI cryptographic engine
 */
void ubi_crypto_init(void)
{
	ubi_kmgr_init();
	ubi_cru_init();
}

/**
 * ubi_crypto_term - Clean up the UBI cryptographic engine.
 */
void ubi_crypto_term(void)
{
	ubi_cru_term();
	ubi_kmgr_term();
}
