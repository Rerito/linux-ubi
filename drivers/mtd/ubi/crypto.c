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

#define TRACE_ENTER(fmt, ...) do {\
	printk(KERN_ALERT "%s - Enter :\n" fmt,__func__, ##__VA_ARGS__);\
	} while (0)

#define TRACE_EXIT(fmt, ...) do {\
	printk(KERN_ALERT "%s - Exit :\n" fmt,__func__, ##__VA_ARGS__);\
	} while (0)


static inline __u8 *ubi_crypto_compute_iv(__be64 sqnum, int offset, int klen);

static int ubi_crypto_get_sg(struct scatterlist **sg,
		void *ptr, unsigned int len,
		unsigned int lpad, unsigned int blk_size);

static void ubi_crypto_sg_recover(struct scatterlist *pad_sg, void *buf,
		unsigned int len, unsigned int blk_size, unsigned int lpad);
void ubi_crypto_sg_free_pad(struct scatterlist *sg);

static int __ubi_crypto_cipher(void *src, void *dst, size_t len, int offset,
		struct ubi_key *key, __u8 *iv);

static inline void print_iv(u8 *iv, int len);
static inline void print_key(u8 *k, int len);

static inline void print_iv(u8 *iv, int len)
{
	int i;
	printk("IV : ");
	for (i = 0; i < len; i++) {
		printk("%#.2x - ", iv[i]);
	}
	printk("\n");
}

static inline void print_key(u8 *k, int len)
{
	int i;
	printk("Key : ");
	for (i = 0; i < len; i++) {
		printk("%#02x - ", k[i]);
	}
	printk("\n");
}


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
	printk("ctr_blk is %llu => ctr is %#llx\n", ctr_blk, ctr);
	p = iv + klen - sizeof(ctr);
	memcpy(p, &ctr, sizeof(ctr));
	p = p - sizeof(nonce);
	memcpy(p, &nonce, sizeof(nonce));
	return iv;
}

static int ubi_crypto_get_sg(struct scatterlist **sg,
		void *ptr, unsigned int len,
		unsigned int lpad, unsigned int blk_size)
{
	unsigned int sg_nb = len/PAGE_SIZE +
			(0 != (len%PAGE_SIZE)) +
			(0 != lpad);
	unsigned long shift = 0, offs = 0, to_cpy = 0;
	struct scatterlist *tmp;
	int vmalloced = IS_VMALLOC(ptr);
	int err = 0, i;
	void *pad = NULL;
	struct page *page = NULL;

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
		printk("%s - Pad : ", __func__);
		for(i = 0; i < blk_size; i++) {
			printk("%#.2x - ", *((char*)pad+i));
		}
		printk("\n");
	} else {
		to_cpy = 0;
	}
	tmp = (*sg + (0 != lpad));

	while (len) {
		offs = offset_in_page(ptr);
		shift = min((unsigned long)len, PAGE_SIZE - offs);
		if (vmalloced) {
			page = vmalloc_to_page(ptr);
		} else {
			page = virt_to_page(ptr);
		}
		sg_set_page(tmp, page, shift, offs);
		len -= shift;
		ptr += shift;
		tmp++;
	}
	sg_mark_end(--tmp);
	return err;
}

static void ubi_crypto_sg_recover(struct scatterlist *pad_sg, void *buf,
		unsigned int len, unsigned int blk_size, unsigned int lpad)
{
	void *pad = sg_virt(pad_sg);
	int i;
	if (NULL != pad) {
		printk("%s - Beginning recovery\n", __func__);
		for (i=0; i < 16; i++) {
			printk("%#.2x - ", *((char*)pad+i));
		}
		printk("\n");
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
		struct ubi_key *key, __u8 *iv)
{
	int err = 0, crypt, to_cpy;
	struct blkcipher_desc desc;
	struct scatterlist *sg_in = NULL, *sg_out = NULL;
	struct ubi_crypto_unit *unit = NULL;
	unsigned int lpad, n, blk_size = key->key_len;
	lpad = offset % blk_size;
	n = lpad + len;
	if (!len) {
		return 0;
	}
	to_cpy = ubi_crypto_get_sg(&sg_in, src, len,
			lpad, blk_size);
	if (0 > to_cpy) {
		printk("An error occured setting input sg.\n");
		err = to_cpy;
		goto exit;
	}
	to_cpy = ubi_crypto_get_sg(&sg_out, dst, len,
			lpad, blk_size);
	if (0 > to_cpy) {
		printk("An error occured setting output sg.\n");
		err = to_cpy;
		goto exit;
	}
	print_key(key->key,
	blk_size);
	unit = ubi_cru_acquire_unit(&ubi_cru_upool);
	if (!BAD_PTR(unit)) {
		mutex_lock(&unit->aes.mutex);
		desc.tfm = (struct crypto_blkcipher*)unit->aes.tfm;
		desc.flags = 0;
		crypto_blkcipher_set_iv(desc.tfm, iv, key->key_len);
		crypto_blkcipher_setkey(desc.tfm, key->key, key->key_len);
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
int ubi_crypto_cipher(int ubi_dev, struct ubi_vid_hdr *vhdr,
		void *src, void *dst, size_t len, int offset)
{
	int err = 0;
	struct ubi_key_entry *k = NULL;
	struct ubi_key *key = NULL;
	struct ubi_key_tree *tree = NULL;
	__u8 *iv = NULL;

	TRACE_ENTER("len : %u | vol_id : %u | LEB : %u off : %d | sqnum : %llu\n",
			len, be32_to_cpu(vhdr->vol_id),
			be32_to_cpu(vhdr->lnum), offset,
			be64_to_cpu(vhdr->sqnum));
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
	k = ubi_kmgr_get_kentry(tree, vhdr->vol_id);
	/*
	 * FIXME : When HMAC support will be deployed,
	 * We must add an additional parameter to this function to state
	 * if we want to use "old" or "cur" key value.
	 */
	if (BAD_PTR(k) || 0 == k->cur.key_len || NULL == k->cur.key) {
		printk("%s - No kentry, omitting ciphering.\n", __func__ );
		if (dst != src) {
			memcpy(dst, src, len);
		}
//		err = -ENODATA;
		err = 0;
		goto exit;
	}
#ifndef CONFIG_UBI_CRYPTO_HMAC
	key = &k->cur;
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
	iv = ubi_crypto_compute_iv(vhdr->sqnum, offset, key->key_len);
	if (unlikely(IS_ERR(iv))) {
		err = PTR_ERR(iv);
		goto exit;
	}
	/*
	 * Step 3:
	 * Do the ciphering
	 */
	if (0 > (err = __ubi_crypto_cipher(src, dst, len, offset, key, iv))) {
		dbg_crypto("Error while ciphering : %d", err);
	}
	exit:
	if (!BAD_PTR(src) && !BAD_PTR(dst)) {
		printk("Src (%d) : ", min(len,48));
		print_iv(src, min(len,48));
		printk("Dst (%d) : ", min(len,48));
		print_iv(dst, min(len,48));
	}
	ubi_kmgr_put_kentry(k);
	ubi_kmgr_put_tree(tree);
	if (likely(!IS_ERR(iv))) {
		kfree(iv);
	}
	TRACE_EXIT("Result : %d\n\n\n\n", err);
	return err;
}

/**
 * ubi_crypto_decipher - Decipher the given data
 * @ubi_dev: The targeted UBI device
 * @vhdr: A pointer to the VID header of the targeted LEB
 * @src: The source pointer, i.e. the ciphertext
 * @dst: The destination pointer, i.e. the place to store the plaintext
 * @len: The length of the data in @src
 * @offset: The offset of @src in the LEB
 *
 * This function is the same as @ubi_crypto_cipher since CTR mode
 * is symmetric. It is declared to make the code clearer.
 * Please, use this function when you intend to decipher data.
 */
inline int ubi_crypto_decipher(int ubi_dev, struct ubi_vid_hdr *vhdr,
		void *src, void *dst, size_t len, int offset)
{
	return ubi_crypto_cipher(ubi_dev, vhdr, src, dst, len, offset);
}

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
