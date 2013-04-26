

#ifndef _UBI_CRYPTO_H_
#define _UBI_CRYPTO_H_

#include "cryptounit.h"
#include "cryptokmgr.h"
#include <linux/mm.h>
#include <asm-generic/pgtable.h>
#include <linux/scatterlist.h>

struct ubi_vid_hdr;

#ifdef CONFIG_UBI_CRYPTO_HMAC
#define UBI_HMAC_PREFIX_LEN 20
#endif

/**
 * struct ubi_crypto_cipher_info - Ciphering information
 * @pnum: The target PEB number
 * @offset: The offset in the LEB
 * @ubi_dev: The number of the ubi device
 * @len: The length of the data
 * @src: Text to be processed
 * @dst: Output for the (de)ciphered data
 * @vhdr: VID header of the target LEB
 * @hmac_hdr: HMAC header of the target LEB
 *
 * This structure gathers all the required information
 * to perform an encryption/decryption operation.
 */
struct ubi_crypto_cipher_info {
	int pnum, offset;
	size_t len;
	u8 *src, *dst;
	struct ubi_vid_hdr *vid_hdr;
	struct ubi_device *ubi;
#ifdef CONFIG_UBI_CRYPTO_HMAC
	struct ubi_hmac_hdr *hmac_hdr;
#endif
};

#ifndef BAD_PTR
#define BAD_PTR(ptr) ((NULL == (ptr)) || (IS_ERR((ptr))))
#endif

#define IS_VMALLOC(ptr) ((VMALLOC_END >= (unsigned long)(ptr)) &&\
		(VMALLOC_START <= (unsigned long)(ptr)))

#define SAFE_FREE(ptr) do {\
		if (!BAD_PTR(ptr)) {\
			(IS_VMALLOC((ptr))) ? vfree((ptr)) :	kfree((ptr));\
			(ptr) = NULL;\
		}\
	}while(0)

int ubi_crypto_cipher(struct ubi_crypto_cipher_info *info);
inline int ubi_crypto_decipher(struct ubi_crypto_cipher_info *info);

#ifdef CONFIG_UBI_CRYPTO_HMAC
u8 *ubi_crypto_compute_hash(struct ubi_crypto_unit *unit,
		struct ubi_key *key, struct ubi_vid_hdr *vid_hdr, __be32 pnum,
		u8 *data, unsigned int len);
int ubi_crypto_compute_hmac_hdr(struct ubi_device *ubi,
		struct ubi_hmac_hdr *hmac_hdr, struct ubi_vid_hdr *vid_hdr,
		int pnum, u8 *data, unsigned int len);
#endif // CONFIG_UBI_CRYPTO_HMAC

void ubi_crypto_init(void);
void ubi_crypto_term(void);

#endif
