

#ifndef _UBI_CRYPTO_H_
#define _UBI_CRYPTO_H_

#include "cryptounit.h"
#include "cryptokmgr.h"
#include <linux/mm.h>
#include <asm-generic/pgtable.h>

struct ubi_vid_hdr;

#define UBI_CRYPTO_CHUNK_SIZE 8

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

int ubi_crypto_cipher(int ubi_dev, struct ubi_vid_hdr *vhdr,
		void *src, void *dst, size_t len, int offset);
inline int ubi_crypto_decipher(int ubi_dev, struct ubi_vid_hdr *vhdr,
		void *src, void *dst, size_t len, int offset);

void ubi_crypto_init(void);
void ubi_crypto_term(void);

#endif
