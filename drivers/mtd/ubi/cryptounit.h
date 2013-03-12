

#ifndef _CRYPTO_UNIT_H_
#define _CRYPTO_UNIT_H_

#include <linux/types.h>
#include <linux/jiffies.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/mutex.h>


#define MAX_UNIT_IN_POOL (u32)(NR_CPUS)

/**
 * struct ubi_crypto_unit_pool - An RB-pool to store the crypto units
 * @node: embedded rb-tree node structure for multiple pools management
 * @id: id of the current pool
 * @pool_head: the head of the available units list
 * @busy_head: the head of the busy units list
 * @n_unit: the number of units currently allocated
 * @disposed: set when the pool has been cleared
 * @mutex: a mutex to protect the whole pool
 * @shrinker: a work struct for shrinking the pool
 *
 * The @busy_head is here to keep track of the acquired units.
 * Since a clean-up may be needed at any time, we must be able to
 * recover the units.
 * If @n_unit is greater or equal to %MAX_UNIT_IN_POOL,
 * no unit is allocated and the calling thread waits for an available one.
 *
 * When an cryptographic operation is needed, a unit is acquired
 * If there is no available unit in @pool_head, a new one is allocated.
 * The resulting unit is prepended to @busy_head, thus becoming the new head
 * of the list.
 *
 * When a unit is released and gets back to the pool, it is appended
 * to the end of @pool_head 's list.
 *
 * Finally, a R/W Semaphore @sem protects operations
 * on both @pool_head and @busy_head.
 *
 * The @shrinker is scheduled when an ENOMEM error is encountered
 * somewhere in the _cryptounit_ code.
 * It let the running processes some time to achieve their operations
 * (and potentially to free some memory) before shrinking the pool.
 */
struct ubi_crypto_unit_pool {
	struct list_head pool_head;
	struct list_head busy_head;
	u32 n_unit;
	u8 disposed;
	struct mutex mutex;
	struct work_struct shrinker;
};

struct ubi_crypto_tfm {
	struct crypto_tfm *tfm;
	struct mutex mutex;
};

/**
 * struct ubi_crypto_unit - A unit for on-the-fly encryption in UBI
 * @node: embedded list_head structure
 * @hmac: pointer to the crypto API structure
 *        that forges HMAC authentication tags
 *        + mutex
 * @aes: pointer to the crypto API structure
 *       that ciphers the data using AES-CTR
 *       + mutex
 * @last_use: a timestamp corresponding to the last acquiring of the unit
 * @mutex: a mutex to protect the unit while it's being used
 * @dying: a value to indicate if the unit is being destroyed
 * @in_use: a value to state if the unit is being used
 *
 * A unit consists of both aes and hmac encryption features.
 * This "gathering of the sheeps" is done because @hmac is needed first
 * to check if the encryption or decryption can be done.
 * @aes is used just after, and this way we avoid getting/putting two units.
 *
 * When a thread will effectively use the unit, it will set @in_use.
 * Note that it will do so only if @dying is unset.
 * When the shrinker wants to remove a unit, it marks it as @dying.
 * This way, the thread that is using it will notice it is moribund,
 * stop using it (unsetting @in_use marker) and acquire a valid one.
 */
struct ubi_crypto_unit {
	struct list_head node;
	struct ubi_crypto_tfm aes;
#ifdef CONFIG_UBI_CRYPTO_HMAC
	struct ubi_crypto_tfm hmac;
#endif
	unsigned long last_use;
	struct mutex mutex;
	__u8 dying, in_use;
};

extern struct ubi_crypto_unit_pool ubi_cru_upool;

struct ubi_crypto_unit *ubi_cru_alloc_unit(void);

struct ubi_crypto_unit *ubi_cru_acquire_unit(
		struct ubi_crypto_unit_pool * const pool);
void ubi_cru_put_unit(struct ubi_crypto_unit *unit,
		struct ubi_crypto_unit_pool *pool);

void ubi_cru_delete_unit(struct ubi_crypto_unit *unit,
		struct ubi_crypto_unit_pool *pool);

inline void ubi_cru_recover_pool(struct ubi_crypto_unit_pool *pool);

void ubi_cru_init(void);
void ubi_cru_term(void);


#endif

