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
 * This file implements the operations on cryptographic units for UBI
 * It consists mostly of SMP handling (unit pool, locking scheme ...)
 * The related functions are tagged "cru" (for CRypto Unit)
 */

#include "cryptounit.h"

#define BAD_PTR(ptr) (((ptr) == NULL) || (IS_ERR((ptr))))

struct ubi_crypto_unit_pool ubi_cru_upool;

static void ubi_cru_free_unit(struct ubi_crypto_unit *unit);

static struct ubi_crypto_unit *ubi_cru_get_unit(struct ubi_crypto_unit_pool *pool);

static inline void ubi_cru_init_pool(struct ubi_crypto_unit_pool *pool);
static void ubi_cru_clear_pool(struct ubi_crypto_unit_pool *pool);

/**
 * ubi_cru_alloc_unit - allocate a new crypto unit
 * This function allocates a crypto unit
 * and the underlying crypto transforms (aes and hmac)
 *
 * It returns a pointer to the newly allocated resource,
 * Or an error pointer.
 */
struct ubi_crypto_unit *ubi_cru_alloc_unit(void)
{
	struct ubi_crypto_unit *p = NULL;
	int err = 0;
	if (NULL == (p = kzalloc(sizeof(*p), GFP_KERNEL))) {
		err = -ENOMEM;
		goto exit;
	}
	p->aes.tfm = (struct crypto_tfm*)crypto_alloc_blkcipher("ctr(aes)", 0, 0);
	if (IS_ERR(p->aes.tfm)) {
		err = PTR_ERR(p->aes.tfm);
		goto exit;
	}

#ifdef CONFIG_UBI_CRYPTO_HMAC
	p->hmac.tfm = (struct crypto_tfm*)crypto_alloc_hash("hmac(sha1)", 0, 0);
	if (IS_ERR(p->hmac.tfm)) {
		crypto_free_blkcipher((struct crypto_blkcipher*)p->aes.tfm);
		err = PTR_ERR(p->hmac.tfm);
		goto exit;
	}
	printk("Successfully allocated HMAC transform object.\n");
	mutex_init(&p->hmac.mutex);
#endif
	mutex_init(&p->mutex);
	mutex_init(&p->aes.mutex);

	exit:
	if (err) {
		if (p) {
			kfree(p);
		}
		p = ERR_PTR(err);
	}
	return p;
}

/**
 * ubi_cru_free_unit - Frees a crypto unit
 * @unit: the unit to free
 * The unit must be marked as dying and must not be in
 * any pool's busy/available lists.
 */
static void ubi_cru_free_unit(struct ubi_crypto_unit *unit)
{
	if (IS_ERR(unit) || NULL == unit) {
		return;
	}

	mutex_lock(&unit->mutex);
	while (unit->in_use) {
		mutex_unlock(&unit->mutex);
		msleep(20);
		mutex_lock(&unit->mutex);
	}
	list_del(&unit->node);
	mutex_lock(&unit->aes.mutex);
	crypto_free_blkcipher((struct crypto_blkcipher*)unit->aes.tfm);
	unit->aes.tfm = NULL;
	mutex_unlock(&unit->aes.mutex);
#ifdef CONFIG_UBI_CRYPTO_HMAC
	mutex_lock(&unit->hmac.mutex);
	crypto_free_hash((struct crypto_hash*)unit->hmac.tfm);
	mutex_unlock(&unit->hmac.mutex);
#endif
	mutex_unlock(&unit->mutex);
	kfree(unit);
}

/**
 * ubi_cru_delete_unit -
 */
void ubi_cru_delete_unit(struct ubi_crypto_unit *unit,
		struct ubi_crypto_unit_pool *pool)
{
	if (BAD_PTR(unit) || (BAD_PTR(pool))) {
		return;
	}
	mutex_lock(&pool->mutex);
	list_del_init(&unit->node);
	mutex_lock(&unit->mutex);
	unit->dying = 1;
	mutex_unlock(&unit->mutex);
	mutex_unlock(&pool->mutex);
	ubi_cru_free_unit(unit);
	mutex_lock(&pool->mutex);
	pool->n_unit--;
	mutex_unlock(&pool->mutex);
}

/**
 * ubi_cru_get_unit - get the crypto unit bound to the given cpu
 * @pool: the crypto_unit pool
 * @n_cpu: the cpu index
 *
 * Return values :
 * A pointer to the requested crypto unit.
 * If no unit were available, NULL is returned.
 */
static struct ubi_crypto_unit *ubi_cru_get_unit(struct ubi_crypto_unit_pool *pool)
{
	u8 ok = 0;
	struct ubi_crypto_unit *p = NULL;
	struct list_head *tmp = NULL;
	if (pool->disposed) {
		return ERR_PTR(-EPERM);
	}
	if (!list_empty(&pool->pool_head)) {
		tmp = &pool->pool_head;
		while (!ok) {
			tmp = tmp->next;
			if (tmp == &pool->pool_head) {
				p = NULL;
				break;
			}
			p = list_entry(tmp, struct ubi_crypto_unit, node);
			mutex_lock(&p->mutex);
			if (!p->dying) {
				ok = 1;
			} else {
				mutex_unlock(&p->mutex);
			}
		}
		if (NULL != p) {
			list_move_tail(tmp, &pool->busy_head);
			p->in_use = 1;
			mutex_unlock(&p->mutex);
		}
	}
	return p;
}



/**
 * ubi_cru_acquire_unit - Get a CPU unit or allocate it if needed
 * @pool: The unit pool
 *
 * This function gets a unit from the pool if it can.
 * The returned unit must then be released with @ubi_cru_put_unit
 * Possible errors :
 * %EPERM : The pool is "disposed" and no unit can be acquired
 * %EINVAL : Bad pointer
 */
struct ubi_crypto_unit *ubi_cru_acquire_unit(
		struct ubi_crypto_unit_pool * const pool)
{
	struct ubi_crypto_unit *unit = NULL;
	int err = 0;
	if (BAD_PTR(pool)) {
		err = -EINVAL;
		goto exit;
	}
	while (NULL == unit) {
		mutex_lock(&pool->mutex);
		if (NULL == (unit = ubi_cru_get_unit(pool))) {
			printk(KERN_ALERT "No available unit ...\n");
		    if (MAX_UNIT_IN_POOL < pool->n_unit) {
		    	mutex_unlock(&pool->mutex);
		    	msleep(20);
		    } else {
		    	unit = ubi_cru_alloc_unit();
		    	if (unlikely(IS_ERR(unit))) {
		    		break;
		    	}
		    	unit->last_use = jiffies;
		    	unit->in_use = 1;
		    	list_add_tail(&unit->node, &pool->busy_head);
		    	pool->n_unit++;
		    }
		}
	}
	mutex_unlock(&pool->mutex);
	exit:
	if (err) {
		unit = ERR_PTR(err);
	}
	return unit;
}

/**
 * ubi_cru_put_unit - Put back a unit in the given pool
 * @unit: the unit to return
 * @pool: the pool to which the unit is put back
 *
 * This function puts back @unit in @pool 's available unit list.
 * This function must be used if @unit was previously obtained
 * using @ubi_cru_acquire_unit.
 * @warning Never call this function with the wrong @pool argument :
 * This would mess up the pool to which @unit really belongs and the
 * wrong supplied pool.
 * If @unit is dying, i.e. scheduled for erasure, the function simply
 * updates the in_use marker.
 */
void ubi_cru_put_unit(struct ubi_crypto_unit *unit,
		struct ubi_crypto_unit_pool *pool)
{
	if (BAD_PTR(unit) || BAD_PTR(pool)) {
		return;
	}
	mutex_lock(&pool->mutex);
	mutex_lock(&unit->mutex);
	if (!unit->dying) {
		list_move(&unit->node, &pool->pool_head);
	}
	unit->in_use = 0;
	mutex_unlock(&unit->mutex);
	mutex_unlock(&pool->mutex);
}

/**
 * ubi_cru_init_pool - Initialize the given pool
 * @pool: the pool to initialize
 */
static inline void ubi_cru_init_pool(struct ubi_crypto_unit_pool *pool)
{
	INIT_LIST_HEAD(&pool->pool_head);
	INIT_LIST_HEAD(&pool->busy_head);
	mutex_init(&pool->mutex);
	pool->n_unit = 0;
}

inline void ubi_cru_recover_pool(struct ubi_crypto_unit_pool *pool)
{
	if (!BAD_PTR(pool)) {
		mutex_lock(&pool->mutex);
		pool->disposed = 0;
		mutex_unlock(&pool->mutex);
	}
}

/**
 * ubi_cru_clear_pool - Clear the given pool
 *
 */
static void ubi_cru_clear_pool(struct ubi_crypto_unit_pool *pool)
{
	struct ubi_crypto_unit *unit;
	LIST_HEAD(del_list);
	struct list_head *node = NULL;
	if (BAD_PTR(pool)) {
		return;
	}
	mutex_lock(&pool->mutex);

	while (!list_empty(&pool->pool_head)) {
		node = pool->pool_head.next;
		list_move(node, &del_list);
	}

	while (!list_empty(&pool->busy_head)) {
		node = pool->busy_head.next;
		unit = list_entry(node, struct ubi_crypto_unit, node);
		mutex_lock(&unit->mutex);
		unit->dying = 1;
		mutex_unlock(&unit->mutex);
		list_move(node, &del_list);
	}
	pool->n_unit = 0;
	pool->disposed = 1;
	mutex_unlock(&pool->mutex);
	/* FIXME
	 * The pool must be marked as being cleaned
	 * Otherwise, new unit could be created while the cleaning
	 * process is running.
	 */
	while(!list_empty(&del_list)) {
		node = del_list.next;
		unit = list_entry(node, struct ubi_crypto_unit, node);
		ubi_cru_free_unit(unit);
	}
}

void ubi_cru_clear_pool_wrapper(void *pool)
{
	ubi_cru_clear_pool((struct ubi_crypto_unit_pool*)pool);
}

void ubi_cru_init(void)
{
	ubi_cru_init_pool(&ubi_cru_upool);
}

void ubi_cru_term(void)
{
	ubi_cru_clear_pool(&ubi_cru_upool);
}
