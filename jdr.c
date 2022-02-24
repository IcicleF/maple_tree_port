// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bitmap.h>
#include <linux/bug.h>
#include <linux/export.h>
#include "jdr.h"
#include <linux/slab.h>
#include <linux/spinlock.h>
#include "xarray.h"

/**
 * jdr_alloc_u32() - Allocate an ID.
 * @jdr: JDR handle.
 * @ptr: Pointer to be associated with the new ID.
 * @nextid: Pointer to an ID.
 * @max: The maximum ID to allocate (inclusive).
 * @gfp: Memory allocation flags.
 *
 * Allocates an unused ID in the range specified by @nextid and @max.
 * Note that @max is inclusive whereas the @end parameter to jdr_alloc()
 * is exclusive.  The new ID is assigned to @nextid before the pointer
 * is inserted into the JDR, so if @nextid points into the object pointed
 * to by @ptr, a concurrent lookup will not find an uninitialised ID.
 *
 * The caller should provide their own locking to ensure that two
 * concurrent modifications to the JDR are not possible.  Read-only
 * accesses to the JDR may be done under the RCU read lock or may
 * exclude simultaneous writers.
 *
 * Return: 0 if an ID was allocated, -ENOMEM if memory allocation failed,
 * or -ENOSPC if no free IDs could be found.  If an error occurred,
 * @nextid is unchanged.
 */
int jdr_alloc_u32(struct jdr *jdr, void *ptr, u32 *nextid,
			unsigned long max, gfp_t gfp)
{
	struct radex_tree_iter iter;
	void __rcu **slot;
	unsigned int base = jdr->jdr_base;
	unsigned int id = *nextid;

	if (WARN_ON_ONCE(!(jdr->jdr_rt.xa_flags & ROOT_IS_JDR)))
		jdr->jdr_rt.xa_flags |= JDR_RT_MARKER;

	id = (id < base) ? 0 : id - base;
	radex_tree_iter_init(&iter, id);
	slot = radex_jdr_get_free(&jdr->jdr_rt, &iter, gfp, max - base);
	if (IS_ERR(slot))
		return PTR_ERR(slot);

	*nextid = iter.index + base;
	/* there is a memory barrier inside radex_tree_iter_replace() */
	radex_tree_iter_replace(&jdr->jdr_rt, &iter, slot, ptr);
	radex_tree_iter_tag_clear(&jdr->jdr_rt, &iter, JDR_FREE);

	return 0;
}
EXPORT_SYMBOL_GPL(jdr_alloc_u32);

/**
 * jdr_alloc() - Allocate an ID.
 * @jdr: JDR handle.
 * @ptr: Pointer to be associated with the new ID.
 * @start: The minimum ID (inclusive).
 * @end: The maximum ID (exclusive).
 * @gfp: Memory allocation flags.
 *
 * Allocates an unused ID in the range specified by @start and @end.  If
 * @end is <= 0, it is treated as one larger than %INT_MAX.  This allows
 * callers to use @start + N as @end as long as N is within integer range.
 *
 * The caller should provide their own locking to ensure that two
 * concurrent modifications to the JDR are not possible.  Read-only
 * accesses to the JDR may be done under the RCU read lock or may
 * exclude simultaneous writers.
 *
 * Return: The newly allocated ID, -ENOMEM if memory allocation failed,
 * or -ENOSPC if no free IDs could be found.
 */
int jdr_alloc(struct jdr *jdr, void *ptr, int start, int end, gfp_t gfp)
{
	u32 id = start;
	int ret;

	if (WARN_ON_ONCE(start < 0))
		return -EINVAL;

	ret = jdr_alloc_u32(jdr, ptr, &id, end > 0 ? end - 1 : INT_MAX, gfp);
	if (ret)
		return ret;

	return id;
}
EXPORT_SYMBOL_GPL(jdr_alloc);

/**
 * jdr_alloc_cyclic() - Allocate an ID cyclically.
 * @jdr: JDR handle.
 * @ptr: Pointer to be associated with the new ID.
 * @start: The minimum ID (inclusive).
 * @end: The maximum ID (exclusive).
 * @gfp: Memory allocation flags.
 *
 * Allocates an unused ID in the range specified by @nextid and @end.  If
 * @end is <= 0, it is treated as one larger than %INT_MAX.  This allows
 * callers to use @start + N as @end as long as N is within integer range.
 * The search for an unused ID will start at the last ID allocated and will
 * wrap around to @start if no free IDs are found before reaching @end.
 *
 * The caller should provide their own locking to ensure that two
 * concurrent modifications to the JDR are not possible.  Read-only
 * accesses to the JDR may be done under the RCU read lock or may
 * exclude simultaneous writers.
 *
 * Return: The newly allocated ID, -ENOMEM if memory allocation failed,
 * or -ENOSPC if no free IDs could be found.
 */
int jdr_alloc_cyclic(struct jdr *jdr, void *ptr, int start, int end, gfp_t gfp)
{
	u32 id = jdr->jdr_next;
	int err, max = end > 0 ? end - 1 : INT_MAX;

	if ((int)id < start)
		id = start;

	err = jdr_alloc_u32(jdr, ptr, &id, max, gfp);
	if ((err == -ENOSPC) && (id > start)) {
		id = start;
		err = jdr_alloc_u32(jdr, ptr, &id, max, gfp);
	}
	if (err)
		return err;

	jdr->jdr_next = id + 1;
	return id;
}
EXPORT_SYMBOL(jdr_alloc_cyclic);

/**
 * jdr_remove() - Remove an ID from the JDR.
 * @jdr: JDR handle.
 * @id: Pointer ID.
 *
 * Removes this ID from the JDR.  If the ID was not previously in the JDR,
 * this function returns %NULL.
 *
 * Since this function modifies the JDR, the caller should provide their
 * own locking to ensure that concurrent modification of the same JDR is
 * not possible.
 *
 * Return: The pointer formerly associated with this ID.
 */
void *jdr_remove(struct jdr *jdr, unsigned long id)
{
	return radex_tree_delete_item(&jdr->jdr_rt, id - jdr->jdr_base, NULL);
}
EXPORT_SYMBOL_GPL(jdr_remove);

/**
 * jdr_find() - Return pointer for given ID.
 * @jdr: JDR handle.
 * @id: Pointer ID.
 *
 * Looks up the pointer associated with this ID.  A %NULL pointer may
 * indicate that @id is not allocated or that the %NULL pointer was
 * associated with this ID.
 *
 * This function can be called under rcu_read_lock(), given that the leaf
 * pointers lifetimes are correctly managed.
 *
 * Return: The pointer associated with this ID.
 */
void *jdr_find(const struct jdr *jdr, unsigned long id)
{
	return radex_tree_lookup(&jdr->jdr_rt, id - jdr->jdr_base);
}
EXPORT_SYMBOL_GPL(jdr_find);

/**
 * jdr_for_each() - Iterate through all stored pointers.
 * @jdr: JDR handle.
 * @fn: Function to be called for each pointer.
 * @data: Data passed to callback function.
 *
 * The callback function will be called for each entry in @jdr, passing
 * the ID, the entry and @data.
 *
 * If @fn returns anything other than %0, the iteration stops and that
 * value is returned from this function.
 *
 * jdr_for_each() can be called concurrently with jdr_alloc() and
 * jdr_remove() if protected by RCU.  Newly added entries may not be
 * seen and deleted entries may be seen, but adding and removing entries
 * will not cause other entries to be skipped, nor spurious ones to be seen.
 */
int jdr_for_each(const struct jdr *jdr,
		int (*fn)(int id, void *p, void *data), void *data)
{
	struct radex_tree_iter iter;
	void __rcu **slot;
	int base = jdr->jdr_base;

	radex_tree_for_each_slot(slot, &jdr->jdr_rt, &iter, 0) {
		int ret;
		unsigned long id = iter.index + base;

		if (WARN_ON_ONCE(id > INT_MAX))
			break;
		ret = fn(id, rcu_dereference_raw(*slot), data);
		if (ret)
			return ret;
	}

	return 0;
}
EXPORT_SYMBOL(jdr_for_each);

/**
 * jdr_get_next_ul() - Find next populated entry.
 * @jdr: JDR handle.
 * @nextid: Pointer to an ID.
 *
 * Returns the next populated entry in the tree with an ID greater than
 * or equal to the value pointed to by @nextid.  On exit, @nextid is updated
 * to the ID of the found value.  To use in a loop, the value pointed to by
 * nextid must be incremented by the user.
 */
void *jdr_get_next_ul(struct jdr *jdr, unsigned long *nextid)
{
	struct radex_tree_iter iter;
	void __rcu **slot;
	void *entry = NULL;
	unsigned long base = jdr->jdr_base;
	unsigned long id = *nextid;

	id = (id < base) ? 0 : id - base;
	radex_tree_for_each_slot(slot, &jdr->jdr_rt, &iter, id) {
		entry = rcu_dereference_raw(*slot);
		if (!entry)
			continue;
		if (!xa_is_internal(entry))
			break;
		if (slot != &jdr->jdr_rt.xa_head && !xa_is_retry(entry))
			break;
		slot = radex_tree_iter_retry(&iter);
	}
	if (!slot)
		return NULL;

	*nextid = iter.index + base;
	return entry;
}
EXPORT_SYMBOL(jdr_get_next_ul);

/**
 * jdr_get_next() - Find next populated entry.
 * @jdr: JDR handle.
 * @nextid: Pointer to an ID.
 *
 * Returns the next populated entry in the tree with an ID greater than
 * or equal to the value pointed to by @nextid.  On exit, @nextid is updated
 * to the ID of the found value.  To use in a loop, the value pointed to by
 * nextid must be incremented by the user.
 */
void *jdr_get_next(struct jdr *jdr, int *nextid)
{
	unsigned long id = *nextid;
	void *entry = jdr_get_next_ul(jdr, &id);

	if (WARN_ON_ONCE(id > INT_MAX))
		return NULL;
	*nextid = id;
	return entry;
}
EXPORT_SYMBOL(jdr_get_next);

/**
 * jdr_replace() - replace pointer for given ID.
 * @jdr: JDR handle.
 * @ptr: New pointer to associate with the ID.
 * @id: ID to change.
 *
 * Replace the pointer registered with an ID and return the old value.
 * This function can be called under the RCU read lock concurrently with
 * jdr_alloc() and jdr_remove() (as long as the ID being removed is not
 * the one being replaced!).
 *
 * Returns: the old value on success.  %-ENOENT indicates that @id was not
 * found.  %-EINVAL indicates that @ptr was not valid.
 */
void *jdr_replace(struct jdr *jdr, void *ptr, unsigned long id)
{
	struct radex_tree_node *node;
	void __rcu **slot = NULL;
	void *entry;

	id -= jdr->jdr_base;

	entry = __radex_tree_lookup(&jdr->jdr_rt, id, &node, &slot);
	if (!slot || radex_tree_tag_get(&jdr->jdr_rt, id, JDR_FREE))
		return ERR_PTR(-ENOENT);

	__radex_tree_replace(&jdr->jdr_rt, node, slot, ptr);

	return entry;
}
EXPORT_SYMBOL(jdr_replace);

/**
 * DOC: JDA description
 *
 * The JDA is an ID allocator which does not provide the ability to
 * associate an ID with a pointer.  As such, it only needs to store one
 * bit per ID, and so is more space efficient than an JDR.  To use an JDA,
 * define it using DEFINE_JDA() (or embed a &struct jda in a data structure,
 * then initialise it using jda_init()).  To allocate a new ID, call
 * jda_alloc(), jda_alloc_min(), jda_alloc_max() or jda_alloc_range().
 * To free an ID, call jda_free().
 *
 * jda_destroy() can be used to dispose of an JDA without needing to
 * free the individual IDs in it.  You can use jda_is_empty() to find
 * out whether the JDA has any IDs currently allocated.
 *
 * The JDA handles its own locking.  It is safe to call any of the JDA
 * functions without synchronisation in your code.
 *
 * IDs are currently limited to the range [0-INT_MAX].  If this is an awkward
 * limitation, it should be quite straightforward to raise the maximum.
 */

/*
 * Developer's notes:
 *
 * The JDA uses the functionality provided by the XArray to store bitmaps in
 * each entry.  The XA_FREE_MARK is only cleared when all bits in the bitmap
 * have been set.
 *
 * I considered telling the XArray that each slot is an order-10 node
 * and indexing by bit number, but the XArray can't allow a single multi-index
 * entry in the head, which would significantly increase memory consumption
 * for the JDA.  So instead we divide the index by the number of bits in the
 * leaf bitmap before doing a radex tree lookup.
 *
 * As an optimisation, if there are only a few low bits set in any given
 * leaf, instead of allocating a 128-byte bitmap, we store the bits
 * as a value entry.  Value entries never have the XA_FREE_MARK cleared
 * because we can always convert them into a bitmap entry.
 *
 * It would be possible to optimise further; once we've run out of a
 * single 128-byte bitmap, we currently switch to a 576-byte node, put
 * the 128-byte bitmap in the first entry and then start allocating extra
 * 128-byte entries.  We could instead use the 512 bytes of the node's
 * data as a bitmap before moving to that scheme.  I do not believe this
 * is a worthwhile optimisation; Rasmus Villemoes surveyed the current
 * users of the JDA and almost none of them use more than 1024 entries.
 * Those that do use more than the 8192 IDs that the 512 bytes would
 * provide.
 *
 * The JDA always uses a lock to alloc/free.  If we add a 'test_bit'
 * equivalent, it will still need locking.  Going to RCU lookup would require
 * using RCU to free bitmaps, and that's not trivial without embedding an
 * RCU head in the bitmap, which adds a 2-pointer overhead to each 128-byte
 * bitmap, which is excessive.
 */

/**
 * jda_alloc_range() - Allocate an unused ID.
 * @jda: JDA handle.
 * @min: Lowest ID to allocate.
 * @max: Highest ID to allocate.
 * @gfp: Memory allocation flags.
 *
 * Allocate an ID between @min and @max, inclusive.  The allocated ID will
 * not exceed %INT_MAX, even if @max is larger.
 *
 * Context: Any context. It is safe to call this function without
 * locking in your code.
 * Return: The allocated ID, or %-ENOMEM if memory could not be allocated,
 * or %-ENOSPC if there are no free IDs.
 */
int jda_alloc_range(struct jda *jda, unsigned int min, unsigned int max,
			gfp_t gfp)
{
	XA_STATE(xas, &jda->xa, min / JDA_BITMAP_BITS);
	unsigned bit = min % JDA_BITMAP_BITS;
	unsigned long flags;
	struct jda_bitmap *bitmap, *alloc = NULL;

	if ((int)min < 0)
		return -ENOSPC;

	if ((int)max < 0)
		max = INT_MAX;

retry:
	xas_lock_irqsave(&xas, flags);
next:
	bitmap = xas_find_marked(&xas, max / JDA_BITMAP_BITS, XA_FREE_MARK);
	if (xas.xa_index > min / JDA_BITMAP_BITS)
		bit = 0;
	if (xas.xa_index * JDA_BITMAP_BITS + bit > max)
		goto nospc;

	if (xa_is_value(bitmap)) {
		unsigned long tmp = xa_to_value(bitmap);

		if (bit < BITS_PER_XA_VALUE) {
			bit = find_next_zero_bit(&tmp, BITS_PER_XA_VALUE, bit);
			if (xas.xa_index * JDA_BITMAP_BITS + bit > max)
				goto nospc;
			if (bit < BITS_PER_XA_VALUE) {
				tmp |= 1UL << bit;
				xas_store(&xas, xa_mk_value(tmp));
				goto out;
			}
		}
		bitmap = alloc;
		if (!bitmap)
			bitmap = kzalloc(sizeof(*bitmap), GFP_NOWAIT);
		if (!bitmap)
			goto alloc;
		bitmap->bitmap[0] = tmp;
		xas_store(&xas, bitmap);
		if (xas_error(&xas)) {
			bitmap->bitmap[0] = 0;
			goto out;
		}
	}

	if (bitmap) {
		bit = find_next_zero_bit(bitmap->bitmap, JDA_BITMAP_BITS, bit);
		if (xas.xa_index * JDA_BITMAP_BITS + bit > max)
			goto nospc;
		if (bit == JDA_BITMAP_BITS)
			goto next;

		__set_bit(bit, bitmap->bitmap);
		if (bitmap_full(bitmap->bitmap, JDA_BITMAP_BITS))
			xas_clear_mark(&xas, XA_FREE_MARK);
	} else {
		if (bit < BITS_PER_XA_VALUE) {
			bitmap = xa_mk_value(1UL << bit);
		} else {
			bitmap = alloc;
			if (!bitmap)
				bitmap = kzalloc(sizeof(*bitmap), GFP_NOWAIT);
			if (!bitmap)
				goto alloc;
			__set_bit(bit, bitmap->bitmap);
		}
		xas_store(&xas, bitmap);
	}
out:
	xas_unlock_irqrestore(&xas, flags);
	if (xas_nomem(&xas, gfp)) {
		xas.xa_index = min / JDA_BITMAP_BITS;
		bit = min % JDA_BITMAP_BITS;
		goto retry;
	}
	if (bitmap != alloc)
		kfree(alloc);
	if (xas_error(&xas))
		return xas_error(&xas);
	return xas.xa_index * JDA_BITMAP_BITS + bit;
alloc:
	xas_unlock_irqrestore(&xas, flags);
	alloc = kzalloc(sizeof(*bitmap), gfp);
	if (!alloc)
		return -ENOMEM;
	xas_set(&xas, min / JDA_BITMAP_BITS);
	bit = min % JDA_BITMAP_BITS;
	goto retry;
nospc:
	xas_unlock_irqrestore(&xas, flags);
	kfree(alloc);
	return -ENOSPC;
}
EXPORT_SYMBOL(jda_alloc_range);

/**
 * jda_free() - Release an allocated ID.
 * @jda: JDA handle.
 * @id: Previously allocated ID.
 *
 * Context: Any context. It is safe to call this function without
 * locking in your code.
 */
void jda_free(struct jda *jda, unsigned int id)
{
	XA_STATE(xas, &jda->xa, id / JDA_BITMAP_BITS);
	unsigned bit = id % JDA_BITMAP_BITS;
	struct jda_bitmap *bitmap;
	unsigned long flags;

	BUG_ON((int)id < 0);

	xas_lock_irqsave(&xas, flags);
	bitmap = xas_load(&xas);

	if (xa_is_value(bitmap)) {
		unsigned long v = xa_to_value(bitmap);
		if (bit >= BITS_PER_XA_VALUE)
			goto err;
		if (!(v & (1UL << bit)))
			goto err;
		v &= ~(1UL << bit);
		if (!v)
			goto delete;
		xas_store(&xas, xa_mk_value(v));
	} else {
		if (!test_bit(bit, bitmap->bitmap))
			goto err;
		__clear_bit(bit, bitmap->bitmap);
		xas_set_mark(&xas, XA_FREE_MARK);
		if (bitmap_empty(bitmap->bitmap, JDA_BITMAP_BITS)) {
			kfree(bitmap);
delete:
			xas_store(&xas, NULL);
		}
	}
	xas_unlock_irqrestore(&xas, flags);
	return;
 err:
	xas_unlock_irqrestore(&xas, flags);
	WARN(1, "jda_free called for id=%d which is not allocated.\n", id);
}
EXPORT_SYMBOL(jda_free);

/**
 * jda_destroy() - Free all IDs.
 * @jda: JDA handle.
 *
 * Calling this function frees all IDs and releases all resources used
 * by an JDA.  When this call returns, the JDA is empty and can be reused
 * or freed.  If the JDA is already empty, there is no need to call this
 * function.
 *
 * Context: Any context. It is safe to call this function without
 * locking in your code.
 */
void jda_destroy(struct jda *jda)
{
	XA_STATE(xas, &jda->xa, 0);
	struct jda_bitmap *bitmap;
	unsigned long flags;

	xas_lock_irqsave(&xas, flags);
	xas_for_each(&xas, bitmap, ULONG_MAX) {
		if (!xa_is_value(bitmap))
			kfree(bitmap);
		xas_store(&xas, NULL);
	}
	xas_unlock_irqrestore(&xas, flags);
}
EXPORT_SYMBOL(jda_destroy);

#ifndef __KERNEL__
extern void xa_dump_index(unsigned long index, unsigned int shift);
#define JDA_CHUNK_SHIFT		ilog2(JDA_BITMAP_BITS)

static void jda_dump_entry(void *entry, unsigned long index)
{
	unsigned long i;

	if (!entry)
		return;

	if (xa_is_node(entry)) {
		struct xa_node *node = xa_to_node(entry);
		unsigned int shift = node->shift + JDA_CHUNK_SHIFT +
			XA_CHUNK_SHIFT;

		xa_dump_index(index * JDA_BITMAP_BITS, shift);
		xa_dump_node(node);
		for (i = 0; i < XA_CHUNK_SIZE; i++)
			jda_dump_entry(node->slots[i],
					index | (i << node->shift));
	} else if (xa_is_value(entry)) {
		xa_dump_index(index * JDA_BITMAP_BITS, ilog2(BITS_PER_LONG));
		pr_cont("value: data %lx [%px]\n", xa_to_value(entry), entry);
	} else {
		struct jda_bitmap *bitmap = entry;

		xa_dump_index(index * JDA_BITMAP_BITS, JDA_CHUNK_SHIFT);
		pr_cont("bitmap: %p data", bitmap);
		for (i = 0; i < JDA_BITMAP_LONGS; i++)
			pr_cont(" %lx", bitmap->bitmap[i]);
		pr_cont("\n");
	}
}

static void jda_dump(struct jda *jda)
{
	struct xarray *xa = &jda->xa;
	pr_debug("jda: %p node %p free %d\n", jda, xa->xa_head,
				xa->xa_flags >> RADEX_ROOT_TAG_SHIFT);
	jda_dump_entry(xa->xa_head, 0);
}
#endif
