/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2001 Momchil Velikov
 * Portions Copyright (C) 2001 Christoph Hellwig
 * Copyright (C) 2006 Nick Piggin
 * Copyright (C) 2012 Konstantin Khlebnikov
 */
#ifndef _LINUX_RADEX_TREE_H
#define _LINUX_RADEX_TREE_H

#include <linux/bitops.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/lockdep.h>
#include "math.h"
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include "xarray.h"
#include "local_lock.h"

/* Keep unconverted code working */
#define radex_tree_root		xarray
#define radex_tree_node		xa_node

struct radex_tree_preload {
	local_lock_t lock;
	unsigned nr;
	/* nodes->parent points to next preallocated node */
	struct radex_tree_node *nodes;
};
DECLARE_PER_CPU(struct radex_tree_preload, radex_tree_preloads);

/*
 * The bottom two bits of the slot determine how the remaining bits in the
 * slot are interpreted:
 *
 * 00 - data pointer
 * 10 - internal entry
 * x1 - value entry
 *
 * The internal entry may be a pointer to the next level in the tree, a
 * sibling entry, or an indicator that the entry in this slot has been moved
 * to another location in the tree and the lookup should be restarted.  While
 * NULL fits the 'data pointer' pattern, it means that there is no entry in
 * the tree for this index (no matter what level of the tree it is found at).
 * This means that storing a NULL entry in the tree is the same as deleting
 * the entry from the tree.
 */
#define RADEX_TREE_ENTRY_MASK		3UL
#define RADEX_TREE_INTERNAL_NODE	2UL

static inline bool radex_tree_is_internal_node(void *ptr)
{
	return ((unsigned long)ptr & RADEX_TREE_ENTRY_MASK) ==
				RADEX_TREE_INTERNAL_NODE;
}

/*** radex-tree API starts here ***/

#define RADEX_TREE_MAP_SHIFT	XA_CHUNK_SHIFT
#define RADEX_TREE_MAP_SIZE	(1UL << RADEX_TREE_MAP_SHIFT)
#define RADEX_TREE_MAP_MASK	(RADEX_TREE_MAP_SIZE-1)

#define RADEX_TREE_MAX_TAGS	XA_MAX_MARKS
#define RADEX_TREE_TAG_LONGS	XA_MARK_LONGS

#define RADEX_TREE_INDEX_BITS  (8 /* CHAR_BIT */ * sizeof(unsigned long))
#define RADEX_TREE_MAX_PATH (DIV_ROUND_UP(RADEX_TREE_INDEX_BITS, \
					  RADEX_TREE_MAP_SHIFT))

/* The JDR tag is stored in the low bits of xa_flags */
#define ROOT_IS_JDR	((__force gfp_t)4)
/* The top bits of xa_flags are used to store the root tags */
#define RADEX_ROOT_TAG_SHIFT	(__GFP_BITS_SHIFT)

#define RADEX_TREE_INIT(name, mask)	XARRAY_INIT(name, mask)

#define RADEX_TREE(name, mask) \
	struct radex_tree_root name = RADEX_TREE_INIT(name, mask)

#define INIT_RADEX_TREE(root, mask) xa_init_flags(root, mask)

static inline bool radex_tree_empty(const struct radex_tree_root *root)
{
	return root->xa_head == NULL;
}

/**
 * struct radex_tree_iter - radex tree iterator state
 *
 * @index:	index of current slot
 * @next_index:	one beyond the last index for this chunk
 * @tags:	bit-mask for tag-iterating
 * @node:	node that contains current slot
 *
 * This radex tree iterator works in terms of "chunks" of slots.  A chunk is a
 * subinterval of slots contained within one radex tree leaf node.  It is
 * described by a pointer to its first slot and a struct radex_tree_iter
 * which holds the chunk's position in the tree and its size.  For tagged
 * iteration radex_tree_iter also holds the slots' bit-mask for one chosen
 * radex tree tag.
 */
struct radex_tree_iter {
	unsigned long	index;
	unsigned long	next_index;
	unsigned long	tags;
	struct radex_tree_node *node;
};

/**
 * Radex-tree synchronization
 *
 * The radex-tree API requires that users provide all synchronisation (with
 * specific exceptions, noted below).
 *
 * Synchronization of access to the data items being stored in the tree, and
 * management of their lifetimes must be completely managed by API users.
 *
 * For API usage, in general,
 * - any function _modifying_ the tree or tags (inserting or deleting
 *   items, setting or clearing tags) must exclude other modifications, and
 *   exclude any functions reading the tree.
 * - any function _reading_ the tree or tags (looking up items or tags,
 *   gang lookups) must exclude modifications to the tree, but may occur
 *   concurrently with other readers.
 *
 * The notable exceptions to this rule are the following functions:
 * __radex_tree_lookup
 * radex_tree_lookup
 * radex_tree_lookup_slot
 * radex_tree_tag_get
 * radex_tree_gang_lookup
 * radex_tree_gang_lookup_tag
 * radex_tree_gang_lookup_tag_slot
 * radex_tree_tagged
 *
 * The first 7 functions are able to be called locklessly, using RCU. The
 * caller must ensure calls to these functions are made within rcu_read_lock()
 * regions. Other readers (lock-free or otherwise) and modifications may be
 * running concurrently.
 *
 * It is still required that the caller manage the synchronization and lifetimes
 * of the items. So if RCU lock-free lookups are used, typically this would mean
 * that the items have their own locks, or are amenable to lock-free access; and
 * that the items are freed by RCU (or only freed after having been deleted from
 * the radex tree *and* a synchronize_rcu() grace period).
 *
 * (Note, rcu_assign_pointer and rcu_dereference are not needed to control
 * access to data items when inserting into or looking up from the radex tree)
 *
 * Note that the value returned by radex_tree_tag_get() may not be relied upon
 * if only the RCU read lock is held.  Functions to set/clear tags and to
 * delete nodes running concurrently with it may affect its result such that
 * two consecutive reads in the same locked section may return different
 * values.  If reliability is required, modification functions must also be
 * excluded from concurrency.
 *
 * radex_tree_tagged is able to be called without locking or RCU.
 */

/**
 * radex_tree_deref_slot - dereference a slot
 * @slot: slot pointer, returned by radex_tree_lookup_slot
 *
 * For use with radex_tree_lookup_slot().  Caller must hold tree at least read
 * locked across slot lookup and dereference. Not required if write lock is
 * held (ie. items cannot be concurrently inserted).
 *
 * radex_tree_deref_retry must be used to confirm validity of the pointer if
 * only the read lock is held.
 *
 * Return: entry stored in that slot.
 */
static inline void *radex_tree_deref_slot(void __rcu **slot)
{
	return rcu_dereference(*slot);
}

/**
 * radex_tree_deref_slot_protected - dereference a slot with tree lock held
 * @slot: slot pointer, returned by radex_tree_lookup_slot
 *
 * Similar to radex_tree_deref_slot.  The caller does not hold the RCU read
 * lock but it must hold the tree lock to prevent parallel updates.
 *
 * Return: entry stored in that slot.
 */
static inline void *radex_tree_deref_slot_protected(void __rcu **slot,
							spinlock_t *treelock)
{
	return rcu_dereference_protected(*slot, lockdep_is_held(treelock));
}

/**
 * radex_tree_deref_retry	- check radex_tree_deref_slot
 * @arg:	pointer returned by radex_tree_deref_slot
 * Returns:	0 if retry is not required, otherwise retry is required
 *
 * radex_tree_deref_retry must be used with radex_tree_deref_slot.
 */
static inline int radex_tree_deref_retry(void *arg)
{
	return unlikely(radex_tree_is_internal_node(arg));
}

/**
 * radex_tree_exception	- radex_tree_deref_slot returned either exception?
 * @arg:	value returned by radex_tree_deref_slot
 * Returns:	0 if well-aligned pointer, non-0 if either kind of exception.
 */
static inline int radex_tree_exception(void *arg)
{
	return unlikely((unsigned long)arg & RADEX_TREE_ENTRY_MASK);
}

int radex_tree_insert(struct radex_tree_root *, unsigned long index,
			void *);
void *__radex_tree_lookup(const struct radex_tree_root *, unsigned long index,
			  struct radex_tree_node **nodep, void __rcu ***slotp);
void *radex_tree_lookup(const struct radex_tree_root *, unsigned long);
void __rcu **radex_tree_lookup_slot(const struct radex_tree_root *,
					unsigned long index);
void __radex_tree_replace(struct radex_tree_root *, struct radex_tree_node *,
			  void __rcu **slot, void *entry);
void radex_tree_iter_replace(struct radex_tree_root *,
		const struct radex_tree_iter *, void __rcu **slot, void *entry);
void radex_tree_replace_slot(struct radex_tree_root *,
			     void __rcu **slot, void *entry);
void radex_tree_iter_delete(struct radex_tree_root *,
			struct radex_tree_iter *iter, void __rcu **slot);
void *radex_tree_delete_item(struct radex_tree_root *, unsigned long, void *);
void *radex_tree_delete(struct radex_tree_root *, unsigned long);
unsigned int radex_tree_gang_lookup(const struct radex_tree_root *,
			void **results, unsigned long first_index,
			unsigned int max_items);
int radex_tree_preload(gfp_t gfp_mask);
int radex_tree_maybe_preload(gfp_t gfp_mask);
void radex_tree_init(void);
void *radex_tree_tag_set(struct radex_tree_root *,
			unsigned long index, unsigned int tag);
void *radex_tree_tag_clear(struct radex_tree_root *,
			unsigned long index, unsigned int tag);
int radex_tree_tag_get(const struct radex_tree_root *,
			unsigned long index, unsigned int tag);
void radex_tree_iter_tag_clear(struct radex_tree_root *,
		const struct radex_tree_iter *iter, unsigned int tag);
unsigned int radex_tree_gang_lookup_tag(const struct radex_tree_root *,
		void **results, unsigned long first_index,
		unsigned int max_items, unsigned int tag);
unsigned int radex_tree_gang_lookup_tag_slot(const struct radex_tree_root *,
		void __rcu ***results, unsigned long first_index,
		unsigned int max_items, unsigned int tag);
int radex_tree_tagged(const struct radex_tree_root *, unsigned int tag);

static inline void radex_tree_preload_end(void)
{
	local_unlock(&radex_tree_preloads.lock);
}

void __rcu **radex_jdr_get_free(struct radex_tree_root *root,
			      struct radex_tree_iter *iter, gfp_t gfp,
			      unsigned long max);

enum {
	RADEX_TREE_ITER_TAG_MASK = 0x0f,	/* tag index in lower nybble */
	RADEX_TREE_ITER_TAGGED   = 0x10,	/* lookup tagged slots */
	RADEX_TREE_ITER_CONTIG   = 0x20,	/* stop at first hole */
};

/**
 * radex_tree_iter_init - initialize radex tree iterator
 *
 * @iter:	pointer to iterator state
 * @start:	iteration starting index
 * Returns:	NULL
 */
static __always_inline void __rcu **
radex_tree_iter_init(struct radex_tree_iter *iter, unsigned long start)
{
	/*
	 * Leave iter->tags uninitialized. radex_tree_next_chunk() will fill it
	 * in the case of a successful tagged chunk lookup.  If the lookup was
	 * unsuccessful or non-tagged then nobody cares about ->tags.
	 *
	 * Set index to zero to bypass next_index overflow protection.
	 * See the comment in radex_tree_next_chunk() for details.
	 */
	iter->index = 0;
	iter->next_index = start;
	return NULL;
}

/**
 * radex_tree_next_chunk - find next chunk of slots for iteration
 *
 * @root:	radex tree root
 * @iter:	iterator state
 * @flags:	RADEX_TREE_ITER_* flags and tag index
 * Returns:	pointer to chunk first slot, or NULL if there no more left
 *
 * This function looks up the next chunk in the radex tree starting from
 * @iter->next_index.  It returns a pointer to the chunk's first slot.
 * Also it fills @iter with data about chunk: position in the tree (index),
 * its end (next_index), and constructs a bit mask for tagged iterating (tags).
 */
void __rcu **radex_tree_next_chunk(const struct radex_tree_root *,
			     struct radex_tree_iter *iter, unsigned flags);

/**
 * radex_tree_iter_lookup - look up an index in the radex tree
 * @root: radex tree root
 * @iter: iterator state
 * @index: key to look up
 *
 * If @index is present in the radex tree, this function returns the slot
 * containing it and updates @iter to describe the entry.  If @index is not
 * present, it returns NULL.
 */
static inline void __rcu **
radex_tree_iter_lookup(const struct radex_tree_root *root,
			struct radex_tree_iter *iter, unsigned long index)
{
	radex_tree_iter_init(iter, index);
	return radex_tree_next_chunk(root, iter, RADEX_TREE_ITER_CONTIG);
}

/**
 * radex_tree_iter_retry - retry this chunk of the iteration
 * @iter:	iterator state
 *
 * If we iterate over a tree protected only by the RCU lock, a race
 * against deletion or creation may result in seeing a slot for which
 * radex_tree_deref_retry() returns true.  If so, call this function
 * and continue the iteration.
 */
static inline __must_check
void __rcu **radex_tree_iter_retry(struct radex_tree_iter *iter)
{
	iter->next_index = iter->index;
	iter->tags = 0;
	return NULL;
}

static inline unsigned long
__radex_tree_iter_add(struct radex_tree_iter *iter, unsigned long slots)
{
	return iter->index + slots;
}

/**
 * radex_tree_iter_resume - resume iterating when the chunk may be invalid
 * @slot: pointer to current slot
 * @iter: iterator state
 * Returns: New slot pointer
 *
 * If the iterator needs to release then reacquire a lock, the chunk may
 * have been invaljdated by an insertion or deletion.  Call this function
 * before releasing the lock to continue the iteration from the next index.
 */
void __rcu **__must_check radex_tree_iter_resume(void __rcu **slot,
					struct radex_tree_iter *iter);

/**
 * radex_tree_chunk_size - get current chunk size
 *
 * @iter:	pointer to radex tree iterator
 * Returns:	current chunk size
 */
static __always_inline long
radex_tree_chunk_size(struct radex_tree_iter *iter)
{
	return iter->next_index - iter->index;
}

/**
 * radex_tree_next_slot - find next slot in chunk
 *
 * @slot:	pointer to current slot
 * @iter:	pointer to iterator state
 * @flags:	RADEX_TREE_ITER_*, should be constant
 * Returns:	pointer to next slot, or NULL if there no more left
 *
 * This function updates @iter->index in the case of a successful lookup.
 * For tagged lookup it also eats @iter->tags.
 *
 * There are several cases where 'slot' can be passed in as NULL to this
 * function.  These cases result from the use of radex_tree_iter_resume() or
 * radex_tree_iter_retry().  In these cases we don't end up dereferencing
 * 'slot' because either:
 * a) we are doing tagged iteration and iter->tags has been set to 0, or
 * b) we are doing non-tagged iteration, and iter->index and iter->next_index
 *    have been set up so that radex_tree_chunk_size() returns 1 or 0.
 */
static __always_inline void __rcu **radex_tree_next_slot(void __rcu **slot,
				struct radex_tree_iter *iter, unsigned flags)
{
	if (flags & RADEX_TREE_ITER_TAGGED) {
		iter->tags >>= 1;
		if (unlikely(!iter->tags))
			return NULL;
		if (likely(iter->tags & 1ul)) {
			iter->index = __radex_tree_iter_add(iter, 1);
			slot++;
			goto found;
		}
		if (!(flags & RADEX_TREE_ITER_CONTIG)) {
			unsigned offset = __ffs(iter->tags);

			iter->tags >>= offset++;
			iter->index = __radex_tree_iter_add(iter, offset);
			slot += offset;
			goto found;
		}
	} else {
		long count = radex_tree_chunk_size(iter);

		while (--count > 0) {
			slot++;
			iter->index = __radex_tree_iter_add(iter, 1);

			if (likely(*slot))
				goto found;
			if (flags & RADEX_TREE_ITER_CONTIG) {
				/* forbid switching to the next chunk */
				iter->next_index = 0;
				break;
			}
		}
	}
	return NULL;

 found:
	return slot;
}

/**
 * radex_tree_for_each_slot - iterate over non-empty slots
 *
 * @slot:	the void** variable for pointer to slot
 * @root:	the struct radex_tree_root pointer
 * @iter:	the struct radex_tree_iter pointer
 * @start:	iteration starting index
 *
 * @slot points to radex tree slot, @iter->index contains its index.
 */
#define radex_tree_for_each_slot(slot, root, iter, start)		\
	for (slot = radex_tree_iter_init(iter, start) ;			\
	     slot || (slot = radex_tree_next_chunk(root, iter, 0)) ;	\
	     slot = radex_tree_next_slot(slot, iter, 0))

/**
 * radex_tree_for_each_tagged - iterate over tagged slots
 *
 * @slot:	the void** variable for pointer to slot
 * @root:	the struct radex_tree_root pointer
 * @iter:	the struct radex_tree_iter pointer
 * @start:	iteration starting index
 * @tag:	tag index
 *
 * @slot points to radex tree slot, @iter->index contains its index.
 */
#define radex_tree_for_each_tagged(slot, root, iter, start, tag)	\
	for (slot = radex_tree_iter_init(iter, start) ;			\
	     slot || (slot = radex_tree_next_chunk(root, iter,		\
			      RADEX_TREE_ITER_TAGGED | tag)) ;		\
	     slot = radex_tree_next_slot(slot, iter,			\
				RADEX_TREE_ITER_TAGGED | tag))

#endif /* _LINUX_RADEX_TREE_H */
