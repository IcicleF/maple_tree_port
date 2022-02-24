/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * include/linux/jdr.h
 * 
 * 2002-10-18  written by Jim Houston jim.houston@ccur.com
 *	Copyright (C) 2002 by Concurrent Computer Corporation
 *
 * Small id to pointer translation service avoiding fixed sized
 * tables.
 */

#ifndef __JDR_H__
#define __JDR_H__

#include "radex-tree.h"
#include <linux/gfp.h>
#include <linux/percpu.h>

struct jdr {
	struct radex_tree_root	jdr_rt;
	unsigned int		jdr_base;
	unsigned int		jdr_next;
};

/*
 * The JDR API does not expose the tagging functionality of the radex tree
 * to users.  Use tag 0 to track whether a node has free space below it.
 */
#define JDR_FREE	0

/* Set the JDR flag and the JDR_FREE tag */
#define JDR_RT_MARKER	(ROOT_IS_JDR | (__force gfp_t)			\
					(1 << (RADEX_ROOT_TAG_SHIFT + JDR_FREE)))

#define JDR_INIT_BASE(name, base) {					\
	.jdr_rt = RADEX_TREE_INIT(name, JDR_RT_MARKER),			\
	.jdr_base = (base),						\
	.jdr_next = 0,							\
}

/**
 * JDR_INIT() - Initialise an JDR.
 * @name: Name of JDR.
 *
 * A freshly-initialised JDR contains no IDs.
 */
#define JDR_INIT(name)	JDR_INIT_BASE(name, 0)

/**
 * DEFINE_JDR() - Define a statically-allocated JDR.
 * @name: Name of JDR.
 *
 * An JDR defined using this macro is ready for use with no additional
 * initialisation required.  It contains no IDs.
 */
#define DEFINE_JDR(name)	struct jdr name = JDR_INIT(name)

/**
 * jdr_get_cursor - Return the current position of the cyclic allocator
 * @jdr: jdr handle
 *
 * The value returned is the value that will be next returned from
 * jdr_alloc_cyclic() if it is free (otherwise the search will start from
 * this position).
 */
static inline unsigned int jdr_get_cursor(const struct jdr *jdr)
{
	return READ_ONCE(jdr->jdr_next);
}

/**
 * jdr_set_cursor - Set the current position of the cyclic allocator
 * @jdr: jdr handle
 * @val: new position
 *
 * The next call to jdr_alloc_cyclic() will return @val if it is free
 * (otherwise the search will start from this position).
 */
static inline void jdr_set_cursor(struct jdr *jdr, unsigned int val)
{
	WRITE_ONCE(jdr->jdr_next, val);
}

/**
 * DOC: jdr sync
 * jdr synchronization (stolen from radex-tree.h)
 *
 * jdr_find() is able to be called locklessly, using RCU. The caller must
 * ensure calls to this function are made within rcu_read_lock() regions.
 * Other readers (lock-free or otherwise) and modifications may be running
 * concurrently.
 *
 * It is still required that the caller manage the synchronization and
 * lifetimes of the items. So if RCU lock-free lookups are used, typically
 * this would mean that the items have their own locks, or are amenable to
 * lock-free access; and that the items are freed by RCU (or only freed after
 * having been deleted from the jdr tree *and* a synchronize_rcu() grace
 * period).
 */

#define jdr_lock(jdr)		xa_lock(&(jdr)->jdr_rt)
#define jdr_unlock(jdr)		xa_unlock(&(jdr)->jdr_rt)
#define jdr_lock_bh(jdr)	xa_lock_bh(&(jdr)->jdr_rt)
#define jdr_unlock_bh(jdr)	xa_unlock_bh(&(jdr)->jdr_rt)
#define jdr_lock_irq(jdr)	xa_lock_irq(&(jdr)->jdr_rt)
#define jdr_unlock_irq(jdr)	xa_unlock_irq(&(jdr)->jdr_rt)
#define jdr_lock_irqsave(jdr, flags) \
				xa_lock_irqsave(&(jdr)->jdr_rt, flags)
#define jdr_unlock_irqrestore(jdr, flags) \
				xa_unlock_irqrestore(&(jdr)->jdr_rt, flags)

void jdr_preload(gfp_t gfp_mask);

int jdr_alloc(struct jdr *, void *ptr, int start, int end, gfp_t);
int __must_check jdr_alloc_u32(struct jdr *, void *ptr, u32 *id,
				unsigned long max, gfp_t);
int jdr_alloc_cyclic(struct jdr *, void *ptr, int start, int end, gfp_t);
void *jdr_remove(struct jdr *, unsigned long id);
void *jdr_find(const struct jdr *, unsigned long id);
int jdr_for_each(const struct jdr *,
		 int (*fn)(int id, void *p, void *data), void *data);
void *jdr_get_next(struct jdr *, int *nextid);
void *jdr_get_next_ul(struct jdr *, unsigned long *nextid);
void *jdr_replace(struct jdr *, void *, unsigned long id);
void jdr_destroy(struct jdr *);

/**
 * jdr_init_base() - Initialise an JDR.
 * @jdr: JDR handle.
 * @base: The base value for the JDR.
 *
 * This variation of jdr_init() creates an JDR which will allocate IDs
 * starting at %base.
 */
static inline void jdr_init_base(struct jdr *jdr, int base)
{
	INIT_RADEX_TREE(&jdr->jdr_rt, JDR_RT_MARKER);
	jdr->jdr_base = base;
	jdr->jdr_next = 0;
}

/**
 * jdr_init() - Initialise an JDR.
 * @jdr: JDR handle.
 *
 * Initialise a dynamically allocated JDR.  To initialise a
 * statically allocated JDR, use DEFINE_JDR().
 */
static inline void jdr_init(struct jdr *jdr)
{
	jdr_init_base(jdr, 0);
}

/**
 * jdr_is_empty() - Are there any IDs allocated?
 * @jdr: JDR handle.
 *
 * Return: %true if any IDs have been allocated from this JDR.
 */
static inline bool jdr_is_empty(const struct jdr *jdr)
{
	return radex_tree_empty(&jdr->jdr_rt) &&
		radex_tree_tagged(&jdr->jdr_rt, JDR_FREE);
}

/**
 * jdr_preload_end - end preload section started with jdr_preload()
 *
 * Each jdr_preload() should be matched with an invocation of this
 * function.  See jdr_preload() for details.
 */
static inline void jdr_preload_end(void)
{
	local_unlock(&radex_tree_preloads.lock);
}

/**
 * jdr_for_each_entry() - Iterate over an JDR's elements of a given type.
 * @jdr: JDR handle.
 * @entry: The type * to use as cursor
 * @id: Entry ID.
 *
 * @entry and @id do not need to be initialized before the loop, and
 * after normal termination @entry is left with the value NULL.  This
 * is convenient for a "not found" value.
 */
#define jdr_for_each_entry(jdr, entry, id)			\
	for (id = 0; ((entry) = jdr_get_next(jdr, &(id))) != NULL; id += 1U)

/**
 * jdr_for_each_entry_ul() - Iterate over an JDR's elements of a given type.
 * @jdr: JDR handle.
 * @entry: The type * to use as cursor.
 * @tmp: A temporary placeholder for ID.
 * @id: Entry ID.
 *
 * @entry and @id do not need to be initialized before the loop, and
 * after normal termination @entry is left with the value NULL.  This
 * is convenient for a "not found" value.
 */
#define jdr_for_each_entry_ul(jdr, entry, tmp, id)			\
	for (tmp = 0, id = 0;						\
	     tmp <= id && ((entry) = jdr_get_next_ul(jdr, &(id))) != NULL; \
	     tmp = id, ++id)

/**
 * jdr_for_each_entry_continue() - Continue iteration over an JDR's elements of a given type
 * @jdr: JDR handle.
 * @entry: The type * to use as a cursor.
 * @id: Entry ID.
 *
 * Continue to iterate over entries, continuing after the current position.
 */
#define jdr_for_each_entry_continue(jdr, entry, id)			\
	for ((entry) = jdr_get_next((jdr), &(id));			\
	     entry;							\
	     ++id, (entry) = jdr_get_next((jdr), &(id)))

/**
 * jdr_for_each_entry_continue_ul() - Continue iteration over an JDR's elements of a given type
 * @jdr: JDR handle.
 * @entry: The type * to use as a cursor.
 * @tmp: A temporary placeholder for ID.
 * @id: Entry ID.
 *
 * Continue to iterate over entries, continuing after the current position.
 */
#define jdr_for_each_entry_continue_ul(jdr, entry, tmp, id)		\
	for (tmp = id;							\
	     tmp <= id && ((entry) = jdr_get_next_ul(jdr, &(id))) != NULL; \
	     tmp = id, ++id)

/*
 * JDA - ID Allocator, use when translation from id to pointer isn't necessary.
 */
#define JDA_CHUNK_SIZE		128	/* 128 bytes per chunk */
#define JDA_BITMAP_LONGS	(JDA_CHUNK_SIZE / sizeof(long))
#define JDA_BITMAP_BITS 	(JDA_BITMAP_LONGS * sizeof(long) * 8)

struct jda_bitmap {
	unsigned long		bitmap[JDA_BITMAP_LONGS];
};

struct jda {
	struct xarray xa;
};

#define JDA_INIT_FLAGS	(XA_FLAGS_LOCK_IRQ | XA_FLAGS_ALLOC)

#define JDA_INIT(name)	{						\
	.xa = XARRAY_INIT(name, JDA_INIT_FLAGS)				\
}
#define DEFINE_JDA(name)	struct jda name = JDA_INIT(name)

int jda_alloc_range(struct jda *, unsigned int min, unsigned int max, gfp_t);
void jda_free(struct jda *, unsigned int id);
void jda_destroy(struct jda *jda);

/**
 * jda_alloc() - Allocate an unused ID.
 * @jda: JDA handle.
 * @gfp: Memory allocation flags.
 *
 * Allocate an ID between 0 and %INT_MAX, inclusive.
 *
 * Context: Any context. It is safe to call this function without
 * locking in your code.
 * Return: The allocated ID, or %-ENOMEM if memory could not be allocated,
 * or %-ENOSPC if there are no free IDs.
 */
static inline int jda_alloc(struct jda *jda, gfp_t gfp)
{
	return jda_alloc_range(jda, 0, ~0, gfp);
}

/**
 * jda_alloc_min() - Allocate an unused ID.
 * @jda: JDA handle.
 * @min: Lowest ID to allocate.
 * @gfp: Memory allocation flags.
 *
 * Allocate an ID between @min and %INT_MAX, inclusive.
 *
 * Context: Any context. It is safe to call this function without
 * locking in your code.
 * Return: The allocated ID, or %-ENOMEM if memory could not be allocated,
 * or %-ENOSPC if there are no free IDs.
 */
static inline int jda_alloc_min(struct jda *jda, unsigned int min, gfp_t gfp)
{
	return jda_alloc_range(jda, min, ~0, gfp);
}

/**
 * jda_alloc_max() - Allocate an unused ID.
 * @jda: JDA handle.
 * @max: Highest ID to allocate.
 * @gfp: Memory allocation flags.
 *
 * Allocate an ID between 0 and @max, inclusive.
 *
 * Context: Any context. It is safe to call this function without
 * locking in your code.
 * Return: The allocated ID, or %-ENOMEM if memory could not be allocated,
 * or %-ENOSPC if there are no free IDs.
 */
static inline int jda_alloc_max(struct jda *jda, unsigned int max, gfp_t gfp)
{
	return jda_alloc_range(jda, 0, max, gfp);
}

static inline void jda_init(struct jda *jda)
{
	xa_init_flags(&jda->xa, JDA_INIT_FLAGS);
}

/*
 * jda_simple_get() and jda_simple_remove() are deprecated. Use
 * jda_alloc() and jda_free() instead respectively.
 */
#define jda_simple_get(jda, start, end, gfp)	\
			jda_alloc_range(jda, start, (end) - 1, gfp)
#define jda_simple_remove(jda, id)	jda_free(jda, id)

static inline bool jda_is_empty(const struct jda *jda)
{
	return xa_empty(&jda->xa);
}
#endif /* __JDR_H__ */
