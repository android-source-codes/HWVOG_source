/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * erofs_utils/include/erofs/defs.h
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 * Modified by Gao Xiang <gaoxiang25@huawei.com>
 */
#ifndef __EROFS_DEFS_H
#define __EROFS_DEFS_H

#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include <inttypes.h>

#include <stdbool.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <linux/types.h>

/*
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 */
#define container_of(ptr, type, member) ({			\
	const typeof(((type *)0)->member) * __mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member)); })

typedef uint8_t         u8;
typedef uint16_t        u16;
typedef uint32_t        u32;
typedef uint64_t        u64;

typedef int8_t          s8;
typedef int16_t         s16;
typedef int32_t         s32;
typedef int64_t         s64;

#ifdef FALSE
#undef FALSE
#endif
#define FALSE    (1 == 0)

#ifdef TRUE
#undef TRUE
#endif
#define TRUE    (1 == 1)

#ifndef NULL
#define NULL    ((void *) 0)
#endif

#define UNUSED(x) (void)(x)

#if __BYTE_ORDER == __LITTLE_ENDIAN
/*
 * The host byte order is the same as network byte order,
 * so these functions are all just identity.
 */
#define cpu_to_le16(x) ((__u16)(x))
#define cpu_to_le32(x) ((__u32)(x))
#define cpu_to_le64(x) ((__u64)(x))
#define le16_to_cpu(x) ((__u16)(x))
#define le32_to_cpu(x) ((__u32)(x))
#define le64_to_cpu(x) ((__u64)(x))

#else
#if __BYTE_ORDER == __BIG_ENDIAN
#define cpu_to_le16(x) (__builtin_bswap16(x))
#define cpu_to_le32(x) (__builtin_bswap32(x))
#define cpu_to_le64(x) (__builtin_bswap64(x))
#define le16_to_cpu(x) (__builtin_bswap16(x))
#define le32_to_cpu(x) (__builtin_bswap32(x))
#define le64_to_cpu(x) (__builtin_bswap64(x))
#else
#pragma error
#endif
#endif

#ifndef __OPTIMIZE__
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2 * !!(condition)]))
#else
#define BUILD_BUG_ON(condition) assert(condition)
#endif

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#define __round_mask(x, y)      ((__typeof__(x))((y)-1))
#define round_up(x, y)          ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y)        ((x) & ~__round_mask(x, y))

/* The `const' in roundup() prevents gcc-3.3 from calling __divdi3 */
#define roundup(x, y) (					\
{							\
	const typeof(y) __y = y;			\
	(((x) + (__y - 1)) / __y) * __y;		\
}							\
)
#define rounddown(x, y) (				\
{							\
	typeof(x) __x = (x);				\
	__x - (__x % (y));				\
}							\
)

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })

/*
 * ..and if you can't take the strict types, you can specify one yourself.
 * Or don't use min/max at all, of course.
 */
#define min_t(type, x, y) ({			\
	type __min1 = (x);			\
	type __min2 = (y);			\
	__min1 < __min2 ? __min1 : __min2; })

#define max_t(type, x, y) ({			\
	type __max1 = (x);			\
	type __max2 = (y);			\
	__max1 > __max2 ? __max1 : __max2; })

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

#define BIT(nr)             (1UL << (nr))
#define BIT_ULL(nr)         (1ULL << (nr))
#define BIT_MASK(nr)        (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)        ((nr) / BITS_PER_LONG)
#define BIT_ULL_MASK(nr)    (1ULL << ((nr) % BITS_PER_LONG_LONG))
#define BIT_ULL_WORD(nr)    ((nr) / BITS_PER_LONG_LONG)
#define BITS_PER_BYTE       8
#define BITS_TO_LONGS(nr)   DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

#define BUG_ON(cond)        assert(!(cond))

#ifdef NDEBUG
#define DBG_BUGON(condition)	((void)(condition))
#else
#define DBG_BUGON(condition)	BUG_ON(condition)
#endif

#endif

