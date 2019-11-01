#ifndef __STRACEBACK_TAILCALL_BPF_H
#define __STRACEBACK_TAILCALL_BPF_H

#include <linux/types.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef __NR_openat
#define __NR_openat 257
#endif

#ifndef PIN_GLOBAL_NS
#define PIN_GLOBAL_NS 2
#endif

#define PARAM_LEN 128
/* reexport for Cgo */
const __u64 PARAM_LENGTH = PARAM_LEN;
const __u64 PARAM_PROBE_AT_EXIT_MASK = 0xf000000000000000ULL;
/* special values used to refer to dynamic length */
const __u64 USE_NULL_BYTE_LENGTH = 0x0fffffffffffffffULL;
const __u64 USE_RET_AS_PARAM_LENGTH = 0x0ffffffffffffffeULL;
/* INDEX(x) is not defined (Cgo cannot access macros),
 * use bit arithmetic with mask below to get value and use addition to generate.
 * The current maximum of parameters is 6, so that means only values until 5 may
 * be added to specify the index. The other theoretical limit is 13 since
 * 14 and 15 are reserved as written above 0xff (null-byte length) and
 * 0xfe (ret as param. length). */
const __u64 USE_ARG_INDEX_AS_PARAM_LENGTH = 0x0ffffffffffffff0ULL;
const __u64 USE_ARG_INDEX_AS_PARAM_LENGTH_MASK = 0xfULL;

/*
 *  XX=fe means unsing the return value as buffer
 *  length, XX=ff means using the position of a 0  ----+
 *  byte as buffer length, XX=00, .. ,05 means         |
 *  using the value of arg[0]..arg[5] as length        |
 *                                                     |
 *                                                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   |
 * |fX|                STATIC LENGTH               |   |
 * |--+-----------------------------------------+--|   |
 * |0X|                fffffffffffff            |XX| <-+
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  ^
 *  |
 *  +- if the highest four bit are not 0,
 *     then probe buffer content at sys_exit
 *     (independently from static/dynamic length)
 *
 */

#define SYSCALL_EVENT_TYPE_ENTER 0
#define SYSCALL_EVENT_TYPE_EXIT  1
#define SYSCALL_EVENT_TYPE_CONT  2

struct syscall_event_t {
	__u64 timestamp;
	__u64 typ;

	/* how many syscall_event_cont_t messages to expect after */
	__u16 cont_nr;
	__u16 cpu;
	__u32 id;
	__u64 pid;
	char comm[TASK_COMM_LEN];
	__u64 args[6];
	/* __u64 ret stored in args[0] */
	/* __u64 caps stored in args[1] */
};

struct syscall_event_cont_t {
	__u64 timestamp;
	__u64 typ;
	__u64 index;
	__u64 length;

	char param[PARAM_LEN];
	__u8 failed;
};

struct syscall_def_t {
	__u64 args_len[6];
};

#endif
