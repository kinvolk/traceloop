#ifndef __STRACEBACK_GUESS_BPF_H
#define __STRACEBACK_GUESS_BPF_H

#include <linux/types.h>

#define GUESS_PIDNS 0

#define GUESS_STATE_UNINITIALIZED 0
#define GUESS_STATE_CHECKING      1
#define GUESS_STATE_CHECKED       2
#define GUESS_STATE_READY         3
struct guess_status_t {
	__u64 state;

	/* checking */
	__u64 pid_tgid;
	__u64 what;
	__u64 offset_nsproxy;
	__u64 offset_pidns;
	__u64 offset_ino;

	__u64 err;

	__u32 pidns;
};

#define MAX_TRACED_PROGRAMS 128

#define MAX_POOLED_PROGRAMS 16

#endif
