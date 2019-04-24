#ifndef __STRACEBACK_TAILCALL_BPF_H
#define __STRACEBACK_TAILCALL_BPF_H

#include <linux/types.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct syscall_event_t {
	__u64 timestamp;
	__u64 cpu;
	__u64 pid;
	__u64 id;
	char comm[TASK_COMM_LEN];
	__u64 args[6];
};

#endif
