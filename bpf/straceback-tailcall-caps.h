#ifndef __STRACEBACK_TAILCALL_CAPS_H
#define __STRACEBACK_TAILCALL_CAPS_H

struct cap_access_key_t {
	__u64 caps;
	__u64 syscall_id;
};

struct cap_access_record_t {
	char comm[TASK_COMM_LEN];
	__u64 syscall_id;
	__u64 pid;
	__u64 args[6];
	__u64 ret;
};

#endif
