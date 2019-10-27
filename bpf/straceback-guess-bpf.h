#ifndef __STRACEBACK_GUESS_BPF_H
#define __STRACEBACK_GUESS_BPF_H

#include <linux/types.h>

#define GUESS_UTSNS 0

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
	__u64 offset_utsns;
	__u64 offset_ino;

	__u64 err;

	__u32 utsns;
};

#define MAX_TRACED_PROGRAMS 128
#define MAX_POOLED_PROGRAMS 32
struct queue_avail_progs_t {
	__u32 indexes[MAX_POOLED_PROGRAMS];
};

#define CONTAINER_STATUS_UNINITIALIZED	0
#define CONTAINER_STATUS_WAITING	1
#define CONTAINER_STATUS_READY		2
struct container_status_t {
	__u32 idx;
	__u32 status;
	__u64 caps;
};

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define CONTAINER_EVENT_TYPE_CREATE	0
#define CONTAINER_EVENT_TYPE_UPDATE	1
#define CONTAINER_EVENT_TYPE_DELETE	2
struct container_event_t {
	__u64 timestamp;

	__u64 pid;
	char comm[TASK_COMM_LEN];

	__u32 idx;
	__u32 utsns;

	__u8 typ;

	//  Unfortunately, the string can be quite long... Example:
	// /sys/fs/cgroup/unified/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1aecc643_23ea_11e9_beec_06c846f19394.slice/docker-da9977a4f9abe14ab2fa87d3780d92fd615b97cc3107fcd4a851f01857cb8ff8.scope
	char param[256];
};

#endif
