#include <linux/kconfig.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <linux/ptrace.h>
#pragma clang diagnostic pop
#include <linux/version.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"

#include "straceback-guess-bpf.h"
#include "straceback-tailcall-bpf.h"

struct bpf_map_def SEC("maps/guess_status") guess_status = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct guess_status_t),
	.max_entries = 1,
	.pinning = 0,
	.namespace = "",
};

/* Emulated queue of available program indexes to be allocated to new utsns
 *
 * Userspace prepares a new program, attaches it to the program arrays, and
 * add its indice in this queue.
 *
 * Kernel picks up a program indice from this queue whenever it needs to
 * allocate one for a newly detected container.
 *
 * BPF_MAP_TYPE_QUEUE is only available in Linux 4.20 and traceloop targets
 * Linux 4.14
 * */
struct bpf_map_def SEC("maps/queue_avail_progs") queue_avail_progs = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct queue_avail_progs_t),
	.max_entries = 1,
	.pinning = 0,
	.namespace = "",
};

/* This is a key/value store with the keys being the cpu number
 * and the values being a perf file descriptor.
 *
 * Whenever a new container is detected, a program is allocated for it and
 * userspace is signalled via this perf ring buffer.
 */
struct bpf_map_def SEC("maps/container_events") container_events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
	.pinning = 0,
	.namespace = "",
};


/* This is a key/value store with the keys being the utsns
 * and the values being the index of tail_call_enter|exit.
 */
struct bpf_map_def SEC("maps/utsns_map") utsns_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct container_status_t),
	.max_entries = MAX_TRACED_PROGRAMS,
	.pinning = 0,
	.namespace = "",
};

/* This is a key/value store with the keys being the index
 * and the values being another BPF program.
 */
struct bpf_map_def SEC("maps/tail_call_enter") tail_call_enter = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = MAX_TRACED_PROGRAMS,
	.pinning = 0,
	.namespace = "",
};
struct bpf_map_def SEC("maps/tail_call_exit") tail_call_exit = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = MAX_TRACED_PROGRAMS,
	.pinning = 0,
	.namespace = "",
};
struct bpf_map_def SEC("maps/tail_call_caps") tail_call_caps = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = MAX_TRACED_PROGRAMS,
	.pinning = 0,
	.namespace = "",
};

struct bpf_map_def SEC("maps/syscalls") syscalls = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct syscall_def_t),
	.max_entries = 1024,
	.pinning = PIN_GLOBAL_NS,
	.namespace = "straceback",
};

__attribute__((always_inline))
static int are_offsets_ready(struct guess_status_t *status, struct task_struct *task, u64 pid, long id) {
	u64 zero = 0;

	switch (status->state) {
		case GUESS_STATE_UNINITIALIZED:
			return 0;
		case GUESS_STATE_CHECKING:
			break;
		case GUESS_STATE_CHECKED:
			return 0;
		case GUESS_STATE_READY:
			return 1;
		default:
			return 0;
	}

	if (id != 269) { // faccessat()
		return 0;
	}

	// Only accept the exact pid & tid. Extraneous connections from other
	// threads must be ignored here. Userland must take care to generate
	// connections from the correct thread. In Golang, this can be achieved
	// with runtime.LockOSThread.
	if (status->pid_tgid != pid)
		return 0;

	printt("offset task - thread_group: %d\n", offsetof(struct task_struct, thread_group));
	printt("offset task - ptraced: %d\n", offsetof(struct task_struct, ptraced));
	printt("offset task - clear_child_tid: %d\n", offsetof(struct task_struct, clear_child_tid));
	printt("offset task - vtime: %d\n", offsetof(struct task_struct, vtime));
	printt("offset task - ptracer_cred: %d\n", offsetof(struct task_struct, ptracer_cred));
	printt("offset task - nsproxy: %d\n", offsetof(struct task_struct, nsproxy));
	//printt("offset_nsproxy: %d\n", offsetof(struct task_struct, nsproxy));
	//printt("offset_utsns: %d\n", offsetof(struct nsproxy, uts_ns));
	//printt("offset_ino: %d\n", offsetof(struct uts_namespace, ns));
	//printt("offset_ino: %d\n", offsetof(struct ns_common, inum));

	struct guess_status_t new_status = { };
	new_status.state = GUESS_STATE_CHECKED;
	new_status.pid_tgid = status->pid_tgid;
	new_status.what = status->what;
	new_status.offset_nsproxy = status->offset_nsproxy;
	new_status.offset_utsns = status->offset_utsns;
	new_status.offset_ino = status->offset_ino;
	new_status.err = 0;
	new_status.utsns = status->utsns;

	void *possible_nsproxy;		// struct nsproxy
	void *possible_uts_namespace;	// struct uts_namespace
	u32 possible_utsns;		// unsigned int

	long ret = 0;

	switch (status->what) {
		case GUESS_UTSNS:
			possible_nsproxy = NULL;
			possible_uts_namespace = NULL;
			possible_utsns = 0;
			bpf_probe_read(&possible_nsproxy, sizeof(void *), ((char *)task) + status->offset_nsproxy);
			// if we get a kernel fault, it means we have
			// an invalid pointer, signal an error so we can go
			// to the next offset
			ret = bpf_probe_read(&possible_uts_namespace, sizeof(void *), ((char *)possible_nsproxy) + status->offset_utsns);
			if (ret == -EFAULT) {
				new_status.err = 2;
				break;
			}
			ret = bpf_probe_read(&possible_utsns, sizeof(possible_utsns), ((char *)possible_uts_namespace) + status->offset_ino);
			if (ret == -EFAULT) {
				new_status.err = 1;
				break;
			}
			new_status.utsns = possible_utsns;
			break;
		default:
			// not for us
			return 0;
	}

	bpf_map_update_elem(&guess_status, &zero, &new_status, BPF_ANY);

	return 0;
}

__attribute__((always_inline))
static u32 get_utsns(struct guess_status_t *status, struct task_struct *task) {
	void *nsproxy;		// struct nsproxy
	void *uts_namespace;	// struct uts_namespace
	u32 utsns;		// unsigned int

	int ret;
	ret = bpf_probe_read(&nsproxy, sizeof(void *), ((char *)task) + status->offset_nsproxy);
	if (ret == -EFAULT || nsproxy == NULL) {
		return 0;
	}
	ret = bpf_probe_read(&uts_namespace, sizeof(void *), ((char *)nsproxy) + status->offset_utsns);
	if (ret == -EFAULT || uts_namespace == NULL) {
		return 0;
	}
	ret = bpf_probe_read(&utsns, sizeof(utsns), ((char *)uts_namespace) + status->offset_ino);
	if (ret == -EFAULT) {
		return 0;
	}
	return utsns;
}

struct sys_enter_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	long id;
	unsigned long args[6];
};

__attribute__((always_inline))
static u32 find_prog_idx(void *ctx, u64 pid, u32 utsns, long id, int exit) {
	struct container_status_t *status;
	status = bpf_map_lookup_elem(&utsns_map, &utsns);
	if (status != NULL) {
		if (status->status == CONTAINER_STATUS_READY) {
			// Program already installed. Use it.
			return status->idx;
		} else if (status->status == CONTAINER_STATUS_WAITING) {
			if (exit != 0 && id != 165) { // mount
				return 0xFFFFFFFF;
			}
			u64 ts = bpf_ktime_get_ns();
			struct container_event_t ev = {
				.timestamp = ts,
				.typ = CONTAINER_EVENT_TYPE_UPDATE,
				.pid = pid,
				.idx = status->idx,
				.utsns = utsns,
			};
			bpf_get_current_comm(ev.comm, sizeof(ev.comm));
			if (ev.comm[0] != 'r' || ev.comm[1] != 'u' ||
			    ev.comm[2] != 'n' || ev.comm[3] != 'c') {
				return 0xFFFFFFFF;
			}
			void *param1 = (void *)(((struct sys_enter_args *) ctx)->args[0]);
			bpf_probe_read(ev.param, 256, param1);
			if (ev.param[0] != '/'  || ev.param[1] != 's'  || ev.param[2] != 'y'  || ev.param[3] != 's'  ||
			    ev.param[4] != '/'  || ev.param[5] != 'f'  || ev.param[6] != 's'  || ev.param[7] != '/'  ||
			    ev.param[8] != 'c'  || ev.param[9] != 'g'  || ev.param[10] != 'r' || ev.param[11] != 'o' ||
			    ev.param[12] != 'u' || ev.param[13] != 'p' || ev.param[14] != '/' || ev.param[15] != 's' ||
			    ev.param[16] != 'y' || ev.param[17] != 's' || ev.param[18] != 't' || ev.param[19] != 'e' ||
			    ev.param[20] != 'm' || ev.param[21] != 'd' || ev.param[22] != '/') {
				return 0xFFFFFFFF;
			}
			bpf_perf_event_output(ctx, &container_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

			status->status = CONTAINER_STATUS_READY;
			return 0xFFFFFFFF;
		}
	}

	// allocate a new prog_idx
	u64 zero = 0;
	struct queue_avail_progs_t *queue;
	queue = bpf_map_lookup_elem(&queue_avail_progs, &zero);
	if (queue == NULL) {
		printt("queue_avail_progs map not readable?\n");
		return 0xFFFFFFFF;
	}

	// pick the top item from the queue
	u32 newProgIdx = queue->indexes[0];
	if (newProgIdx >= MAX_POOLED_PROGRAMS) {
		printt("queue_avail_progs does not have anything to use? %d\n", newProgIdx);
		return 0xFFFFFFFF;
	}

	// assign idx for the utsns
	struct container_status_t new_status = {newProgIdx, CONTAINER_STATUS_WAITING, 0};
	bpf_map_update_elem(&utsns_map, &utsns, &new_status, BPF_ANY);

	// shift the queue
	int i;
	#pragma clang loop unroll(full)
	for (i=0; i<MAX_POOLED_PROGRAMS-1; i++) {
		queue->indexes[i] = queue->indexes[i+1];
	}
	queue->indexes[MAX_POOLED_PROGRAMS-1] = 0xFFFFFFFF;

	// notify userspace of the new container
	u64 ts = bpf_ktime_get_ns();
	struct container_event_t ev = {
		.timestamp = ts,
		.typ = CONTAINER_EVENT_TYPE_CREATE,
		.pid = pid,
		.idx = newProgIdx,
		.utsns = utsns,
	};
	bpf_get_current_comm(ev.comm, sizeof(ev.comm));
	bpf_perf_event_output(ctx, &container_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

	printt("allocate utsns %u to %d [%d]\n", utsns, newProgIdx, exit);

	return newProgIdx;
}

// Defined in include/linux/proc_ns.h
#ifndef PROC_PID_INIT_INO
#define PROC_PID_INIT_INO 0xEFFFFFFCU
#endif
#ifndef PROC_UTS_INIT_INO
#define PROC_UTS_INIT_INO 0xEFFFFFFEU
#endif

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__sys_enter(struct sys_enter_args *ctx)
{
	struct guess_status_t *status;
	u64 zero = 0;
	status = bpf_map_lookup_elem(&guess_status, &zero);
	if (status == NULL || status->state == GUESS_STATE_UNINITIALIZED) {
		return 0;
	}

	u64 pid = bpf_get_current_pid_tgid();
	struct task_struct *task = (void *)bpf_get_current_task();
	if (!are_offsets_ready(status, task, pid, ctx->id)) {
		return 0;
	}

	u32 utsns = get_utsns(status, task);
	if (utsns == 0 || utsns == PROC_UTS_INIT_INO) {
		return 0;
	}

	u32 progIdx = find_prog_idx(ctx, pid, utsns, ctx->id, 0);
	if (progIdx >= MAX_TRACED_PROGRAMS) {
		// Couldn't find a suitable slot
		return 0;
	}

	bpf_tail_call((void *)ctx, (void *)&tail_call_enter, progIdx);
	printt("failed to exec tail call in sys_enter\n");

	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int tracepoint__sys_exit(struct pt_regs *ctx)
{
	struct guess_status_t *status;
	u64 zero = 0;
	status = bpf_map_lookup_elem(&guess_status, &zero);
	if (status == NULL || status->state != GUESS_STATE_READY) {
		return 0;
	}

	struct task_struct *task = (void *)bpf_get_current_task();

	u32 utsns = get_utsns(status, task);
	if (utsns == 0 || utsns == PROC_UTS_INIT_INO) {
		return 0;
	}

	u64 pid = bpf_get_current_pid_tgid();
	u32 progIdx = find_prog_idx(ctx, pid, utsns, 0, 1);
	if (progIdx >= MAX_TRACED_PROGRAMS) {
		// Couldn't find a suitable slot
		return 0;
	}

	bpf_tail_call((void *)ctx, (void *)&tail_call_exit, progIdx);
	printt("failed to exec tail call in sys_exit\n");

	return 0;
}

__attribute__((always_inline))
static u32 get_utsns_from_kprobe(struct guess_status_t *status, void *ns) {
	u32 utsns;		// unsigned int

	int ret;
	ret = bpf_probe_read(&utsns, sizeof(utsns), ((char *)ns) + status->offset_ino);
	if (ret == -EFAULT) {
		return 0;
	}
	return utsns;
}

SEC("kprobe/free_uts_ns")
int kprobe__free_uts_ns(struct pt_regs *ctx)
{
	void *ns;
	ns = (void *) PT_REGS_PARM1(ctx);

	struct guess_status_t *status;
	u64 zero = 0;
	status = bpf_map_lookup_elem(&guess_status, &zero);
	if (status == NULL || status->state == GUESS_STATE_UNINITIALIZED) {
		return 0;
	}

	u32 utsns = get_utsns_from_kprobe(status, ns);

	struct container_status_t *container_status;
	container_status = bpf_map_lookup_elem(&utsns_map, &utsns);
	if (container_status == NULL) {
		return 0;
	}

	// notify userspace of the deleted container
	u64 ts = bpf_ktime_get_ns();
	struct container_event_t ev = {
		.timestamp = ts,
		.typ = CONTAINER_EVENT_TYPE_DELETE,
		.idx = container_status->idx,
		.utsns = utsns,
	};
	bpf_perf_event_output(ctx, &container_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

	// remove the mapping
	bpf_map_delete_elem(&utsns_map, &utsns);
	return 0;
}

SEC("kprobe/cap_capable")
int kprobe__cap_capable(struct pt_regs *ctx)
{
	int cap;
	cap = (int) PT_REGS_PARM3(ctx);

	struct guess_status_t *status;
	u64 zero = 0;
	status = bpf_map_lookup_elem(&guess_status, &zero);
	if (status == NULL || status->state != GUESS_STATE_READY) {
		return 0;
	}

	struct task_struct *task = (void *)bpf_get_current_task();

	u32 utsns = get_utsns(status, task);
	if (utsns == 0 || utsns == PROC_UTS_INIT_INO) {
		return 0;
	}

	struct container_status_t *container_status;
	container_status = bpf_map_lookup_elem(&utsns_map, &utsns);
	if (container_status == NULL || container_status->status != CONTAINER_STATUS_READY) {
		return 0;
	}

	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(comm, sizeof(comm));
	if (comm[0] == 'r' && comm[1] == 'u' &&
	    comm[2] != 'n' && comm[3] == 'c') {
		return 0;
	}

	container_status->caps |= 1 << cap;

	bpf_tail_call((void *)ctx, (void *)&tail_call_caps, container_status->idx);

	return 0;
}

char _license[] SEC("license") = "GPL";

// this number will be interpreted by gobpf-elf-loader to set the current
// running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;

