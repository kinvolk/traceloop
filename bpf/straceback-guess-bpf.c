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

/* This is a key/value store with the keys being the utsns
 * and the values being the index of tail_call_enter|exit.
 */
struct bpf_map_def SEC("maps/utsns_map") utsns_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
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
	u32 *progIdx;
	progIdx = bpf_map_lookup_elem(&utsns_map, &utsns);
	if (progIdx != NULL) {
		printt("normal tailcall; utsns %u progIdx %d\n", utsns, *progIdx);
		bpf_tail_call((void *)ctx, (void *)&tail_call_enter, *progIdx);
		return 0;
	}

	// allocate a new prog_idx
	u32 newProgIdx = utsns % MAX_POOLED_PROGRAMS; // FIXME
	bpf_map_update_elem(&utsns_map, &utsns, &newProgIdx, BPF_ANY);
	printt("allocate utsns %u to %d\n", utsns, newProgIdx);
	bpf_tail_call((void *)ctx, (void *)&tail_call_enter, newProgIdx);
	printt("failed to exec tail call\n");

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
	u32 *progIdx;
	progIdx = bpf_map_lookup_elem(&utsns_map, &utsns);
	if (progIdx != NULL) {
		bpf_tail_call(ctx, (void *)&tail_call_exit, *progIdx);
		return 0;
	}

	// allocate a new prog_idx
	//u32 newProgIdx = utsns % 8; // FIXME
	//bpf_map_update_elem(&utsns_map, &utsns, &newProgIdx, BPF_ANY);
	//bpf_tail_call((void *)ctx, (void *)&tail_call_exit, newProgIdx);

	return 0;
}

char _license[] SEC("license") = "GPL";

