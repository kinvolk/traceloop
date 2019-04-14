#include <linux/kconfig.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <linux/ptrace.h>
#pragma clang diagnostic pop
#include <linux/version.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"
#include "straceback-tailcall-bpf.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Wenum-conversion"
#include <net/sock.h>
#pragma clang diagnostic pop
#include <net/inet_sock.h>
#include <net/net_namespace.h>

#define USE_QUEUE_MAP 0

/* This is a key/value store with the keys being the cpu number
 * and the values being a perf file descriptor.
 */
struct bpf_map_def SEC("maps/events") events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
	.pinning = 0,
	.namespace = "",
};

#if USE_QUEUE_MAP
struct bpf_map_def SEC("maps/queue") queue = {
	.type = BPF_MAP_TYPE_QUEUE,
	.key_size = 0,
	.value_size = sizeof(__u64),
	.max_entries = 1024,
	.pinning = 0,
	.namespace = "",
};
#endif

struct sys_enter_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	long id;
	unsigned long args[6];
};

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__sys_enter(struct sys_enter_args *ctx)
{
	int err;
	u32 cpu = bpf_get_smp_processor_id();
	u64 pid = bpf_get_current_pid_tgid();
	u64 ts = bpf_ktime_get_ns();
	struct syscall_event_t sc = {
		.timestamp = ts,
		.cpu = cpu,
		.pid = pid,
		.id = ctx->id,
	};
	
	bpf_get_current_comm(sc.comm, sizeof(sc.comm));

	err = bpf_perf_event_output(ctx, &events, cpu, &sc, sizeof(sc));

	printt("tailcall: pid %llu NR %lu err=%d\n", pid >> 32, ctx->id, err);

#if USE_QUEUE_MAP
	u64 nr = ctx->id;
	err = bpf_map_push_elem(&queue, &nr, BPF_EXIST);
	printt("tailcall: queue nr %llu err=%d\n", nr, err);
#endif

	return 0;
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by gobpf-elf-loader to set the current
// running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;
