#include <linux/kconfig.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <linux/ptrace.h>
#pragma clang diagnostic pop
#include <linux/version.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"
#include "straceback-main-bpf.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Wenum-conversion"
#include <net/sock.h>
#pragma clang diagnostic pop
#include <net/inet_sock.h>
#include <net/net_namespace.h>

/* This is a key/value store with the keys being the cgroupid
 * and the values being the index of tail_call_map.
 */
struct bpf_map_def SEC("maps/cgroup_map") cgroup_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__u32),
	.max_entries = 8,
	.pinning = 0,
	.namespace = "",
};

/* This is a key/value store with the keys being the index
 * and the values being another BPF program.
 */
struct bpf_map_def SEC("maps/tail_call_map") tail_call_map = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 8,
	.pinning = 0,
	.namespace = "",
};

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__sys_enter(struct pt_regs *ctx)
{
	//u64 pid = bpf_get_current_pid_tgid();
	u64 cgroupid = bpf_get_current_cgroup_id();
	u32 *progIdx;

	//printt("sys_enter: pid %llu cgr %llu\n", pid >> 32, cgroupid);

	progIdx = bpf_map_lookup_elem(&cgroup_map, &cgroupid);
	if (progIdx == NULL)
		return 0;

	bpf_tail_call(ctx, (void *)&tail_call_map, *progIdx);

	return 0;
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by gobpf-elf-loader to set the current
// running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;
