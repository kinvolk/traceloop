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

struct bpf_map_def SEC("maps/syscalls") syscalls = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct syscall_def_t),
	.max_entries = 1024,
	.pinning = PIN_GLOBAL_NS,
	.namespace = "straceback",
};

struct remembered_args {
	u64 timestamp;
	u64 args[6];
};

/* This key/value store maps thread PIDs to syscall arg arrays
 * that were remembered at sys_enter so that sys_exit can probe buffer
 * contents and generate syscall events showing the result content.
 */
struct bpf_map_def SEC("maps/probe_at_sys_exit") probe_at_sys_exit = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct remembered_args),
	.max_entries = 128,
	.pinning = 0,
	.namespace = "",
};

struct sys_enter_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	long id;
	unsigned long args[6];
};

struct sys_exit_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	long id;
	unsigned long ret;
};

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__sys_enter(struct sys_enter_args *ctx)
{
	int i;
	u32 cpu = bpf_get_smp_processor_id();
	u64 pid = bpf_get_current_pid_tgid();
	u64 ts = bpf_ktime_get_ns();
	u64 nr = ctx->id;
	struct syscall_event_t sc = {
		.timestamp = ts,
		.cont_nr = 0,
		.cpu = cpu,
		.pid = pid,
		.typ = SYSCALL_EVENT_TYPE_ENTER,
		.id = nr,
	};
	struct remembered_args remembered = {
		.timestamp = ts,
	};
	struct syscall_def_t *syscall_def;
	syscall_def = bpf_map_lookup_elem(&syscalls, &nr);
	if (syscall_def == NULL)
		return 0;

	bpf_get_current_comm(sc.comm, sizeof(sc.comm));

	#pragma clang loop unroll(full)
	for (i = 0; i< 6; i++) {
		sc.args[i] = ctx->args[i];
		remembered.args[i] = ctx->args[i];
		sc.cont_nr += !!syscall_def->args_len[i];
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &sc, sizeof(sc));

	bpf_map_update_elem(&probe_at_sys_exit, &pid, &remembered, BPF_ANY);

	#pragma clang loop unroll(full)
	for (i = 0; i < 6; i++) {
		__u64 arg_len = syscall_def->args_len[i];
		if (arg_len != 0 && !(arg_len & PARAM_PROBE_AT_EXIT_MASK) && arg_len != USE_RET_AS_PARAM_LENGTH) {
			bool null_terminated = false;
			struct syscall_event_cont_t sc_cont = {
				.timestamp = ts,
				.typ = SYSCALL_EVENT_TYPE_CONT,
				.index = i,
				.failed = false,
			};

			if (arg_len == USE_NULL_BYTE_LENGTH) {
				null_terminated = true;
				arg_len = PARAM_LEN - 1;
				/* enforce termination */
				sc_cont.param[arg_len] = '\0';
			} else if (arg_len >= USE_ARG_INDEX_AS_PARAM_LENGTH) {
				__u64 idx = arg_len & USE_ARG_INDEX_AS_PARAM_LENGTH_MASK;
				/* Access args via the previously saved map entry instead of
				 * the ctx pointer or 'remembered' struct to avoid this verifier
				 * issue (which does not occur in sys_exit for the same code):
				 * "variable ctx access var_off=(0x0; 0x38) disallowed"
				 */
				struct remembered_args *remembered_ctx_workaround;
				if (idx < 6) {
					remembered_ctx_workaround = bpf_map_lookup_elem(&probe_at_sys_exit, &pid);
					if (remembered_ctx_workaround)
						arg_len = remembered_ctx_workaround->args[idx];
					else
						arg_len = 0;
				} else
					arg_len = PARAM_LEN;
			}

			if (arg_len > sizeof(sc_cont.param))
				arg_len = sizeof(sc_cont.param);
			if (null_terminated)
				sc_cont.length = USE_NULL_BYTE_LENGTH;
			else
				sc_cont.length = arg_len;

			// Call bpf_probe_read() with a constant size to avoid errors on 4.14.137+
			// invalid stack type R1 off=-304 access_size=0
			// Possibly related:
			// https://github.com/torvalds/linux/commit/9fd29c08e52023252f0480ab8f6906a1ecc9a8d5
			switch (arg_len) {
			case 0:
				sc_cont.failed = true;
				break;
#define UNROLL_CASE(len) \
			case (len): \
				if (bpf_probe_read(sc_cont.param, (len), (void *)(ctx->args[i]))) { \
					sc_cont.failed = true; \
				} \
				break;
			UNROLL_CASE(1) UNROLL_CASE(2) UNROLL_CASE(3) UNROLL_CASE(4) UNROLL_CASE(5)
			UNROLL_CASE(6) UNROLL_CASE(7) UNROLL_CASE(8)
			default:
				if (bpf_probe_read(sc_cont.param, PARAM_LEN, (void *)(ctx->args[i]))) {
					sc_cont.failed = true;
				}
			}
			bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &sc_cont, sizeof(sc_cont));
		}
	}

	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int tracepoint__sys_exit(struct sys_exit_args *ctx)
{
	int i;
	u32 cpu = bpf_get_smp_processor_id();
	u64 pid = bpf_get_current_pid_tgid();
	u64 ts = bpf_ktime_get_ns();
	u64 nr = ctx->id;
	struct remembered_args *remembered;
	struct syscall_def_t *syscall_def;
	struct syscall_event_t sc = {
		.timestamp = ts,
		.cpu = cpu,
		.pid = pid,
		.typ = SYSCALL_EVENT_TYPE_EXIT,
		.id = nr,
	};
	sc.args[0] = ctx->ret;

	syscall_def = bpf_map_lookup_elem(&syscalls, &nr);
	if (syscall_def == NULL)
		return 0;
	/* no need to cleanup probe_at_sys_exit before returning because
	 * "syscalls" is never modified between sys_enter and sys_exit
	 */

	remembered = bpf_map_lookup_elem(&probe_at_sys_exit, &pid);
	if (remembered) {
		#pragma clang loop unroll(full)
		for (i = 0; i < 6; i++) {
			__u64 arg_len = syscall_def->args_len[i];
			if (arg_len != 0 && (arg_len & PARAM_PROBE_AT_EXIT_MASK)) {
				bool null_terminated = false;
				struct syscall_event_cont_t sc_cont = {
					.timestamp = remembered->timestamp,
					.typ = SYSCALL_EVENT_TYPE_CONT,
					.index = i,
					.failed = false,
				};
				arg_len &= ~PARAM_PROBE_AT_EXIT_MASK;

				if (arg_len == USE_RET_AS_PARAM_LENGTH) {
					if ((signed long) ctx->ret < 0)
						arg_len = 0;
					else
						arg_len = ctx->ret;
				} else if (arg_len == USE_NULL_BYTE_LENGTH) {
					null_terminated = true;
					arg_len = PARAM_LEN - 1;
					/* enforce termination */
					sc_cont.param[arg_len] = '\0';
				} else if (arg_len >= USE_ARG_INDEX_AS_PARAM_LENGTH) {
					__u64 idx = arg_len & USE_ARG_INDEX_AS_PARAM_LENGTH_MASK;
					if (idx < 6)
						arg_len = remembered->args[idx];
					else
						arg_len = PARAM_LEN;
				}

				if (arg_len > sizeof(sc_cont.param))
					arg_len = sizeof(sc_cont.param);
				if (null_terminated)
					sc_cont.length = USE_NULL_BYTE_LENGTH;
				else
					sc_cont.length = arg_len;

				// On Linux 4.14.137+, calling bpf_probe_read() with a variable size causes:
				// "invalid stack type R1 off=-304 access_size=0"
				// This is fixed on newer kernels.
				//
				// I know arg_len is not a volatile but that stops the compiler from
				// optimising the ifs into one bpf_probe_read call with a variable size.
				if (arg_len == 0) {
					sc_cont.failed = true;
				}
#define UNROLL_TEST(len) \
				else if ((volatile __u64)arg_len == (len)) { \
					if (bpf_probe_read(sc_cont.param, (len), (void *)(remembered->args[i]))) { \
						sc_cont.failed = true; \
					} \
				}
				UNROLL_TEST(1) UNROLL_TEST(2) UNROLL_TEST(3) UNROLL_TEST(4)
				UNROLL_TEST(5) UNROLL_TEST(6) UNROLL_TEST(7) UNROLL_TEST(8)
				else {
					if (bpf_probe_read(sc_cont.param, PARAM_LEN, (void *)(remembered->args[i]))) {
						sc_cont.failed = true;
					}
				}
				bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &sc_cont, sizeof(sc_cont));
			}
		}
		bpf_map_delete_elem(&probe_at_sys_exit, &pid);
	}

	bpf_get_current_comm(sc.comm, sizeof(sc.comm));

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &sc, sizeof(sc));

	return 0;
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by gobpf-elf-loader to set the current
// running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;
