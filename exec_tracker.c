//go:build ignore

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <linux/bpf.h> // <-- THE FIX IS THIS LINE!
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event {
    __u32 pid; // Using kernel types for consistency
    __u8  _padding[4];
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(void *ctx) {
    struct event event = {};
	event.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
