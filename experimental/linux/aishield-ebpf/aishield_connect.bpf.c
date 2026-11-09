// SPDX-License-Identifier: GPL-2.0
// AI Firewall — connect() trace scaffold for Linux

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct connect_event {
    __u32 pid;
    __u16 port;
    __u8  dst_ip[4];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct connect_event *ev;
    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->pid = bpf_get_current_pid_tgid() >> 32;
    ev->port = 0;
    __builtin_memset(ev->dst_ip, 0, sizeof(ev->dst_ip));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
