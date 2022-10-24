// +build ignore

#include "common.h"

#include "bpf_tracing.h"
char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    u32 pid;
    u8 line[300];
    u32 uid;
    u32 gid;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256*1024);
}events SEC(".maps");

const struct event *unused __attribute__((unused));

SEC("uretprobe/bash_readline_ringbuf")
int uretprobe_bash_readline(struct pt_regs *ctx) {
	struct event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) {
		return 0;
	}
	event->pid = bpf_get_current_pid_tgid();
    event->uid = bpf_get_current_uid_gid();
    event->gid = bpf_get_current_uid_gid() >> 32;
	bpf_probe_read(&event->line, sizeof(event->line), (void *)PT_REGS_RC(ctx));
	bpf_ringbuf_submit(event, 0);
	return 0;
}