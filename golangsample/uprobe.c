// +build ignore

#include "common.h"

#include "bpf_tracing.h"
char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    int a;
    int b;
    int c;
    int d;
    int e;
    int f;
    int g;
};

struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const struct event *unused __attribute__((unused));

SEC("uprobe/golangsample")
int trace_golang_sample(struct pt_regs *ctx)
{   
    if (!PT_REGS_PARM1(ctx)){
        return 0;
    }
   
    void *stackAddr = (void *)PT_REGS_PARM1(ctx);
    struct event * e;
    e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if(!e){
        return 0;
    }
    bpf_probe_read(&e->a, sizeof(e->a), stackAddr);
  
    // bpf_probe_read(&e->b, sizeof(e->b), stackAddr+16);
    // bpf_probe_read(&e->c, sizeof(e->c), stackAddr+24);
    // bpf_probe_read(&e->d, sizeof(e->d), stackAddr+32);
    // bpf_probe_read(&e->e, sizeof(e->e), stackAddr+40);
    // bpf_probe_read(&e->f, sizeof(e->f), stackAddr+48);
    // bpf_probe_read(&e->g, sizeof(e->g), stackAddr+56);
    bpf_ringbuf_submit(e, 0);
    return 0;
}