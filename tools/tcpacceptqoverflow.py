#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# Credits for inspiration go to:
# - Brendan Gregg for https://github.com/iovisor/bcc/blob/master/tools/tcpdrop.py
# - majek for https://github.com/cloudflare/cloudflare-blog/blob/master/2018-01-syn-floods/acceptq.stp
#
# @kosfar
#

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep
from bcc import tcp

# arguments
examples = """examples:
    ./tcpacceptqoverflow         # trace kernel TCP accept queue overflows
"""
parser = argparse.ArgumentParser(
    description="Trace TCP accept queue overflows by the kernel",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <net/sock.h>
#include <bcc/proto.h>

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u16 ack_backlog;
    u16 max_ack_backlog;
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u16 ack_backlog;
    u16 max_ack_backlog;
    u32 pid;
    u64 saddr[2];
    u64 daddr[2];
    u16 sport;
    u16 dport;
};
BPF_PERF_OUTPUT(ipv6_events);

static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in tcp_hdr() -> skb_transport_header().
    return (struct tcphdr *)(skb->head + skb->transport_header);
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in ip_hdr() -> skb_network_header().
    return (struct iphdr *)(skb->head + skb->network_header);
}

static inline struct ipv6hdr *skb_to_ipv6hdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in ipv6_hdr() -> skb_network_header().
    return (struct ipv6hdr *)(skb->head + skb->network_header);
}

// check defintion of tcp_v4_conn_request kernel function
// to conclude on trace function args
int trace_tcp_v4_conn_request(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    if (sk == NULL)
        return 0;
    u32 pid = bpf_get_current_pid_tgid();

    // pull in details from the packet headers and the sock struct
    u16 family = sk->__sk_common.skc_family;
    u16 sport = 0, dport = 0, ack_backlog = 0, max_ack_backlog = 0;
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct iphdr *ip = skb_to_iphdr(skb);
    sport = tcp->source;
    dport = tcp->dest;
    sport = ntohs(sport);
    dport = ntohs(dport);

    ack_backlog = sk->sk_ack_backlog;
    max_ack_backlog = sk->sk_max_ack_backlog;

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {};

        if (ack_backlog > max_ack_backlog) {
          data4.ack_backlog = ack_backlog;
          data4.max_ack_backlog = max_ack_backlog;
          data4.pid = pid;
          data4.saddr = ip->saddr;
          data4.daddr = ip->daddr;
          data4.dport = dport;
          data4.sport = sport;
          ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
      }
    }
    // else drop

    return 0;
}

// check defintion of tcp_v6_conn_request kernel function
// to conclude on trace function args
int trace_tcp_v6_conn_request(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    if (sk == NULL)
        return 0;
    u32 pid = bpf_get_current_pid_tgid();

    // pull in details from the packet headers and the sock struct
    u16 family = sk->__sk_common.skc_family;
    u16 sport = 0, dport = 0, ack_backlog = 0, max_ack_backlog = 0;
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct ipv6hdr *ip = skb_to_ipv6hdr(skb);
    sport = tcp->source;
    dport = tcp->dest;
    sport = ntohs(sport);
    dport = ntohs(dport);

    ack_backlog = sk->sk_ack_backlog;
    max_ack_backlog = sk->sk_max_ack_backlog;

    if (family == AF_INET6) {
        struct ipv6_data_t data6 = {};

        if (ack_backlog > max_ack_backlog) {
          data6.ack_backlog = ack_backlog;
          data6.max_ack_backlog = max_ack_backlog;
          data6.pid = pid;
          bpf_probe_read(&data6.saddr, sizeof(ip->saddr), (char*)ip + offsetof(struct ipv6hdr, saddr));
          bpf_probe_read(&data6.daddr, sizeof(ip->daddr), (char*)ip + offsetof(struct ipv6hdr, daddr));
          data6.dport = dport;
          data6.sport = sport;
          ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
        }
    }
    // else drop

    return 0;
}
"""

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# process event
def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    print("%-8s %-6d %-8d %-8d %-20s > %-20s" % (
        strftime("%H:%M:%S"), event.pid, event.ack_backlog, event.max_ack_backlog,
        "%s:%d" % (inet_ntop(AF_INET, pack('I', event.saddr)), event.sport),
        "%s:%s" % (inet_ntop(AF_INET, pack('I', event.daddr)), event.dport)))
    print("")

def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    print("%-8s %-6d %-8d %-8d %-20s > %-20s" % (
        strftime("%H:%M:%S"), event.pid, event.ack_backlog, event.max_ack_backlog,
        "%s:%d" % (inet_ntop(AF_INET6, event.saddr), event.sport),
        "%s:%d" % (inet_ntop(AF_INET6, event.daddr), event.dport)))
    print("")

# initialize BPF
b = BPF(text=bpf_text)

if b.get_kprobe_functions(b"tcp_v4_conn_request"):
    b.attach_kprobe(event="tcp_v4_conn_request", fn_name="trace_tcp_v4_conn_request")
else:
    print("ERROR: tcp_v4_conn_request() kernel function not found or traceable. "
        "Older kernel versions not supported.")
    exit()

if b.get_kprobe_functions(b"tcp_v6_conn_request"):
    b.attach_kprobe(event="tcp_v6_conn_request", fn_name="trace_tcp_v6_conn_request")
else:
    print("ERROR: tcp_v6_conn_request() kernel function not found or traceable. "
        "Older kernel versions not supported.")
    exit()

# header
print("%-8s %-6s %-8s %-8s %-20s > %-20s" % ("TIME", "PID", "ACCEPTQ", "QMAX", "SADDR:SPORT", "DADDR:DPORT"))

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

