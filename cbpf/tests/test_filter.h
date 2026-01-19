#ifndef TEST_FILTER_H
#define TEST_FILTER_H

#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

// Структуры данных из оригинального кода
struct flow5_key
{
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u8 pad1;
    __u16 pad2;
};

struct stats_val
{
    __u64 allowed;
    __u64 dropped;
    __u64 syn_allowed;
    __u64 syn_dropped;
    __u64 active_flow_hits;
    __u64 pending_promotions;
    __u64 pending_expired_cleanups;
    __u64 ip_port_auth_hits;
    __u64 non_guarded_port_allowed;
    __u64 guarded_port_dropped;
};

struct log_event
{
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 tcp_flags;
    __u8 event_type;
    __u8 result;
    __u32 pad;
};

// Прототипы функций для тестирования
static __always_inline int
update_stats(__u32 idx, int allow, int stat_type);
static __always_inline void
log_event(struct flow5_key* k, __u8 tcp_flags, __u8 event_type, __u8 result);
static __always_inline int
is_expired(__u64* expiry_ns);
static __always_inline __u8
get_tcp_flags(struct tcphdr* tcph);
static __always_inline int
send_rst(struct __sk_buff* skb, struct iphdr* iph, struct tcphdr* tcph);

#endif
