// SPDX-License-Identifier: MIT
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

// Локальные определения на случай отсутствия макросов в kernel headers.
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef TCP_SYN
#define TCP_SYN 0x02
#endif

#ifndef TCP_RST
#define TCP_RST 0x04
#endif

#ifndef TCP_ACK
#define TCP_ACK 0x10
#endif

// Ключ 5-tuple (IPv4).
// Поля адресов/портов хранятся в network byte order (как в пакетах).
struct flow5_key
{
    __u32 saddr; // source IPv4
    __u32 daddr; // destination IPv4
    __u16 sport; // source TCP port
    __u16 dport; // destination TCP port
    __u8 proto;
    __u8 pad1;
    __u16 pad2;
};

// Имя map ограничено 15 символами (BPF_OBJ_NAME_LEN - 1).
// Активные TCP-потоки.
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct flow5_key);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} l4_active_flows SEC(".maps");

// Временные авторизации: source IP + destination port.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u8[8]);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} l4_pending_src SEC(".maps");

// Конфигурация защищенных портов.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, __u16); // порт в network byte order
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} l4_guarded_port SEC(".maps");

// Статистика фильтра.
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
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} l4_stats SEC(".maps");

// События для логирования и отладки.
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

// Ring buffer для расширенной отладки (например, через bpftool).
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} l4_logs SEC(".maps");

// Runtime-конфиг фильтра.
// key=0 -> значение TTL для активного потока в наносекундах.
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} l4_runtime_cfg SEC(".maps");

// Значение по умолчанию для TTL активного потока.
#define DEFAULT_INACTIVE_ALLOW_NS ((__u64)300 * 1000000000ULL)

// Коды обновления статистики.
#define STAT_ALLOW_DENY 0            // общее разрешение/блокировка
#define STAT_SYN_ALLOW_DENY 1        // разрешение/блокировка SYN
#define STAT_ACTIVE_FLOW_HIT 2       // попадание в активный поток
#define STAT_PENDING_PROMOTION 3     // повышение из pending
#define STAT_PENDING_EXPIRED_CLEAN 6 // очистка истекших pending
#define STAT_IP_PORT_AUTH_HIT 7      // попадание авторизации IP+порт
#define STAT_NON_GUARDED_PORT 8      // разрешен незащищенный порт
#define STAT_GUARDED_PORT_DENIED 9   // заблокирован защищенный порт

// Коды событий ring buffer.
#define LOG_SYN_RECEIVED 100         // Получен SYN на защищенный порт
#define LOG_ACTIVE_FLOW 101          // Попадание в активный поток
#define LOG_PENDING_PROMOTION 102    // Повышение из pending в active
#define LOG_PENDING_EXPIRED 103      // Истекшая pending запись
#define LOG_IP_PORT_AUTH 104         // Авторизация по IP+порт
#define LOG_NON_GUARDED_PORT 105     // Доступ к незащищенному порту
#define LOG_GUARDED_PORT_DROPPED 106 // Блокировка защищенного порта

static __always_inline int
update_stats(__u32 idx, int allow, int stat_type)
{
    struct stats_val* s = bpf_map_lookup_elem(&l4_stats, &idx);
    if (!s)
        return 0;

    switch (stat_type) {
    case STAT_ALLOW_DENY:
        if (allow)
            __sync_fetch_and_add(&s->allowed, 1);
        else
            __sync_fetch_and_add(&s->dropped, 1);
        break;
    case STAT_SYN_ALLOW_DENY:
        if (allow)
            __sync_fetch_and_add(&s->syn_allowed, 1);
        else
            __sync_fetch_and_add(&s->syn_dropped, 1);
        break;
    case STAT_ACTIVE_FLOW_HIT:
        __sync_fetch_and_add(&s->active_flow_hits, 1);
        break;
    case STAT_PENDING_PROMOTION:
        __sync_fetch_and_add(&s->pending_promotions, 1);
        break;
    case STAT_PENDING_EXPIRED_CLEAN:
        __sync_fetch_and_add(&s->pending_expired_cleanups, 1);
        break;
    case STAT_IP_PORT_AUTH_HIT:
        __sync_fetch_and_add(&s->ip_port_auth_hits, 1);
        break;
    case STAT_NON_GUARDED_PORT:
        __sync_fetch_and_add(&s->non_guarded_port_allowed, 1);
        break;
    case STAT_GUARDED_PORT_DENIED:
        __sync_fetch_and_add(&s->guarded_port_dropped, 1);
        break;
    }
    return 0;
}

// Публикует событие в ring buffer (best effort).
static __always_inline void
log_event(struct flow5_key* k, __u8 tcp_flags, __u8 event_type, __u8 result)
{
    struct log_event* event = bpf_ringbuf_reserve(&l4_logs, sizeof(struct log_event), 0);
    if (!event)
        return;

    event->saddr = k->saddr;
    event->daddr = k->daddr;
    event->sport = k->sport;
    event->dport = k->dport;
    event->tcp_flags = tcp_flags;
    event->event_type = event_type;
    event->result = result;
    event->pad = 0;

    bpf_ringbuf_submit(event, 0);
}

static __always_inline int
is_expired(__u64* expiry_ns)
{
    if (!expiry_ns)
        return 1;
    __u64 now = bpf_ktime_get_ns();
    return now > *expiry_ns;
}

static __always_inline __u8
get_tcp_flags(struct tcphdr* tcph)
{
    // TCP flags находятся в байте 13 TCP-заголовка.
    __u8* flags_byte = (__u8*)tcph + 13;
    return *flags_byte & 0x3F;
}

static __always_inline __u64
get_inactive_allow_ns()
{
    __u32 cfg_key = 0;
    __u64* value = bpf_map_lookup_elem(&l4_runtime_cfg, &cfg_key);
    if (!value || *value == 0) {
        return DEFAULT_INACTIVE_ALLOW_NS;
    }

    return *value;
}

// Формат ключа l4_pending_src:
// [0:4] source IPv4 bytes as in packet (network order bytes)
// [4:6] destination port in little-endian
// [6:8] pad (zeros)
// Важно: little-endian для destination port должен совпадать с userspace (Go).
static __always_inline void
build_pending_lookup_key(__u8 key[8], __u32 saddr_be, __u16 dport_be)
{
    __builtin_memcpy(&key[0], &saddr_be, sizeof(saddr_be));

    // dport_be в TCP header хранится как network order (big-endian).
    // Преобразуем в host-order и сериализуем в little-endian.
    __u16 dport_host = __builtin_bswap16(dport_be);
    key[4] = (__u8)(dport_host & 0xFF);
    key[5] = (__u8)(dport_host >> 8);
    key[6] = 0;
    key[7] = 0;
}

// Формирует RST+ACK из входящего SYN, отправляет клон обратно и дропает исходный пакет.
static __always_inline int
send_rst(struct __sk_buff* skb, struct iphdr* iph, struct tcphdr* tcph)
{
    // RST-ответ формируем только для SYN.
    if (!(get_tcp_flags(tcph) & TCP_SYN)) {
        return BPF_DROP;
    }

    // Меняем местами source/destination адреса.
    __u32 tmp_ip = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = tmp_ip;

    // Меняем местами source/destination порты.
    __u16 tmp_port = tcph->source;
    tcph->source = tcph->dest;
    tcph->dest = tmp_port;

    // Очищаем флаги и выставляем RST+ACK.
    __u8* flags_byte = (__u8*)tcph + 13;
    *flags_byte = 0;
    *flags_byte = TCP_RST | TCP_ACK;

    // Сохраняем sequence number клиента.
    __u32 client_seq = tcph->seq;

    // Для RST+ACK: seq=0, ack=client_seq+1 (ответ на SYN).
    tcph->seq = 0;
    tcph->ack_seq = __builtin_bswap32(__builtin_bswap32(client_seq) + 1);

    // Окно/urg не используются.
    tcph->window = 0;
    tcph->urg_ptr = 0;

    // Контрольные суммы обнуляем: будут пересчитаны сетевым стеком.
    iph->check = 0;
    tcph->check = 0;

    // Клонируем и отправляем пакет обратно через egress.
    // BPF_F_INGRESS=0 -> egress.
    (void)bpf_clone_redirect(skb, skb->ifindex, 0);

    // Исходный пакет всегда дропаем.
    return BPF_DROP;
}

SEC("tc")
int
l4_filter(struct __sk_buff* skb)
{
    void* data = (void*)(long)skb->data;
    void* data_end = (void*)(long)skb->data_end;

    struct ethhdr* eth = data;
    if ((void*)(eth + 1) > data_end) {
        return BPF_OK;
    }

    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return BPF_OK;
    }

    struct iphdr* iph = (void*)(eth + 1);
    if ((void*)(iph + 1) > data_end) {
        return BPF_OK;
    }

    if (iph->protocol != IPPROTO_TCP) {
        return BPF_OK;
    }

    __u32 ihl = iph->ihl * 4;
    if (ihl < sizeof(struct iphdr)) {
        return BPF_OK;
    }

    struct tcphdr* tcph = (void*)((void*)iph + ihl);
    if ((void*)(tcph + 1) > data_end) {
        return BPF_OK;
    }

    // Формируем 5-tuple ключ.
    struct flow5_key k = {};
    k.saddr = iph->saddr;
    k.daddr = iph->daddr;
    k.sport = tcph->source;
    k.dport = tcph->dest;
    k.proto = IPPROTO_TCP;

    __u8 tcp_flags = get_tcp_flags(tcph);
    __u16 dest_port = tcph->dest;

    // Один lookup в map защищенных портов.
    __u8* guarded_port_value = bpf_map_lookup_elem(&l4_guarded_port, &dest_port);
    int port_guarded = (guarded_port_value != NULL);

    if (!port_guarded) {
        update_stats(0, 1, STAT_ALLOW_DENY);
        update_stats(0, 0, STAT_NON_GUARDED_PORT); // разрешен незащищенный порт
        if (tcp_flags & TCP_SYN) {
            update_stats(0, 1, STAT_SYN_ALLOW_DENY); // разрешен SYN
        }
        log_event(&k, tcp_flags, LOG_NON_GUARDED_PORT, 1);
        return BPF_OK;
    }

    // Защищенный порт: нужна авторизация.
    if (tcp_flags & TCP_SYN) {
        log_event(&k, tcp_flags, LOG_SYN_RECEIVED, 0);
    }

    __u64 inactive_allow_ns = get_inactive_allow_ns();

    // Сначала проверяем active flow.
    __u64* active_exp = bpf_map_lookup_elem(&l4_active_flows, &k);
    if (active_exp && !is_expired(active_exp)) {
        // Продлеваем TTL активного потока.
        __u64 now = bpf_ktime_get_ns();
        __u64 new_exp = now + inactive_allow_ns;
        bpf_map_update_elem(&l4_active_flows, &k, &new_exp, BPF_ANY);

        update_stats(0, 1, STAT_ALLOW_DENY);
        if (tcp_flags & TCP_SYN) {
            update_stats(0, 1, STAT_SYN_ALLOW_DENY); // разрешен SYN
        }
        update_stats(0, 0, STAT_ACTIVE_FLOW_HIT); // попадание в активный поток
        log_event(&k, tcp_flags, LOG_ACTIVE_FLOW, 1);
        return BPF_OK;
    }

    // Проверяем pending-авторизацию source IP + destination port.
    __u8 lookup_key[8] = {0};
    build_pending_lookup_key(lookup_key, iph->saddr, dest_port);

    __u64* pending_exp = bpf_map_lookup_elem(&l4_pending_src, &lookup_key);
    if (pending_exp) {
        if (!is_expired(pending_exp)) {
            // Pending-авторизация найдена и не истекла.
            log_event(&k, tcp_flags, LOG_IP_PORT_AUTH, 1);

            // Для SYN создаем active flow.
            if (tcp_flags & TCP_SYN) {
                __u64 now = bpf_ktime_get_ns();
                __u64 new_active_exp = now + inactive_allow_ns;
                bpf_map_update_elem(&l4_active_flows, &k, &new_active_exp, BPF_ANY);

                update_stats(0, 0, STAT_PENDING_PROMOTION); // повышение из pending
                log_event(&k, tcp_flags, LOG_PENDING_PROMOTION, 1);
            } else {
                // Для не-SYN тоже создаем active flow:
                // полезно, если соединение уже шло до появления pending-записи.
                __u64 now = bpf_ktime_get_ns();
                __u64 new_active_exp = now + inactive_allow_ns;
                bpf_map_update_elem(&l4_active_flows, &k, &new_active_exp, BPF_ANY);
            }

            update_stats(0, 1, STAT_ALLOW_DENY);
            if (tcp_flags & TCP_SYN) {
                update_stats(0, 1, STAT_SYN_ALLOW_DENY); // разрешен SYN
            }
            update_stats(0, 0, STAT_IP_PORT_AUTH_HIT); // попадание авторизации IP+порт
            return BPF_OK;
        } else {
            // Pending-авторизация истекла: удаляем запись.
            bpf_map_delete_elem(&l4_pending_src, &lookup_key);
            update_stats(0, 0, STAT_PENDING_EXPIRED_CLEAN); // очистка истекших pending
            log_event(&k, tcp_flags, LOG_PENDING_EXPIRED, 0);
        }
    }

    // Пакет не авторизован.
    update_stats(0, 0, STAT_ALLOW_DENY);          // общая блокировка
    update_stats(0, 0, STAT_GUARDED_PORT_DENIED); // заблокирован защищенный порт

    // Для SYN отправляем RST, чтобы клиент сразу получил отказ.
    if (tcp_flags & TCP_SYN) {
        update_stats(0, 0, STAT_SYN_ALLOW_DENY); // заблокирован SYN
        log_event(&k, tcp_flags, LOG_GUARDED_PORT_DROPPED, 0);

        // Отправляем RST обратно клиенту.
        return send_rst(skb, iph, tcph);
    }

    log_event(&k, tcp_flags, LOG_GUARDED_PORT_DROPPED, 0);
    return BPF_DROP;
}

char _license[] SEC("license") = "MIT";
