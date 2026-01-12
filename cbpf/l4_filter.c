// SPDX-License-Identifier: MIT
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

// Определяем константы
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


// Ключ для 5-tuple (IPv4)
// Все поля в network byte order (big-endian), как в сетевых заголовках
struct flow5_key {
    __u32 saddr;  // IP источника (network byte order)
    __u32 daddr;  // IP назначения (network byte order)
    __u16 sport;  // порт источника (network byte order)
    __u16 dport;  // порт назначения (network byte order)
    __u8  proto;
    __u8  pad1;
    __u16 pad2;
};

// Ключ для авторизации по IP+порт
// Все поля в network byte order (big-endian), как в сетевых заголовках
struct ip_port_key {
    __u32 saddr;    // IP источника (network byte order)
    __u16 dport;    // порт назначения (network byte order)
    __u16 pad;
};

// Карта активных потоков
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct flow5_key);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rdp_active_flows SEC(".maps");

// Ожидающие handshake по IP источника + порт назначения
// ВАЖНО: используем байтовый массив для ключа вместо структуры
// Это гарантирует, что порядок байт не будет конвертироваться ядром
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u8[8]);  // байтовый массив из 8 байт вместо структуры
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rdp_pending_src SEC(".maps");

// Конфигурация защищенных портов
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);  // порт в сетевом порядке байт
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rdp_guarded_ports SEC(".maps");

// Статистика
struct stats_val {
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
    __u64 port_3389_not_found_in_map; // диагностика: порт 3389 не найден в карте
    __u64 port_3389_found_in_map;     // диагностика: порт 3389 найден в карте
    __u64 pending_lookup_failed;      // диагностика: lookup в pending map не нашел запись
    __u64 pending_lookup_success;     // диагностика: lookup в pending map нашел запись
    __u64 last_pending_key_saddr;    // диагностика: последний saddr, использованный для lookup
    __u64 last_pending_key_dport;    // диагностика: последний dport, использованный для lookup
    __u64 last_pending_key_pad;      // диагностика: последний pad, использованный для lookup
    __u64 lookup_key_bytes_0_3;      // диагностика: первые 4 байта lookup_key (для сравнения)
    __u64 lookup_key_bytes_4_7;      // диагностика: последние 4 байта lookup_key (для сравнения)
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rdp_stats SEC(".maps");

// События для логирования и отладки
struct log_event {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 tcp_flags;
    __u8 event_type;
    __u8 result;
    __u32 pad;
};

// Дополнительная структура для диагностики ключей pending map
struct pending_key_debug {
    __u32 saddr;
    __u16 dport;
    __u16 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} rdp_logs SEC(".maps");

// Временные константы
#define ACTIVE_ALLOW_NS ((__u64)300 * 1000000000ULL)

// Типы событий
#define EVENT_SYN_RECEIVED 0
#define EVENT_ACTIVE_FLOW 1
#define EVENT_PENDING_PROMOTION 2
#define EVENT_PENDING_EXPIRED 7
#define EVENT_IP_PORT_AUTH 8
#define EVENT_NON_GUARDED_PORT 9
#define EVENT_GUARDED_PORT_DROPPED 10

static __always_inline int update_stats(__u32 idx, int allow, int stat_type) {
    struct stats_val *s = bpf_map_lookup_elem(&rdp_stats, &idx);
    if (!s) return 0;

    switch (stat_type) {
        case 0: // общее разрешение/блокировка
            if (allow) __sync_fetch_and_add(&s->allowed, 1);
            else __sync_fetch_and_add(&s->dropped, 1);
            break;
        case 1: // разрешение/блокировка SYN
            if (allow) __sync_fetch_and_add(&s->syn_allowed, 1);
            else __sync_fetch_and_add(&s->syn_dropped, 1);
            break;
        case 2: // попадание в активный поток
            __sync_fetch_and_add(&s->active_flow_hits, 1);
            break;
        case 3: // повышение из pending
            __sync_fetch_and_add(&s->pending_promotions, 1);
            break;
        case 6: // очистка истекших pending
            __sync_fetch_and_add(&s->pending_expired_cleanups, 1);
            break;
        case 7: // попадание авторизации IP+порт
            __sync_fetch_and_add(&s->ip_port_auth_hits, 1);
            break;
        case 8: // разрешен незащищенный порт
            __sync_fetch_and_add(&s->non_guarded_port_allowed, 1);
            break;
        case 9: // заблокирован защищенный порт
            __sync_fetch_and_add(&s->guarded_port_dropped, 1);
            break;
        case 10: // диагностика: порт 3389 не найден в карте
            __sync_fetch_and_add(&s->port_3389_not_found_in_map, 1);
            break;
        case 11: // диагностика: порт 3389 найден в карте
            __sync_fetch_and_add(&s->port_3389_found_in_map, 1);
            break;
        case 12: // диагностика: lookup в pending map не нашел запись
            __sync_fetch_and_add(&s->pending_lookup_failed, 1);
            break;
        case 13: // диагностика: lookup в pending map нашел запись
            __sync_fetch_and_add(&s->pending_lookup_success, 1);
            break;
        case 14: // диагностика: сохранить saddr ключа для pending lookup
            // Используем allowed как временное хранилище для saddr
            // (это не идеально, но для диагностики сойдет)
            break;
        case 15: // диагностика: сохранить dport ключа для pending lookup
            // Используем dropped как временное хранилище для dport
            // (это не идеально, но для диагностики сойдет)
            break;
    }
    return 0;
}

static __always_inline void log_event(struct flow5_key *k, __u8 tcp_flags, __u8 event_type, __u8 result) {
    struct log_event *event = bpf_ringbuf_reserve(&rdp_logs, sizeof(struct log_event), 0);
    if (!event) return;

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

static __always_inline int is_expired(__u64 *expiry_ns) {
    if (!expiry_ns) return 1;
    __u64 now = bpf_ktime_get_ns();
    return now > *expiry_ns;
}

static __always_inline __u8 get_tcp_flags(struct tcphdr *tcph) {
    return *(__u8 *)tcph & 0x3F;
}

// Функция is_port_guarded удалена - используем прямой lookup для всех портов

// Отправка RST пакета путем модификации входящего SYN и перенаправления обратно
static __always_inline int send_rst(struct __sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph) {
    // Отправляем RST только для SYN пакетов
    if (!(get_tcp_flags(tcph) & TCP_SYN)) {
        return BPF_DROP;
    }

    // Меняем местами IP источника и назначения
    __u32 tmp_ip = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = tmp_ip;

    // Меняем местами порты источника и назначения
    __u16 tmp_port = tcph->source;
    tcph->source = tcph->dest;
    tcph->dest = tmp_port;

    // Устанавливаем флаги RST+ACK
    // TCP флаги находятся в байте 13 заголовка TCP (смещение от начала tcph)
    // Очищаем все флаги и устанавливаем RST и ACK
    __u8 *flags_byte = (__u8 *)tcph + 13;
    *flags_byte = 0; // Сначала очищаем все флаги
    *flags_byte = TCP_RST | TCP_ACK;

    // Сохраняем sequence number клиента перед модификацией
    __u32 client_seq = tcph->seq;

    // Устанавливаем sequence number в 0 для RST ответа
    tcph->seq = 0;
    // Устанавливаем ack number в seq клиента + 1 (для SYN)
    tcph->ack_seq = __builtin_bswap32(__builtin_bswap32(client_seq) + 1);

    // Сбрасываем окно и указатель urgent
    tcph->window = 0;
    tcph->urg_ptr = 0;

    // Сбрасываем контрольную сумму IP (ядро пересчитает)
    iph->check = 0;

    // Сбрасываем контрольную сумму TCP (ядро пересчитает)
    tcph->check = 0;

    // Клонируем и перенаправляем пакет обратно через egress
    // BPF_F_INGRESS = 0 означает направление egress
    return bpf_clone_redirect(skb, skb->ifindex, 0);
}

SEC("tc")
int rdp_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return BPF_OK;
    }

    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return BPF_OK;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return BPF_OK;
    }

    if (iph->protocol != IPPROTO_TCP) {
        return BPF_OK;
    }

    __u32 ihl = iph->ihl * 4;
    if (ihl < sizeof(struct iphdr)) {
        return BPF_OK;
    }

    struct tcphdr *tcph = (void *)((void *)iph + ihl);
    if ((void *)(tcph + 1) > data_end) {
        return BPF_OK;
    }

    // Строим ключ 5-tuple
    // IP адреса и порты в заголовках уже в network byte order (big-endian)
    struct flow5_key k = {};
    k.saddr = iph->saddr;  // IP источника (network byte order)
    k.daddr = iph->daddr;  // IP назначения (network byte order)
    k.sport = tcph->source; // порт источника (network byte order)
    k.dport = tcph->dest;   // порт назначения (network byte order)
    k.proto = IPPROTO_TCP;

    __u8 tcp_flags = get_tcp_flags(tcph);
    __u16 dest_port = tcph->dest;

    // Проверяем, защищен ли порт назначения
    // ВАЖНО: делаем lookup один раз и используем результат везде
    __u8 *guarded_port_value = bpf_map_lookup_elem(&rdp_guarded_ports, &dest_port);
    int port_guarded = (guarded_port_value != NULL);

    // ДИАГНОСТИКА: для порта 3389 логируем результат
    if (dest_port == __constant_htons(3389)) {
        if (guarded_port_value == NULL) {
            // Порт 3389 не найден в карте - это проблема!
            update_stats(0, 0, 10); // порт 3389 не найден в карте
        } else {
            // Порт 3389 найден в карте - это хорошо
            update_stats(0, 0, 11); // порт 3389 найден в карте
        }
    }

    if (!port_guarded) {
        update_stats(0, 1, 0);
        update_stats(0, 0, 8); // разрешен незащищенный порт
        log_event(&k, tcp_flags, EVENT_NON_GUARDED_PORT, 1);
        return BPF_OK;
    }

    // ПОРТ ЗАЩИЩЕН - требуется авторизация
    log_event(&k, tcp_flags, EVENT_SYN_RECEIVED, 0);

    // Сначала проверяем активный поток
    __u64 *active_exp = bpf_map_lookup_elem(&rdp_active_flows, &k);
    if (active_exp && !is_expired(active_exp)) {
        // Обновляем срок действия при трафике
        __u64 now = bpf_ktime_get_ns();
        __u64 new_exp = now + ACTIVE_ALLOW_NS;
        bpf_map_update_elem(&rdp_active_flows, &k, &new_exp, BPF_ANY);

        update_stats(0, 1, 0);
        update_stats(0, 0, 2); // попадание в активный поток
        log_event(&k, tcp_flags, EVENT_ACTIVE_FLOW, 1);
        return BPF_OK;
    }

    // Проверяем pending по IP источника + порт назначения
    // ПРОБЛЕМА: использование структуры может вызывать проблемы с порядком байт при lookup
    // РЕШЕНИЕ: используем байтовый массив для lookup, чтобы гарантировать правильный порядок байт
    // IP адреса и порты уже в network byte order, используем напрямую
    __u8 lookup_key[8] = {0};

    // ВАЖНО: записываем байты напрямую из заголовков пакетов
    // IP источника и порт назначения уже в network byte order (big-endian) из заголовков
    // Используем прямое присваивание через указатели для IP (4 байта - безопасно)
    *((__u32 *)&lookup_key[0]) = iph->saddr;  // IP источника (network byte order)

    // ВАЖНО: для порта записываем байты напрямую, чтобы гарантировать network byte order
    // dest_port уже в network byte order (big-endian), но присваивание через указатель
    // может конвертировать порядок байт, поэтому записываем байты напрямую
    lookup_key[4] = (dest_port >> 8) & 0xFF;  // старший байт порта
    lookup_key[5] = dest_port & 0xFF;        // младший байт порта

    // pad уже инициализирован нулем через {0}

    // ДИАГНОСТИКА: для порта 3389 сохраняем ключ ДО lookup
    // Сохраняем байты ключа для сравнения с записанным ключом
    if (dest_port == __constant_htons(3389)) {
        struct stats_val *s = bpf_map_lookup_elem(&rdp_stats, &(__u32){0});
        if (s) {
            // Сохраняем IP и порт для диагностики
            s->last_pending_key_saddr = *((__u32 *)&lookup_key[0]);
            s->last_pending_key_dport = *((__u16 *)&lookup_key[4]);
            s->last_pending_key_pad = *((__u16 *)&lookup_key[6]);

            // ДИАГНОСТИКА: сохраняем байты ключа напрямую для сравнения
            // Это поможет понять, правильно ли формируется ключ
            s->lookup_key_bytes_0_3 = *((__u32 *)&lookup_key[0]);
            s->lookup_key_bytes_4_7 = *((__u32 *)&lookup_key[4]);
        }
    }

    // Используем байтовый массив для lookup
    __u64 *pending_exp = bpf_map_lookup_elem(&rdp_pending_src, &lookup_key);

    // ДИАГНОСТИКА: для порта 3389 проверяем результат поиска и сохраняем ключ
    if (dest_port == __constant_htons(3389)) {
        // Сохраняем ключ, который мы используем для поиска, в статистику
        // Это поможет понять, почему ключи не совпадают
        struct stats_val *s = bpf_map_lookup_elem(&rdp_stats, &(__u32){0});
        if (s) {
            s->last_pending_key_saddr = *((__u32 *)&lookup_key[0]);
            s->last_pending_key_dport = *((__u16 *)&lookup_key[4]);
            s->last_pending_key_pad = *((__u16 *)&lookup_key[6]);
        }

        // Логируем ключ для диагностики
        log_event(&k, tcp_flags, EVENT_IP_PORT_AUTH, 0);

        if (pending_exp == NULL) {
            // Запись не найдена в pending map - это проблема!
            update_stats(0, 0, 12); // pending lookup failed
            log_event(&k, tcp_flags, EVENT_PENDING_EXPIRED, 0);
        } else {
            // Запись найдена - логируем для диагностики
            update_stats(0, 0, 13); // pending lookup success
            log_event(&k, tcp_flags, EVENT_IP_PORT_AUTH, 1);
        }
    }

    if (pending_exp) {
        if (!is_expired(pending_exp)) {
            // IP+port авторизован и не истек
            log_event(&k, tcp_flags, EVENT_IP_PORT_AUTH, 1);

            // Для SYN пакетов создаем активный флоу
            if (tcp_flags & TCP_SYN) {
                __u64 now = bpf_ktime_get_ns();
                __u64 new_active_exp = now + ACTIVE_ALLOW_NS;
                bpf_map_update_elem(&rdp_active_flows, &k, &new_active_exp, BPF_ANY);

                update_stats(0, 0, 3); // повышение из pending
                log_event(&k, tcp_flags, EVENT_PENDING_PROMOTION, 1);
            } else {
                // Для не-SYN пакетов (уже установленное соединение) также создаем active flow
                // Это нужно для случаев, когда соединение было установлено до добавления в pending
                __u64 now = bpf_ktime_get_ns();
                __u64 new_active_exp = now + ACTIVE_ALLOW_NS;
                bpf_map_update_elem(&rdp_active_flows, &k, &new_active_exp, BPF_ANY);
            }

            update_stats(0, 1, 0);
            update_stats(0, 0, 7); // попадание авторизации IP+порт
            return BPF_OK;
        } else {
            // IP+порт истек - удаляем
            bpf_map_delete_elem(&rdp_pending_src, &lookup_key);
            update_stats(0, 0, 6); // очистка истекших pending
            log_event(&k, tcp_flags, EVENT_PENDING_EXPIRED, 0);
        }
    }

    // Если дошли сюда - пакет НЕ авторизован
    update_stats(0, 0, 0); // общая блокировка
    update_stats(0, 0, 9); // заблокирован защищенный порт

    // Для SYN пакетов отправляем RST для быстрой реакции клиента
    if (tcp_flags & TCP_SYN) {
        update_stats(0, 0, 1); // заблокирован SYN
        log_event(&k, tcp_flags, EVENT_GUARDED_PORT_DROPPED, 0);

        // Отправляем RST пакет обратно клиенту
        int ret = send_rst(skb, iph, tcph);
        if (ret >= 0) {
            return ret; // перенаправление успешно
        }
        // Если перенаправление не удалось, продолжаем с блокировкой
    }

    log_event(&k, tcp_flags, EVENT_GUARDED_PORT_DROPPED, 0);
    return BPF_DROP;
}

char _license[] SEC("license") = "MIT";
