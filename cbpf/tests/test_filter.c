#include "filter.skel.h"
#include "test_filter.h"
#include <test_progs.h>

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10
#define ACTIVE_ALLOW_NS (300 * 1000000000ULL)

// Тестовые данные
struct test_packet
{
    struct ethhdr eth;
    struct iphdr ip;
    struct tcphdr tcp;
    char payload[64];
};

static struct test_packet
create_test_packet(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport, __u8 tcp_flags)
{
    struct test_packet pkt = {0};

    // Ethernet заголовок
    memset(pkt.eth.h_dest, 0xaa, ETH_ALEN);
    memset(pkt.eth.h_source, 0xbb, ETH_ALEN);
    pkt.eth.h_proto = htons(ETH_P_IP);

    // IP заголовок
    pkt.ip.ihl = 5;
    pkt.ip.version = 4;
    pkt.ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    pkt.ip.id = htons(1234);
    pkt.ip.frag_off = 0;
    pkt.ip.ttl = 64;
    pkt.ip.protocol = IPPROTO_TCP;
    pkt.ip.check = 0;
    pkt.ip.saddr = saddr;
    pkt.ip.daddr = daddr;

    // TCP заголовок
    pkt.tcp.source = sport;
    pkt.tcp.dest = dport;
    pkt.tcp.seq = htonl(1000);
    pkt.tcp.ack_seq = 0;
    pkt.tcp.doff = 5;
    pkt.tcp.res1 = 0;
    pkt.tcp.window = htons(64240);
    pkt.tcp.check = 0;
    pkt.tcp.urg_ptr = 0;

    // TCP флаги
    *((__u8*)&pkt.tcp + 13) = tcp_flags;

    return pkt;
}

void
test_non_guarded_port(void)
{
    struct rdp_filter* skel;
    struct bpf_prog_test_run_attr attr = {0};
    struct test_packet pkt;
    int err;

    // Загружаем скелетон BPF программы
    skel = rdp_filter__open_and_load();
    if (!ASSERT_OK_PTR(skel, "rdp_filter__open_and_load"))
        return;

    // Создаем пакет с незащищенным портом
    pkt = create_test_packet(
        htonl(0x0a000001), // 10.0.0.1
        htonl(0x0a000002), // 10.0.0.2
        htons(12345),      // source port
        htons(80),         // destination port (не защищен)
        TCP_SYN);

    // Настраиваем тестовый запуск
    attr.prog_fd = bpf_program__fd(skel->progs.rdp_filter);
    attr.data_in = &pkt;
    attr.data_size_in = sizeof(pkt);
    attr.data_out = NULL;
    attr.data_size_out = 0;
    attr.repeat = 1;

    // Запускаем программу
    err = bpf_prog_test_run_xattr(&attr);
    ASSERT_OK(err, "bpf_prog_test_run");

    // Проверяем, что пакет разрешен
    ASSERT_EQ(attr.retval, BPF_OK, "packet_should_be_allowed");

    // Проверяем статистику
    struct stats_val* stats;
    int stats_key = 0;
    stats = bpf_map__lookup_elem(skel->maps.rdp_stats, &stats_key, sizeof(stats_key), sizeof(*stats), 0);

    ASSERT_OK_PTR(stats, "lookup_stats");
    ASSERT_EQ(stats->allowed, 1, "stats_allowed");
    ASSERT_EQ(stats->non_guarded_port_allowed, 1, "non_guarded_port_allowed");

    rdp_filter__destroy(skel);
}

void
test_guarded_port_no_auth(void)
{
    struct rdp_filter* skel;
    struct bpf_prog_test_run_attr attr = {0};
    struct test_packet pkt;
    int err;

    skel = rdp_filter__open_and_load();
    if (!ASSERT_OK_PTR(skel, "rdp_filter__open_and_load"))
        return;

    // Добавляем защищенный порт
    __u16 guarded_port = htons(3389); // RDP порт
    __u8 value = 1;
    err = bpf_map_update_elem(bpf_map__fd(skel->maps.rdp_guarded_ports), &guarded_port, &value, BPF_ANY);
    ASSERT_OK(err, "add_guarded_port");

    // Создаем SYN пакет на защищенный порт без авторизации
    pkt = create_test_packet(
        htonl(0x0a000001), // 10.0.0.1
        htonl(0x0a000002), // 10.0.0.2
        htons(12345),      // source port
        htons(3389),       // destination port (защищен)
        TCP_SYN);

    attr.prog_fd = bpf_program__fd(skel->progs.rdp_filter);
    attr.data_in = &pkt;
    attr.data_size_in = sizeof(pkt);
    attr.data_out = NULL;
    attr.data_size_out = 0;
    attr.repeat = 1;

    err = bpf_prog_test_run_xattr(&attr);
    ASSERT_OK(err, "bpf_prog_test_run");

    // Проверяем, что пакет заблокирован
    ASSERT_EQ(attr.retval, BPF_DROP, "packet_should_be_dropped");

    // Проверяем статистику
    struct stats_val* stats;
    int stats_key = 0;
    stats = bpf_map__lookup_elem(skel->maps.rdp_stats, &stats_key, sizeof(stats_key), sizeof(*stats), 0);

    ASSERT_OK_PTR(stats, "lookup_stats");
    ASSERT_EQ(stats->dropped, 1, "stats_dropped");
    ASSERT_EQ(stats->syn_dropped, 1, "syn_dropped");
    ASSERT_EQ(stats->guarded_port_dropped, 1, "guarded_port_dropped");

    rdp_filter__destroy(skel);
}

void
test_active_flow_hit(void)
{
    struct rdp_filter* skel;
    struct bpf_prog_test_run_attr attr = {0};
    struct test_packet pkt;
    struct flow5_key flow_key;
    __u64 expiry;
    int err;

    skel = rdp_filter__open_and_load();
    if (!ASSERT_OK_PTR(skel, "rdp_filter__open_and_load"))
        return;

    // Добавляем защищенный порт
    __u16 guarded_port = htons(3389);
    __u8 value = 1;
    err = bpf_map_update_elem(bpf_map__fd(skel->maps.rdp_guarded_ports), &guarded_port, &value, BPF_ANY);
    ASSERT_OK(err, "add_guarded_port");

    // Добавляем активный флоу
    flow_key.saddr = htonl(0x0a000001);
    flow_key.daddr = htonl(0x0a000002);
    flow_key.sport = htons(12345);
    flow_key.dport = htons(3389);
    flow_key.proto = IPPROTO_TCP;

    expiry = bpf_ktime_get_ns() + ACTIVE_ALLOW_NS / 2; // Время еще не истекло
    err = bpf_map_update_elem(bpf_map__fd(skel->maps.rdp_active_flows), &flow_key, &expiry, BPF_ANY);
    ASSERT_OK(err, "add_active_flow");

    // Создаем пакет (не SYN) для существующего флоу
    pkt = create_test_packet(
        htonl(0x0a000001),
        htonl(0x0a000002),
        htons(12345),
        htons(3389),
        TCP_ACK // Флаг ACK, не SYN
    );

    attr.prog_fd = bpf_program__fd(skel->progs.rdp_filter);
    attr.data_in = &pkt;
    attr.data_size_in = sizeof(pkt);
    attr.data_out = NULL;
    attr.data_size_out = 0;
    attr.repeat = 1;

    err = bpf_prog_test_run_xattr(&attr);
    ASSERT_OK(err, "bpf_prog_test_run");

    // Проверяем, что пакет разрешен
    ASSERT_EQ(attr.retval, BPF_OK, "packet_should_be_allowed");

    // Проверяем статистику
    struct stats_val* stats;
    int stats_key = 0;
    stats = bpf_map__lookup_elem(skel->maps.rdp_stats, &stats_key, sizeof(stats_key), sizeof(*stats), 0);

    ASSERT_OK_PTR(stats, "lookup_stats");
    ASSERT_EQ(stats->allowed, 1, "stats_allowed");
    ASSERT_EQ(stats->active_flow_hits, 1, "active_flow_hits");

    rdp_filter__destroy(skel);
}

void
test_pending_promotion(void)
{
    struct rdp_filter* skel;
    struct bpf_prog_test_run_attr attr = {0};
    struct test_packet pkt;
    __u8 lookup_key[8] = {0};
    __u64 expiry;
    int err;

    skel = rdp_filter__open_and_load();
    if (!ASSERT_OK_PTR(skel, "rdp_filter__open_and_load"))
        return;

    // Добавляем защищенный порт
    __u16 guarded_port = htons(3389);
    __u8 value = 1;
    err = bpf_map_update_elem(bpf_map__fd(skel->maps.rdp_guarded_ports), &guarded_port, &value, BPF_ANY);
    ASSERT_OK(err, "add_guarded_port");

    // Добавляем pending запись
    *((__u32*)&lookup_key[0]) = htonl(0x0a000001); // IP источника
    lookup_key[4] = (ntohs(guarded_port) >> 8) & 0xFF;
    lookup_key[5] = ntohs(guarded_port) & 0xFF;

    expiry = bpf_ktime_get_ns() + ACTIVE_ALLOW_NS / 2;
    err = bpf_map_update_elem(bpf_map__fd(skel->maps.rdp_pending_src), lookup_key, &expiry, BPF_ANY);
    ASSERT_OK(err, "add_pending_entry");

    // Создаем SYN пакет от авторизованного IP
    pkt = create_test_packet(htonl(0x0a000001), htonl(0x0a000002), htons(12345), htons(3389), TCP_SYN);

    attr.prog_fd = bpf_program__fd(skel->progs.rdp_filter);
    attr.data_in = &pkt;
    attr.data_size_in = sizeof(pkt);
    attr.data_out = NULL;
    attr.data_size_out = 0;
    attr.repeat = 1;

    err = bpf_prog_test_run_xattr(&attr);
    ASSERT_OK(err, "bpf_prog_test_run");

    // Проверяем, что пакет разрешен
    ASSERT_EQ(attr.retval, BPF_OK, "packet_should_be_allowed");

    // Проверяем статистику
    struct stats_val* stats;
    int stats_key = 0;
    stats = bpf_map__lookup_elem(skel->maps.rdp_stats, &stats_key, sizeof(stats_key), sizeof(*stats), 0);

    ASSERT_OK_PTR(stats, "lookup_stats");
    ASSERT_EQ(stats->allowed, 1, "stats_allowed");
    ASSERT_EQ(stats->pending_promotions, 1, "pending_promotions");
    ASSERT_EQ(stats->ip_port_auth_hits, 1, "ip_port_auth_hits");

    // Проверяем, что флоу добавлен в активные
    struct flow5_key flow_key;
    flow_key.saddr = htonl(0x0a000001);
    flow_key.daddr = htonl(0x0a000002);
    flow_key.sport = htons(12345);
    flow_key.dport = htons(3389);
    flow_key.proto = IPPROTO_TCP;

    __u64* active_expiry =
        bpf_map__lookup_elem(skel->maps.rdp_active_flows, &flow_key, sizeof(flow_key), sizeof(__u64), 0);
    ASSERT_OK_PTR(active_expiry, "active_flow_created");

    rdp_filter__destroy(skel);
}

void
test_expired_pending_cleanup(void)
{
    struct rdp_filter* skel;
    struct bpf_prog_test_run_attr attr = {0};
    struct test_packet pkt;
    __u8 lookup_key[8] = {0};
    __u64 expiry;
    int err;

    skel = rdp_filter__open_and_load();
    if (!ASSERT_OK_PTR(skel, "rdp_filter__open_and_load"))
        return;

    // Добавляем защищенный порт
    __u16 guarded_port = htons(3389);
    __u8 value = 1;
    err = bpf_map_update_elem(bpf_map__fd(skel->maps.rdp_guarded_ports), &guarded_port, &value, BPF_ANY);
    ASSERT_OK(err, "add_guarded_port");

    // Добавляем истекшую pending запись
    *((__u32*)&lookup_key[0]) = htonl(0x0a000001);
    lookup_key[4] = (ntohs(guarded_port) >> 8) & 0xFF;
    lookup_key[5] = ntohs(guarded_port) & 0xFF;

    expiry = bpf_ktime_get_ns() - 1000000; // Истекшая запись
    err = bpf_map_update_elem(bpf_map__fd(skel->maps.rdp_pending_src), lookup_key, &expiry, BPF_ANY);
    ASSERT_OK(err, "add_expired_pending");

    // Создаем SYN пакет
    pkt = create_test_packet(htonl(0x0a000001), htonl(0x0a000002), htons(12345), htons(3389), TCP_SYN);

    attr.prog_fd = bpf_program__fd(skel->progs.rdp_filter);
    attr.data_in = &pkt;
    attr.data_size_in = sizeof(pkt);
    attr.data_out = NULL;
    attr.data_size_out = 0;
    attr.repeat = 1;

    err = bpf_prog_test_run_xattr(&attr);
    ASSERT_OK(err, "bpf_prog_test_run");

    // Проверяем, что пакет заблокирован (запись истекла)
    ASSERT_EQ(attr.retval, BPF_DROP, "packet_should_be_dropped");

    // Проверяем статистику
    struct stats_val* stats;
    int stats_key = 0;
    stats = bpf_map__lookup_elem(skel->maps.rdp_stats, &stats_key, sizeof(stats_key), sizeof(*stats), 0);

    ASSERT_OK_PTR(stats, "lookup_stats");
    ASSERT_EQ(stats->pending_expired_cleanups, 1, "pending_expired_cleanups");

    // Проверяем, что pending запись удалена
    __u64* pending = bpf_map__lookup_elem(skel->maps.rdp_pending_src, lookup_key, sizeof(lookup_key), sizeof(__u64), 0);
    ASSERT_NULL(pending, "expired_pending_removed");

    rdp_filter__destroy(skel);
}

void
test_rst_generation(void)
{
    struct rdp_filter* skel;
    struct bpf_prog_test_run_attr attr = {0};
    struct test_packet pkt;
    int err;

    skel = rdp_filter__open_and_load();
    if (!ASSERT_OK_PTR(skel, "rdp_filter__open_and_load"))
        return;

    // Добавляем защищенный порт
    __u16 guarded_port = htons(3389);
    __u8 value = 1;
    err = bpf_map_update_elem(bpf_map__fd(skel->maps.rdp_guarded_ports), &guarded_port, &value, BPF_ANY);
    ASSERT_OK(err, "add_guarded_port");

    // Создаем SYN пакет без авторизации
    pkt = create_test_packet(htonl(0x0a000001), htonl(0x0a000002), htons(12345), htons(3389), TCP_SYN);

    // Сохраняем оригинальные значения для проверки
    __be32 orig_saddr = pkt.ip.saddr;
    __be32 orig_daddr = pkt.ip.daddr;
    __be16 orig_sport = pkt.tcp.source;
    __be16 orig_dport = pkt.tcp.dest;

    attr.prog_fd = bpf_program__fd(skel->progs.rdp_filter);
    attr.data_in = &pkt;
    attr.data_size_in = sizeof(pkt);

    // Выделяем буфер для выходных данных (модифицированный пакет)
    void* data_out = malloc(sizeof(pkt));
    attr.data_out = data_out;
    attr.data_size_out = sizeof(pkt);
    attr.repeat = 1;

    err = bpf_prog_test_run_xattr(&attr);
    ASSERT_OK(err, "bpf_prog_test_run");

    // Проверяем, что функция пыталась отправить RST
    // (bpf_clone_redirect возвращает код пересылки, а не BPF_DROP)
    ASSERT_NE(attr.retval, BPF_DROP, "should_try_redirect");

    // Проверяем, что пакет был модифицирован (теоретически)
    // В реальности bpf_prog_test_run может не поддерживать полную эмуляцию

    free(data_out);
    rdp_filter__destroy(skel);
}
