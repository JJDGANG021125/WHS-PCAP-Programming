#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14
#define ETHERTYPE_IPV4 0x0800

struct ethheader {
    uint8_t ether_dhost[ETHER_ADDR_LEN];
    uint8_t ether_shost[ETHER_ADDR_LEN];
    uint16_t ether_type;
} __attribute__((packed));

struct ipheader {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint8_t iph_ihl : 4;
    uint8_t iph_ver : 4;
#else
    uint8_t iph_ver : 4;
    uint8_t iph_ihl : 4;
#endif
    uint8_t iph_tos;
    uint16_t iph_len;
    uint16_t iph_ident;
    uint16_t iph_flags_offset;
    uint8_t iph_ttl;
    uint8_t iph_protocol;
    uint16_t iph_chksum;
    struct in_addr iph_sourceip;
    struct in_addr iph_destip;
} __attribute__((packed));

struct tcpheader {
    uint16_t tcp_sport;
    uint16_t tcp_dport;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint8_t tcp_reserved : 4;
    uint8_t tcp_offset : 4;
#else
    uint8_t tcp_offset : 4;
    uint8_t tcp_reserved : 4;
#endif
    uint8_t tcp_flags;
    uint16_t tcp_window;
    uint16_t tcp_checksum;
    uint16_t tcp_urgent;
} __attribute__((packed));

void print_mac(const uint8_t mac[ETHER_ADDR_LEN]) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct ethheader *eth;
    const struct ipheader *ip;
    const struct tcpheader *tcp;
    int ip_header_len;
    int tcp_header_len;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    if (header->caplen < ETHER_HDR_LEN + 20) {
        return;
    }

    eth = (const struct ethheader *)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IPV4) {
        return;
    }

    ip = (const struct ipheader *)(packet + ETHER_HDR_LEN);
    ip_header_len = ip->iph_ihl * 4;

    if (ip->iph_ver != 4 || ip_header_len < 20) {
        return;
    }

    if (ip->iph_protocol != IPPROTO_TCP) {
        return;
    }

    if (header->caplen < ETHER_HDR_LEN + ip_header_len + 20) {
        return;
    }

    tcp = (const struct tcpheader *)(packet + ETHER_HDR_LEN + ip_header_len);
    tcp_header_len = tcp->tcp_offset * 4;

    if (tcp_header_len < 20) {
        return;
    }

    inet_ntop(AF_INET, &ip->iph_sourceip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip->iph_destip, dst_ip, sizeof(dst_ip));

    printf("\n================ PACKET ================\n");
    printf("[Ethernet Header]\n");
    printf("Src MAC : ");
    print_mac(eth->ether_shost);
    printf("\n");
    printf("Dst MAC : ");
    print_mac(eth->ether_dhost);
    printf("\n");

    printf("[IP Header]\n");
    printf("Src IP : %s\n", src_ip);
    printf("Dst IP : %s\n", dst_ip);
    printf("IP Header Length : %d bytes\n", ip_header_len);

    printf("[TCP Header]\n");
    printf("Src Port : %u\n", ntohs(tcp->tcp_sport));
    printf("Dst Port : %u\n", ntohs(tcp->tcp_dport));
    printf("TCP Header Length : %d bytes\n", tcp_header_len);
    printf("========================================\n");
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if (argc != 2) {
        printf("사용법: sudo %s <인터페이스>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        printf("패킷 캡처 시작 실패: %s\n", errbuf);
        return 1;
    }

    printf("패킷 캡처 시작: %s\n", argv[1]);
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);

    return 0;
}
