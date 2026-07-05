#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14
#define ETHERTYPE_IPV4 0x0800


/* Ethernet Header */
struct ethheader {
    uint8_t ether_dhost[ETHER_ADDR_LEN];
    uint8_t ether_shost[ETHER_ADDR_LEN];
    uint16_t ether_type;
} __attribute__((packed));


/* IPv4 Header */
struct ipheader {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint8_t iph_ihl : 4;
    uint8_t iph_ver : 4;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    uint8_t iph_ver : 4;
    uint8_t iph_ihl : 4;
#else
#error "Unsupported byte order"
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


/* TCP Header */
struct tcpheader {
    uint16_t tcp_sport;
    uint16_t tcp_dport;
    uint32_t tcp_seq;
    uint32_t tcp_ack;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint8_t tcp_reserved : 4;
    uint8_t tcp_offset : 4;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    uint8_t tcp_offset : 4;
    uint8_t tcp_reserved : 4;
#else
#error "Unsupported byte order"
#endif

    uint8_t tcp_flags;
    uint16_t tcp_window;
    uint16_t tcp_checksum;
    uint16_t tcp_urgent;
} __attribute__((packed));


/* MAC 주소 출력 함수 */
void print_mac(const uint8_t mac[ETHER_ADDR_LEN]) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}


/* HTTP Message 출력 함수 */
void print_http_message(
    const u_char *payload,
    int payload_len
) {
    printf("[HTTP Message]\n");

    for (int i = 0; i < payload_len; i++) {
        unsigned char c = payload[i];

        if (isprint(c) ||
            c == '\r' ||
            c == '\n' ||
            c == '\t') {
            putchar(c);
        } else {
            putchar('.');
        }
    }

    printf("\n");
}


/* 패킷이 캡처될 때마다 실행 */
void got_packet(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
) {
    (void)args;


    /* 1. Ethernet Header 최소 길이 확인 */
    if (header->caplen <
        sizeof(struct ethheader)) {
        return;
    }


    /* packet 시작을 Ethernet Header로 해석 */
    const struct ethheader *eth =
        (const struct ethheader *)packet;


    /* IPv4만 처리 */
    if (ntohs(eth->ether_type) !=
        ETHERTYPE_IPV4) {
        return;
    }


    /* IP Header 최소 길이 확인 */
    if (header->caplen <
        ETHER_HDR_LEN +
        sizeof(struct ipheader)) {
        return;
    }


    /* 2. IP Header 시작 위치 */
    const struct ipheader *ip =
        (const struct ipheader *)
        (packet + ETHER_HDR_LEN);


    /* 실제 IP Header 길이 계산 */
    int ip_header_len =
        ip->iph_ihl * 4;


    /* IPv4인지 확인 */
    if (ip->iph_ver != 4) {
        return;
    }


    /* IP Header 최소 길이 확인 */
    if (ip_header_len < 20) {
        return;
    }


    /* 실제 캡처 데이터가 IP Header 전체를 포함하는지 확인 */
    if (header->caplen <
        (bpf_u_int32)
        (ETHER_HDR_LEN +
         ip_header_len)) {
        return;
    }


    /* TCP만 처리 */
    if (ip->iph_protocol !=
        IPPROTO_TCP) {
        return;
    }


    /* TCP Header 최소 크기 확인 */
    if (header->caplen <
        (bpf_u_int32)
        (ETHER_HDR_LEN +
         ip_header_len +
         20)) {
        return;
    }


    /* 3. TCP Header 시작 위치 */
    const struct tcpheader *tcp =
        (const struct tcpheader *)
        (packet +
         ETHER_HDR_LEN +
         ip_header_len);


    /* 실제 TCP Header 길이 계산 */
    int tcp_header_len =
        tcp->tcp_offset * 4;


    /* TCP Header 최소 길이 확인 */
    if (tcp_header_len < 20) {
        return;
    }


    /* 전체 Header 길이 */
    int headers_len =
        ETHER_HDR_LEN +
        ip_header_len +
        tcp_header_len;


    /* 실제 캡처 길이가 Header 전체보다 짧으면 종료 */
    if (header->caplen <
        (bpf_u_int32)headers_len) {
        return;
    }


    /* IP Packet 전체 길이 */
    int ip_total_len =
        ntohs(ip->iph_len);


    /* 길이 값이 비정상적인 경우 */
    if (ip_total_len <
        ip_header_len +
        tcp_header_len) {
        return;
    }


    /* TCP Payload 길이 계산 */
    int payload_len =
        ip_total_len -
        ip_header_len -
        tcp_header_len;


    /* 실제 캡처된 Payload 길이 */
    int captured_payload_len =
        (int)header->caplen -
        headers_len;


    /* 캡처된 범위를 넘어서 읽지 않도록 제한 */
    if (payload_len >
        captured_payload_len) {
        payload_len =
            captured_payload_len;
    }


    /* 음수 방지 */
    if (payload_len < 0) {
        payload_len = 0;
    }


    /* Application Data 시작 위치 */
    const u_char *payload =
        packet + headers_len;


    /* Source / Destination Port */
    unsigned int src_port =
        ntohs(tcp->tcp_sport);

    unsigned int dst_port =
        ntohs(tcp->tcp_dport);


    /* IP 문자열 저장 공간 */
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];


    /* Source IP 변환 */
    if (inet_ntop(
            AF_INET,
            &ip->iph_sourceip,
            src_ip,
            sizeof(src_ip)
        ) == NULL) {
        return;
    }


    /* Destination IP 변환 */
    if (inet_ntop(
            AF_INET,
            &ip->iph_destip,
            dst_ip,
            sizeof(dst_ip)
        ) == NULL) {
        return;
    }


    printf("\n");
    printf("================ PACKET ================\n");


    printf("[Ethernet Header]\n");

    printf("Src MAC : ");
    print_mac(eth->ether_shost);
    printf("\n");

    printf("Dst MAC : ");
    print_mac(eth->ether_dhost);
    printf("\n");


    printf("[IP Header]\n");

    printf("Src IP  : %s\n",
           src_ip);

    printf("Dst IP  : %s\n",
           dst_ip);

    printf("IP Header Length : %d bytes\n",
           ip_header_len);


    printf("[TCP Header]\n");

    printf("Src Port : %u\n",
           src_port);

    printf("Dst Port : %u\n",
           dst_port);

    printf("TCP Header Length : %d bytes\n",
           tcp_header_len);

    printf("Payload Length : %d bytes\n",
           payload_len);


    /*
     * HTTP 기본 포트 80과 관련된 TCP 패킷 중
     * 실제 Payload가 존재하면 Message 출력
     */
    if (payload_len > 0 &&
        (src_port == 80 ||
         dst_port == 80)) {

        print_http_message(
            payload,
            payload_len);

    } else {

        printf("[HTTP Message]\n");
        printf("No HTTP payload "
               "in this TCP packet.\n");
    }


    printf("========================================\n");
}


int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];


    /* 인터페이스 이름을 입력했는지 확인 */
    if (argc != 2) {
        printf(
            "사용법: sudo %s <인터페이스>\n",
            argv[0]
        );

        return 1;
    }


    /* 실시간 패킷 캡처 시작 */
    pcap_t *handle =
        pcap_open_live(
            argv[1],
            BUFSIZ,
            1,
            1000,
            errbuf
        );


    /* 캡처 시작 실패 */
    if (handle == NULL) {
        printf(
            "패킷 캡처 시작 실패: %s\n",
            errbuf
        );

        return 1;
    }


    printf(
        "패킷 캡처 시작: %s\n",
        argv[1]
    );


    /* 패킷이 잡힐 때마다 got_packet 실행 */
    pcap_loop(
        handle,
        -1,
        got_packet,
        NULL
    );


    /* 캡처 종료 */
    pcap_close(handle);


    return 0;
}
