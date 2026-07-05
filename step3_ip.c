#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

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


void print_mac(const uint8_t mac[ETHER_ADDR_LEN]) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}


void got_packet(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
) {
    (void)args;

    /* Ethernet Header가 존재하는지 확인 */
    if (header->caplen < sizeof(struct ethheader)) {
        return;
    }

    const struct ethheader *eth =
        (const struct ethheader *)packet;


    /* IPv4 패킷만 처리 */
    if (ntohs(eth->ether_type) != ETHERTYPE_IPV4) {
        return;
    }


    /* Ethernet 뒤에 IP Header가 존재하는지 확인 */
    if (header->caplen <
        ETHER_HDR_LEN + sizeof(struct ipheader)) {
        return;
    }


    /* packet + 14 위치를 IP Header로 해석 */
    const struct ipheader *ip =
        (const struct ipheader *)
        (packet + ETHER_HDR_LEN);


    /* 실제 IP Header 길이 계산 */
    int ip_header_len =
        ip->iph_ihl * 4;


    /* IPv4인지, 정상적인 Header 길이인지 확인 */
    if (ip->iph_ver != 4 ||
        ip_header_len < 20) {
        return;
    }


    /* 실제 캡처 길이가 IP Header 전체를 포함하는지 확인 */
    if (header->caplen <
        (bpf_u_int32)
        (ETHER_HDR_LEN + ip_header_len)) {
        return;
    }


    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];


    /* Source IP를 문자열로 변환 */
    if (inet_ntop(
            AF_INET,
            &ip->iph_sourceip,
            src_ip,
            sizeof(src_ip)
        ) == NULL) {
        return;
    }


    /* Destination IP를 문자열로 변환 */
    if (inet_ntop(
            AF_INET,
            &ip->iph_destip,
            dst_ip,
            sizeof(dst_ip)
        ) == NULL) {
        return;
    }


    printf("\n================ PACKET ================\n");


    printf("[Ethernet Header]\n");

    printf("Src MAC : ");
    print_mac(eth->ether_shost);
    printf("\n");

    printf("Dst MAC : ");
    print_mac(eth->ether_dhost);
    printf("\n");


    printf("[IP Header]\n");

    printf("Src IP  : %s\n", src_ip);
    printf("Dst IP  : %s\n", dst_ip);

    printf("IP Header Length : %d bytes\n",
           ip_header_len);


    printf("========================================\n");
}


int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];

    if (argc != 2) {
        printf("사용법: sudo %s <인터페이스>\n",
               argv[0]);
        return 1;
    }


    pcap_t *handle = pcap_open_live(
        argv[1],
        BUFSIZ,
        1,
        1000,
        errbuf
    );


    if (handle == NULL) {
        printf("패킷 캡처 시작 실패: %s\n",
               errbuf);
        return 1;
    }


    printf("패킷 캡처 시작: %s\n", argv[1]);


    pcap_loop(
        handle,
        -1,
        got_packet,
        NULL
    );


    pcap_close(handle);

    return 0;
}
