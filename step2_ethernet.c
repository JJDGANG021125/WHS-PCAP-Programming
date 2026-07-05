#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

#define ETHER_ADDR_LEN 6

struct ethheader {
    uint8_t ether_dhost[ETHER_ADDR_LEN];
    uint8_t ether_shost[ETHER_ADDR_LEN];
    uint16_t ether_type;
} __attribute__((packed));

void print_mac(const uint8_t mac[ETHER_ADDR_LEN]) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct ethheader *eth;

    if (header->caplen < sizeof(struct ethheader)) {
        return;
    }

    eth = (const struct ethheader *)packet;

    printf("\n================ PACKET ================\n");
    printf("Src MAC : ");
    print_mac(eth->ether_shost);
    printf("\n");
    printf("Dst MAC : ");
    print_mac(eth->ether_dhost);
    printf("\n");
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
