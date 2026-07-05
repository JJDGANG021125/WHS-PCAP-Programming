#include <pcap.h>
#include <stdio.h>

void got_packet(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
) {
    printf("패킷 캡처 성공! 길이: %u bytes\n",
           header->caplen);
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
