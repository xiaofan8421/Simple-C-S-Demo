/* header file corresponding to this c/cpp file first */
#include "pkt_dump.h"

/* system headers */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/time.h> // for gettimeofday
#include <unistd.h>
#include <stdbool.h>

/* third party headers */



/*-----------------------------------------------------------------------------
* constants and structures
*/
#define TCPDUMP_MAGIC   0xa1b2c3d4
#define MAX_CAP_LEN     65535

/*
 * Pkt header format from libpcap
 */
struct em_pcap_timeval {
    uint32_t tv_sec;       /* seconds */
    uint32_t tv_usec;      /* microseconds */
};

struct em_pcap_sf_pkthdr {
    struct em_pcap_timeval ts; /* timestamp */
    uint32_t caplen;     /* length of portion present */
    uint32_t len;        /* length this packet (off wire) */
};

int get_pkt_header_length()
{
    struct em_pcap_sf_pkthdr h;
    return sizeof(h);
}

// 24B
int write_pcap_file_header_to_buffer(uint8_t* buffer, int linktype, int thiszone, int snaplen)
{
    if (NULL == buffer) {
        return -1;
    }

    struct pcap_file_header hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic = TCPDUMP_MAGIC;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;

    hdr.thiszone = thiszone;
    hdr.snaplen = snaplen;
    hdr.sigfigs = 0;
    hdr.linktype = linktype;

    memcpy(buffer, (char *)&hdr, sizeof(hdr));
    return sizeof(hdr);
}

// 16B
int write_pkt_header_to_buffer(uint8_t* buffer, struct timeval ts, uint32_t caplen, uint32_t pktlen)
{
    struct em_pcap_sf_pkthdr h;
    h.ts.tv_sec = ts.tv_sec;
    h.ts.tv_usec = ts.tv_usec;
    h.caplen = caplen;
    h.len = pktlen;
    memcpy(buffer, (char*)&h, sizeof(h));
    return sizeof(h);
}

static int __write_header(FILE *fp, int linktype, int thiszone, int snaplen)
{
    struct pcap_file_header hdr;

    hdr.magic = TCPDUMP_MAGIC;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;

    hdr.thiszone = thiszone;
    hdr.snaplen = snaplen;
    hdr.sigfigs = 0;
    hdr.linktype = linktype;

    if (1 != fwrite((char *)&hdr, sizeof(hdr), 1, fp)) {
        printf("fwrite header failed! \n");
        return -1;
    }

    return 0;
}

int pkt_dump_pcap(pkt_context_t *pctx, const char *name)
{
    static bool g_first_flag = true;
    int ret = 0;
    register FILE *fp = NULL;
    int linktype = 1; //数据链路层为以太网类型。
    int thiszone = 0; //区域时间，实际该值未使用，填0。
    int snaplen = 65535; //所抓数据包的最大长度，这里设置为最大。
    struct pcap_pkthdr h;
    struct timeval ts;

    fp = fopen(name, "ab+");
    setbuf(fp, NULL);
    if (NULL == fp) {
        printf("%s fopen failed! \n", name);
        return -1;
    }

    if(g_first_flag) {
        if (0 != __write_header(fp, linktype, thiszone, snaplen)) {
            return -1;
        }
        g_first_flag = false;
    }

    gettimeofday(&ts, NULL);
#if 1
    h.ts.tv_sec = ts.tv_sec;
    h.ts.tv_usec = ts.tv_usec;
    h.caplen = pctx->pkt_len;
    h.len = pctx->pkt_len;
    printf("caplen=%d \n", h.caplen);
    pcap_dump((u_char *)fp, &h, (char *)pctx->pkt);

#else
    struct pcap_sf_pkthdr sf_hdr;
    sf_hdr.ts.tv_sec = ts.tv_sec;
    sf_hdr.ts.tv_usec = ts.tv_usec;
    sf_hdr.caplen = pctx->pkt_len;
    sf_hdr.len = pctx->pkt_len;
    ret = fwrite(&sf_hdr, sizeof(sf_hdr), 1, fp);
    printf("sf_hdr:ret=%d \n", ret);
    fwrite((char*)pctx->pkt, pctx->pkt_len, 1, fp);
    printf("payload:ret=%d \n", ret);
#endif

    fflush(fp);
    fclose(fp);

    return 0;
}
