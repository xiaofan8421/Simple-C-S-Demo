#ifndef __PKT_DUMP_H__
#define __PKT_DUMP_H__

#include <stdint.h>
#include <sys/time.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct tag_pkt_context {
    uint8_t *pkt; //原始包起始地址
    uint16_t pkt_len; // 数据包长度
    uint64_t timestamp; //
}pkt_context_t;


int get_pkt_header_length();
int write_pcap_file_header_to_buffer(uint8_t* buffer, int linktype, int thiszone, int snaplen);
int write_pkt_header_to_buffer(uint8_t* buffer, struct timeval ts, uint32_t caplen, uint32_t pktlen);

// 生成.pcap文件：pkt为待写入的包地址指针，name指定写入文件名。
int pkt_dump_pcap(pkt_context_t *pctx, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* __PKT_DUMP_H__ */
