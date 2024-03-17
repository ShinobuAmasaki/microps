#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "platform.h"

#include "util.h"
#include "ip.h"
#include "udp.h"

#define UDP_PCB_SIZE 16

// コントロールブロックの状態を示す定数
#define UDP_PCB_STATE_FREE    0
#define UDP_PCB_STATE_OPEN    1
#define UDP_PCB_STATE_CLOSING 2

// 疑似ヘッダの構造体
struct pseudo_hdr {
   uint32_t src;
   uint32_t dst;
   uint8_t zero;
   uint8_t protocol;
   uint16_t len;
};

// UDPヘッダの構造体
struct udp_hdr {
   uint16_t src;
   uint16_t dst;
   uint16_t len;
   uint16_t sum;
};

// コントロールブロックの構造体
struct udp_pcb {
   int state;
   struct ip_endpoint local;
   struct queue_head queue;  /* receive queue */ 
};

// 受信キューのエントリの構造体
struct udp_queue_entry {
   struct ip_endpoint foreign; // 送信元のアドレス&ポート番号
   uint16_t len;
   uint8_t data[];
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct udp_pcb pcbs[UDP_PCB_SIZE]; // コントロールブロックの配列


static void
udp_dump(const uint8_t *data, size_t len)
{
   struct udp_hdr *hdr;

   flockfile(stderr);
   hdr = (struct udp_hdr *)data;
   fprintf(stderr, "       src: %u\n", ntoh16(hdr->src));
   fprintf(stderr, "       dst: %u\n", ntoh16(hdr->dst));
   fprintf(stderr, "       len: %u\n", ntoh16(hdr->len));
   fprintf(stderr, "       sum: 0x%04x\n", ntoh16(hdr->sum));
#ifdef HEXDUMP
   hexdump(stderr, data, len);
#endif
   funlockfile(stderr);
}

/*
 * UDP Protocol Control Block (PCB)
 * 
 * NOTE: UDP PCB functions must be called after mutex locked
 */

static struct udp_pcb *
udp_pcb_alloc(void)
{
   struct udp_pcb *pcb;

   // 使用されていないPCBを探して返す
   for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
      if (pcb->state == UDP_PCB_STATE_FREE) {
         pcb->state = UDP_PCB_STATE_OPEN;
         return pcb;
      }
   }
   return NULL; //空きがなければNULLを返す
}

static void
udp_pcb_release(struct udp_pcb *pcb)
{
   struct queue_entry *entry;

   // 値をクリアする
   pcb->state = UDP_PCB_STATE_FREE;
   pcb->local.addr = IP_ADDR_ANY;
   pcb->local.port = 0;

   // 受信キューを空にする
   while (1) { /* Discard the entries in the queue. */
      entry = queue_pop(&pcb->queue);
      if (!entry) {
         break;
      }
      memory_free(entry);
   }
}

static struct udp_pcb *
udp_pcb_select(ip_addr_t addr, uint16_t port)
{
   struct udp_pcb *pcb;

   for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
      if (pcb->state == UDP_PCB_STATE_OPEN) {
         // IPアドレスとポート番号が一致するPCBを探して返す
         if ((pcb->local.addr == IP_ADDR_ANY || addr == IP_ADDR_ANY || pcb->local.addr == addr) && pcb->local.port == port) {
              // IPアドレスがワイルドカード（IP_ADDR_ANY)の場合、すべてのアドレスに対して一致の判定を下す
            return pcb;
         }
      }
   }
   return NULL;
}

static struct udp_pcb *
udp_pcb_get(int id)
{
   struct udp_pcb *pcb;

   if (id < 0 || id >= (int)countof(pcbs)) {
      /* out of range */
      return NULL;
   }
   pcb = &pcbs[id];
   if (pcb->state != UDP_PCB_STATE_OPEN) {
      return NULL;
   }
   return pcb;
}

static int
udp_pcb_id(struct udp_pcb *pcb)
{
   return indexof(pcbs, pcb); // 配列のインデックスをidとして返す
}

static void
udp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
   struct pseudo_hdr pseudo;
   uint16_t psum = 0;
   struct udp_hdr *hdr;
   char addr1[IP_ADDR_STR_LEN];
   char addr2[IP_ADDR_STR_LEN];
   struct udp_pcb *pcb;
   struct udp_queue_entry *entry;

   if (len < sizeof(*hdr)) {
      errorf("too short");
      return;
   }

   hdr = (struct udp_hdr *)data;

   if (len != ntoh16(hdr->len)) { /* just to make sure*/
      errorf("length error: len=%zu, hdr->len=%u", len, ntoh16(hdr->len));
      return;
   }

   pseudo.src = src;
   pseudo.dst = dst;
   pseudo.zero = 0;
   pseudo.protocol = IP_PROTOCOL_UDP;
   pseudo.len = hton16(len);

   psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0); // 疑似ヘッダ部分のチェックサムを計算（計算結果はビット反転されているので戻しておく）
   if (cksum16((uint16_t *)hdr, len, psum) != 0) { // cksum16()の第3引数にpsumを渡すことで続きを計算できる
      errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
      return;
   }
   debugf("%s:%d => %s:%d, len=%zu (payload=%zu)", 
      ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
      ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
      len, len - sizeof(*hdr));
   udp_dump(data, len);

   mutex_lock(&mutex);
   pcb = udp_pcb_select(dst, hdr->dst); // 宛先アドレスとポート番号に対応するPCBを検索する
   if (!pcb) {
      /* port is not in use */
      mutex_unlock(&mutex);
      return;
   }

   /* Exercise 19-1: 受信キューへデータを格納する */
   // entry = memory_alloc(sizeof(*entry));
   entry = memory_alloc(sizeof(*entry)+ (len - sizeof(*hdr))); //　フレキシブル配列の部分も含めて確保する
   if (!entry) {
      errorf("memory_alloc() failure");
      mutex_unlock(&mutex);
      return;
   }

   entry->foreign.addr = src;
   entry->foreign.port = hdr->src;
   entry->len = len - sizeof(*hdr);
   memcpy(entry+1, hdr+1, entry->len); // フレキシブル配列のアドレスはentry+1とhdr+1となっている

   if (!queue_push(&pcb->queue, entry)) {
      errorf("queue_push failure");
      mutex_unlock(&mutex);
      return;
   }
   // Exerciseここまで

   debugf("queue pushed: id=%d, num=%d", udp_pcb_id(pcb), pcb->queue.num);
   mutex_unlock(&mutex);   
}

/*
 * UDP User Commands
 */

int
udp_open(void)
{
   struct udp_pcb *pcb;
   int id;

   mutex_lock(&mutex);

   pcb = udp_pcb_alloc();
   if (!pcb) {
      errorf("udp_pcb_alloc() failure");
      mutex_unlock(&mutex);
      return -1;
   }
   id = udp_pcb_id(pcb);
   mutex_unlock(&mutex);
   return id;
}

int
udp_close(int id)
{
   struct udp_pcb *pcb;

   mutex_lock(&mutex);
   pcb = udp_pcb_get(id);
   if (!pcb) {
      errorf("udp_pcb_get() failure: id=%d", id);
      mutex_unlock(&mutex);
      return -1;
   }
   udp_pcb_release(pcb);
   mutex_unlock(&mutex);
   return 0;

}

int
udp_bind(int id, struct ip_endpoint *local)
{
   struct udp_pcb *pcb, *exist;
   char ep1[IP_ENDPOINT_STR_LEN];
   char ep2[IP_ENDPOINT_STR_LEN];

   mutex_lock(&mutex);
   /* Exercise 19-4: UDPソケットへアドレスとポート番号を対応付ける*/
   // 1. IDからPCBのポインタを取得する
   pcb = udp_pcb_get(id);
   if (!pcb) {
      errorf("pcb not found: id=%d", id);
      mutex_unlock(&mutex);
      return -1;
   }
   exist = udp_pcb_select(local->addr, local->port);
   if (exist) {
      errorf("already in use, id=%d, want=%s, exist=%s",
         ip_endpoint_ntop(local, ep1, sizeof(ep1)), ip_endpoint_ntop(&exist->local, ep2, sizeof(ep2)));
      mutex_unlock(&mutex);
      return -1;
   }
   
   // pcb->local.addr = local.addr;
   // pcb->local.port = local.port;
   pcb->local = *local;

   // Exerciseここまで

   debugf("bound, id=%d, local=%s", id, ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)));
   mutex_unlock(&mutex);
   return 0;
}

ssize_t
udp_output(struct ip_endpoint *src, struct ip_endpoint *dst, const uint8_t *data, size_t len)
{
   uint8_t buf[IP_PAYLOAD_SIZE_MAX];
   struct udp_hdr *hdr;
   struct pseudo_hdr pseudo;
   uint16_t total, psum = 0;
   char ep1[IP_ENDPOINT_STR_LEN];
   char ep2[IP_ENDPOINT_STR_LEN];

   // IPのペイロードに乗せきれないほど大きなデータが渡されたらエラーを返す
   if (len > IP_PAYLOAD_SIZE_MAX - sizeof(*hdr)) {
      errorf("too long");
      return -1;
   }
   hdr = (struct udp_hdr *)buf;

   /* Exercise 18-1: UDPデータグラムの生成 */
   //hdr->src = hton16(src->port);
   hdr->src = src->port;
   // hdr->dst = hton16(src->port);
   hdr->dst = dst->port;
   total = len + sizeof(*hdr);
   hdr->len = hton16(total);
   hdr->sum = 0;
   memcpy(hdr+1, data, len);

   // pseudo.src = hton32(src->addr);
   pseudo.src = src->addr;
   // pseudo.dst = hton32(dst->addr);
   pseudo.dst = dst->addr;
   pseudo.zero = 0; 
   pseudo.protocol = IP_PROTOCOL_UDP;
   pseudo.len = hton16(total);
   

   psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
   // hdr->sum = cksum16((uint16_t *)hdr, len, psum);
   hdr->sum = cksum16((uint16_t *)hdr, total, psum);
   /* Exerciseここまで */

   debugf("%s => %s, len=%zu (payload=%zu)", 
      ip_endpoint_ntop(src, ep1, sizeof(ep1)), ip_endpoint_ntop(dst, ep2, sizeof(ep2)), total, len);
   udp_dump((uint8_t *)hdr, total);

   /* Exercise 18-2: IPの送信関数を呼び出す */
   if (ip_output(IP_PROTOCOL_UDP, (uint8_t*)hdr, total, src->addr, dst->addr) == -1) {
      errorf("ip_output() failure");
      return -1;
   }

   return len;

}

int
udp_init(void)
{
   /* Exercise 18-3: IPの上位プロトコルとしてUDPを登録する*/
   if(ip_protocol_register(IP_PROTOCOL_UDP, udp_input) == -1) {
      errorf("ip_protocol_register() failure");
      return -1;
   }

   return 0;
}