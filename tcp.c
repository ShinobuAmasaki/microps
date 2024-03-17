#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "platform.h"

#include "util.h"
#include "ip.h"
#include "tcp.h"

// TCPヘッダのフラグフィールドの値
#define TCP_FLG_FIN 0x01
#define TCP_FLG_SYN 0x02
#define TCP_FLG_RST 0x04
#define TCP_FLG_PSH 0x08
#define TCP_FLG_ACK 0x10
#define TCP_FLG_URG 0x20

#define TCP_FLG_IS(x, y) ((x & 0x3f) == (y))
#define TCP_FLG_ISSET(x, y) ((x & 0x3f) & (y) ? 1: 0)

#define TCP_PCB_SIZE 16

#define TCP_PCB_STATE_FREE          0
#define TCP_PCB_STATE_CLOSED        1
#define TCP_PCB_STATE_LISTEN        2
#define TCP_PCB_STATE_SYN_SENT      3
#define TCP_PCB_STATE_SYN_RECEIVED  4
#define TCP_PCB_STATE_ESTABLISHED   5
#define TCP_PCB_STATE_FIN_WAIT1     6
#define TCP_PCB_STATE_FIN_WAIT2     7
#define TCP_PCB_STATE_CLOSING       8
#define TCP_PCB_STATE_TIME_WAIT     9
#define TCP_PCB_STATE_CLOSE_WAIT   10
#define TCP_PCB_STATE_LAST_ACK     11

// 疑似ヘッダの構造体
struct pseudo_hdr {
   uint32_t src;
   uint32_t dst;
   uint8_t zero;
   uint8_t protocol;
   uint16_t len;
};

// TCPヘッダの構造体
struct tcp_hdr {
   uint16_t src;
   uint16_t dst;
   uint32_t seq;
   uint32_t ack;
   uint8_t off;
   uint8_t flg;
   uint16_t wnd;
   uint16_t sum;
   uint16_t up;
};

// 受信したTCPセグメントから重要な情報を抽出したもの（RFCの記述に合わせてある）
struct tcp_segment_info {
   uint32_t seq;  //シーケンス番号
   uint32_t ack;  //確認応答番号
   uint16_t len;  //シーケンス番号を消費するデータ長（SYNとFINフラグも1カウントする）
   uint16_t wnd;  //受信ウィンドウ（相手の受信バッファの空き状況）
   uint16_t up;   //緊急ポインタ（今のところ使用しない）
};

struct tcp_pcb {
   int state; // コネクションの状態
   struct ip_endpoint local;  // コネクションの両端のアドレス情報
   struct ip_endpoint foreign;
   struct { //送信時に必要となる情報
      uint32_t nxt;  //次に送信するシーケンス番号
      uint32_t una;  //ACKが返ってきていない最後のシーケンス番号
      uint16_t wnd;  //相手の受信ウィンドウ（受信バッファの空き状態）
      uint16_t up;   //緊急ポインタ（未使用）
      uint32_t wl1;  //snd.wndを更新したときの受信セグメントのシーケンス番号
      uint32_t wl2;  //snd.wndを更新したときの受信セグメントのACK番号
   } snd;
   uint32_t iss;  //自分の初期シーケンス番号
   struct { //受信時に必要となる情報
      uint32_t nxt;  //次に受信を期待するシーケンス番号（ACKで使われる）
      uint16_t wnd;  //自分の受信ウィンドウ（受信バッファの空き状態）
      uint16_t up;   //緊急ポインタ（未使用）
   } rcv;
   uint32_t irs;  //相手の初期シーケンス番号
   uint16_t mtu;  //送信デバイスのMTU
   uint16_t mss;  //最大セグメントサイズ
   uint8_t buf[65535]; /* receive buffer */
   struct sched_ctx ctx;
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct tcp_pcb pcbs[TCP_PCB_SIZE];

static char *
tcp_flg_ntoa(uint8_t flg)
{
   static char str[9];

   snprintf(str, sizeof(str), "--%c%c%c%c%c%c",
      TCP_FLG_ISSET(flg, TCP_FLG_URG) ? 'U' : '-',
      TCP_FLG_ISSET(flg, TCP_FLG_ACK) ? 'A' : '-',
      TCP_FLG_ISSET(flg, TCP_FLG_PSH) ? 'P' : '-',
      TCP_FLG_ISSET(flg, TCP_FLG_RST) ? 'R' : '-',
      TCP_FLG_ISSET(flg, TCP_FLG_SYN) ? 'S' : '-',
      TCP_FLG_ISSET(flg, TCP_FLG_FIN) ? 'F' : '-');
   return str;
}

static void
tcp_dump(const uint8_t *data, size_t len)
{
   struct tcp_hdr *hdr;

   flockfile(stderr);
   hdr = (struct tcp_hdr *)data;
   fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
   fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
   fprintf(stderr, "        seq: %u\n", ntoh32(hdr->seq));
   fprintf(stderr, "        ack: %u\n", ntoh32(hdr->ack));
   fprintf(stderr, "        off: 0x%02x (%d)\n", hdr->off, (hdr->off >> 4) << 2);
   fprintf(stderr, "        flg: 0x%02x (%s)\n", hdr->flg, tcp_flg_ntoa(hdr->flg));
   fprintf(stderr, "        wnd: %u\n", ntoh16(hdr->sum));
   fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
   fprintf(stderr, "         up: %u\n", ntoh16(hdr->up));
#ifdef HEXDUMP
   hexdump(stderr, data, len);
#endif
   funlockfile(stderr);
}


/*
 * TCP Protocol Control Block (PCB)
 * 
 * NOTE: TCP PCB functions must be called after mutex locked
 */

static struct tcp_pcb *
tcp_pcb_alloc(void)
{
   struct tcp_pcb *pcb;

   for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
      if (pcb->state == TCP_PCB_STATE_FREE) {
         pcb->state = TCP_PCB_STATE_CLOSED;  // FREE状態のPCBを見つけて返す(CLOSED状態に初期化する)
         sched_ctx_init(&pcb->ctx);
         return pcb;
      }
   }
   return NULL;
}

static void
tcp_pcb_release(struct tcp_pcb *pcb)
{
   char ep1[IP_ENDPOINT_STR_LEN];
   char ep2[IP_ENDPOINT_STR_LEN];

   if (sched_ctx_destroy(&pcb->ctx) == -1) {
      sched_wakeup(&pcb->ctx); // PCBを利用しているタスクがいたらこのタイミングでは解放できない
         //タスクを起床させる（他のタスクに解放を任せる）
      return;
   }
   debugf("released, local=%s, foreign=s", 
      ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)),
      ip_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));
   memset(pcb, 0, sizeof(*pcb)); /* pcb->state is set to TCP_PCB_STATE_FREE (0) */
}

static struct tcp_pcb *
tcp_pcb_select(struct ip_endpoint *local, struct ip_endpoint *foreign)
{
   struct tcp_pcb *pcb, *listen_pcb = NULL;
   for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
      if ((pcb->local.addr == IP_ADDR_ANY || pcb->local.addr == local->addr) && pcb->local.port == local->port) {
         if (!foreign) { // ローカルアドレスにbind可能かどうか調べるときは外部アドレスを指定せずに呼ばれる
            return pcb;  // ローカルアドレスがマッチしているので返す
         }
         if (pcb->foreign.addr == foreign->addr && pcb->foreign.port == foreign->port) {
            // ローカルアドレスと外部アドレスが共にマッチ
            return pcb;
         }
         if (pcb->state == TCP_PCB_STATE_LISTEN) {
            //外部アドレスを指定せずにLISTENしていたらどんな外部アドレスにもマッチする
            if (pcb->foreign.addr == IP_ADDR_ANY && pcb->foreign.port == 0) {
               //ローカルアドレス/外部アドレス共にマッチしたものが優先されるのですぐには返さない
               /* LISTENed with wildcard foreign address/port */
               listen_pcb = pcb;
            }
         }
      }
   }
   return listen_pcb;
} 

static struct tcp_pcb *
tcp_pcb_get(int id)
{
   struct tcp_pcb *pcb;

   if (id < 0 || id >= (int)countof(pcbs)) {
      /* out of range */
      return NULL;
   }
   pcb =&pcbs[id];
   if (pcb->state == TCP_PCB_STATE_FREE) {
      return NULL;
   }
   return pcb;
}

static int
tcp_pcb_id(struct tcp_pcb *pcb)
{
   return indexof(pcbs, pcb);
}

static ssize_t
tcp_output_segment(uint32_t seq, uint32_t ack, uint8_t flg, uint16_t wnd, uint8_t *data, size_t len, struct ip_endpoint *local, struct ip_endpoint *foreign)
{
   uint8_t buf[IP_PAYLOAD_SIZE_MAX] = {};
   struct tcp_hdr *hdr;
   struct pseudo_hdr pseudo;
   uint16_t psum;
   uint16_t total;
   char ep1[IP_ENDPOINT_STR_LEN];
   char ep2[IP_ENDPOINT_STR_LEN];

   hdr = (struct tcp_hdr *) buf;

   /* Exercise 23-1: TCPセグメントの生成 */
   hdr->src = local->port;
   hdr->dst = foreign->port;
   hdr->seq = hton32(seq);
   hdr->ack = hton32(ack);
   hdr->off = (sizeof(*hdr) >> 2)<< 4;
   hdr->flg = flg;
   hdr->wnd = hton16(wnd);
   hdr->sum = 0;
   hdr->up = 0;
   memcpy(hdr+1, data, len);
   pseudo.src = local->addr;
   pseudo.dst = foreign->addr;
   pseudo.zero = 0;
   pseudo.protocol = IP_PROTOCOL_TCP;
   total = sizeof(*hdr) + len;
   pseudo.len = hton16(total);
   psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
   hdr->sum = cksum16((uint16_t *)hdr, total, psum);
   
   // Exercise ここまで

   debugf("%s => %s, len=%zu (payload=%zu)", 
      ip_endpoint_ntop(local, ep1, sizeof(ep1)),
      ip_endpoint_ntop(foreign, ep2, sizeof(ep2)),
      total, len);
   tcp_dump((uint8_t *)hdr, total);

   /* Exercise 23-2: IPの送信関数を呼び出す */
   if (ip_output(IP_PROTOCOL_TCP, (uint8_t *)hdr, total, local->addr, foreign->addr) == -1) {
      return -1;
   }
   // Exerciseここまで
   return len;
}

static ssize_t
tcp_output(struct tcp_pcb *pcb, uint8_t flg, uint8_t *data, size_t len)
{
   uint32_t seq;

   seq = pcb->snd.nxt;
   if (TCP_FLG_ISSET(flg, TCP_FLG_SYN)) {
      seq = pcb->iss; // SYNフラグが指定されるのは初回送信時なのでiss(初期送信シーケンス番号)をつかう
   }
   if (TCP_FLG_ISSET(flg, TCP_FLG_SYN | TCP_FLG_FIN) || len) {
      /* TODO: add retransmission queue*/
   }
   return tcp_output_segment(seq, pcb->rcv.nxt, flg, pcb->rcv.wnd, data, len, &pcb->local, &pcb->foreign);// PCBの情報を使ってTCPセグメントを送信する
}

/* rfc793 - section 3.9 [Event Processing > SEGMENT ARRIVES] */
static void
tcp_segment_arrives(struct tcp_segment_info *seg, uint8_t flags, uint8_t *data, size_t len, struct ip_endpoint *local, struct ip_endpoint *foreign)
{
   struct tcp_pcb *pcb;

   pcb = tcp_pcb_select(local, foreign);
   if (!pcb || pcb->state == TCP_PCB_STATE_CLOSED) { // 使用していないポート宛に届いたTCPセグメントの処理
      if (TCP_FLG_ISSET(flags, TCP_FLG_RST)) {
         return; // RSTフラグを含むセグメントは無視
      }
      // ACKフラグを含まないでセグメントを受信する（こちらからは何も送信していないと思われる状況（なにか送っていればACKを含んだセグメントを受信するはず）
      if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
         tcp_output_segment(0, seg->seq + seg->len, TCP_FLG_RST | TCP_FLG_ACK, 0, NULL, 0, local, foreign);
            // 相手が送ってきたデータへのACK番号（seg->seq + seg->len）を設定してRSTを送信する
      } else { //ACKフラグを含むセグメントを受信 - こちらから何か送信していると思われる状況（何か送っているのでACKを含んだセグメントを受信している）
            //以前に存在していたコネクションのセグメントが遅れて到着？
         tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
            //相手から伝えられたACK番号（相手が次に欲しがっているシーケンス番号）をシーケンス版後うに設定してRSTを送信する
      }
      return;
   }
   /* implemented in the next step */
}

static void
tcp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
   struct tcp_hdr *hdr;
   struct pseudo_hdr pseudo;
   uint16_t psum;
   char addr1[IP_ADDR_STR_LEN];
   char addr2[IP_ADDR_STR_LEN];
   struct ip_endpoint local, foreign;
   uint16_t hlen;
   struct tcp_segment_info seg;

   if (len < sizeof(*hdr)) {
      errorf("too short");
      return;
   }
   hdr = (struct tcp_hdr *) data;
   /* Exercise 22-3: チェックサムの検証*/


   pseudo.src = src;
   pseudo.dst = dst;
   pseudo.zero = 0;
   pseudo.protocol = IP_PROTOCOL_TCP;
   pseudo.len = hton16(len);

   psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
   if (cksum16((uint16_t *)hdr, len, psum) != 0) {
      errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
      return;
   }
   /* Exercise 22-4: アドレスのチェック*/
   if (hdr->src == IP_ADDR_BROADCAST || hdr->dst == IP_ADDR_BROADCAST) {
      errorf("broadcast address error");
      return;
   }

   /* Exercisesここまで*/
   debugf("%s:%d => %s:%d, len=%zu, (payload=%zu)",
      ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
      ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
      len, len - sizeof(*hdr));
   tcp_dump(data, len);

   // struct ip_endpointの変数に入れ直す
   local.addr = dst;
   local.port = hdr->dst;
   foreign.addr = src;
   foreign.port = hdr->src;

   //tcp_segment_arrives()で必要な情報（SEG.XXX）を集める
   hlen = (hdr->off >> 4) << 2;
   seg.seq = ntoh32(hdr->seq);
   seg.ack = ntoh32(hdr->ack);
   seg.len = len - hlen;
   if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN)) {
      seg.len++; /* SYN flag consumes one sequence number */
   }
   if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN)) {
      seg.len++; /* FIN flag consumes one sequence number */
   }
   seg.wnd = ntoh16(hdr->wnd);
   seg.up = ntoh16(hdr->up);

   mutex_lock(&mutex);
   tcp_segment_arrives(&seg, hdr->flg, (uint8_t *)hdr + hlen, len - hlen, &local, &foreign);
   mutex_unlock(&mutex);
   return;
}

int
tcp_init(void)
{
   // Exercise 22-1: IPの上位プロトコルとしてTCPを登録する
   if (ip_protocol_register(IP_PROTOCOL_TCP, tcp_input) == -1) {
      errorf("ip_protocol_register() failure");
      return -1;
   }
   return 0;
}