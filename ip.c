#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"
#include "arp.h"

struct ip_hdr {
   uint8_t vhl; // バージョンとIPヘッダ長をまとめて8ビットとして扱う
   uint8_t tos;
   uint16_t total;
   uint16_t id;
   uint16_t offset; // フラグ（3ビット）とフラグメントオフセット（13ビット）をまとめて16ビットとして扱う
   uint8_t ttl;
   uint8_t protocol;
   uint16_t sum;
   ip_addr_t src; // IPアドレスにはip_addr_tを使う
   ip_addr_t dst;
   uint8_t options[]; // オプションは可変長なのでフレキシブル配列メンバとする。
};

//　IPの上位プロトコルを管理するための構造体
struct ip_protocol {
   struct ip_protocol *next;
   uint8_t type;
   void (*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface);
};

const ip_addr_t IP_ADDR_ANY       = 0x00000000; /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; /* 255.255.255.255 */


/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex. */
static struct ip_iface *ifaces;
static struct ip_protocol *protocols;

// Printable text TO Network binary
int
ip_addr_pton(const char *p, ip_addr_t *n)
{
   // IPアドレスを文字列からネットワークバイトオーダーのバイナリ値（ip_addr_t）に変換する
   char *sp, *ep;
   int idx;
   long ret;

   sp = (char *)p;
   for (idx = 0; idx < 4; idx++) {
      ret = strtol(sp, &ep, 10);
      if (ret < 0 || ret > 255) {
         return -1;
      }
      if (ep == sp) {
         return -1;
      }
      if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.')) {
         return -1;
      }
      ((uint8_t *)n)[idx] = ret;
      sp = ep + 1;
   } 
   return 0;
}

// Network binary TO Printable text
char *
ip_addr_ntop(ip_addr_t n, char *p, size_t size)
{
   // IPアドレスをネットワークバイトオーダーのバイナリ値（ip_addr_t）から文字列に変換する
   uint8_t *u8;
   u8 = (uint8_t *)&n;
   snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);
   return p;
}

static void
ip_dump(const uint8_t *data, size_t len)
{
   struct ip_hdr *hdr;
   uint8_t v, hl, hlen;
   uint16_t total, offset;
   char addr[IP_ADDR_STR_LEN];

   flockfile(stderr);
   hdr = (struct ip_hdr *) data;
   v = (hdr->vhl & 0xf0) >> 4;  // 上位4ビット=バージョン
   hl = hdr->vhl & 0x0f;  // 下位4ビット=IPヘッダ長
   hlen = hl << 2;   // IPヘッダ長は32ビット単位の値が格納されているので、4倍して8ビット単位の値にする。
   fprintf(stderr, "        vhl: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->vhl, v, hl, hlen);
   fprintf(stderr, "        tos: 0x%02x\n", hdr->tos);
   total = ntoh16(hdr->total); // バイトオーダーの変換
   fprintf(stderr, "      total: %u (payload: %u)\n", total, total - hlen); // トータル長からIPヘッダ長を引いたものがペイロードの長さ
   fprintf(stderr, "         id: %u\n", ntoh16(hdr->id));
   offset = ntoh16(hdr->offset);
   fprintf(stderr, "     offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xe000) >> 13, offset & 0x1fff); 
      // offsetは、上位3ビットがフラグで、下位13ビットがフラグメントオフセット
   fprintf(stderr, "        ttl: %u\n", hdr->ttl);
   fprintf(stderr, "   protocol: %u\n", hdr->protocol);
   fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
   fprintf(stderr, "        src: %s\n", ip_addr_ntop(hdr->src, addr, sizeof(addr)));
   fprintf(stderr, "        dst: %s\n", ip_addr_ntop(hdr->dst, addr, sizeof(addr)));
      // IPアドレスをネットワークバイトオーダーのバイナリ値から文字列に変換する
#ifdef HEXDUMP
   hexdump(stderr, data, len);
#endif
   funlockfile(stderr);
}

struct ip_iface*
ip_iface_alloc(const char *unicast, const char *netmask)
{
   struct ip_iface *iface;

   iface = memory_alloc(sizeof(*iface));
   if (!iface) {
      errorf("memory_alloc() failure");
      return NULL;
   }
   NET_IFACE(iface)->family = NET_IFACE_FAMILY_IP;

   /* Exercise 7-3: IPインタフェースにアドレス情報を設定する*/
   // ifaces->unicast
   if (ip_addr_pton(unicast, &iface->unicast) == -1) {
      errorf("ip_addr_pton() failure: address=%s", unicast);
      free(iface);
      return NULL;
   }
   
   // ifaces->netmask
   if (ip_addr_pton(netmask, &iface->netmask) == -1) {
      errorf("ip_addr_pton() failure: address=%s", netmask);
      free(iface);
      return NULL;
   }

   // iface->broadcast
   iface->broadcast = (iface->unicast & iface->netmask) | ~iface->netmask;

   return iface;
}

/* NOTE: must not be call after net_run()*/
int
ip_iface_register(struct net_device *dev, struct ip_iface *iface)
{
   char addr1[IP_ADDR_STR_LEN];
   char addr2[IP_ADDR_STR_LEN];
   char addr3[IP_ADDR_STR_LEN];
   
   /* Exercise 7-4: IPインタフェースの登録*/
   // デバイスにIPインタフェースを登録する（エラーが返されたらこの関数もエラーを返す）
   if (net_device_add_iface(dev, &iface->iface)== -1) {
      errorf("net_device_add_iface() failure: dev=%s", dev);
      return -1;
   }
   // IPインタフェースのリスト（ifaces）の先頭にifaceを挿入する
   iface->next = ifaces;
   ifaces = iface;

   // Exerciseここまで

   infof("registered: dev=%s, unicast=%s, netmask=%s, broadcast=%s", dev->name,
      ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)),
      ip_addr_ntop(iface->netmask, addr2, sizeof(addr2)),
      ip_addr_ntop(iface->broadcast, addr3, sizeof(addr3)));
   return 0;

}

struct ip_iface *
ip_iface_select(ip_addr_t addr)
{
   /* Exercise 7-5: IPインタフェースの検索*/
   struct ip_iface *entry;
   for (entry = ifaces; entry; entry = entry->next) {
      if (entry->unicast == addr) {
         return entry;
      }
   }
   return NULL; 

   // Exerciseここまで
}

/* Note: must not be call after net_run() */
int
ip_protocol_register(uint8_t type, void (*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface))
{
   struct ip_protocol *entry;

   /* Exercise 9-1: 重複登録の確認*/
   for (entry = protocols; entry; entry = entry->next) {
      if (type == entry->type) {
         errorf("already exist protocol, type=%u", type);
         return -1;
      }
   }

   /* Exercise 9-2: プロトコルの登録*/
   entry = memory_alloc(sizeof(*entry));
   if (!entry) {
      errorf("memory_alloc() failure");
      return -1;
   }

   entry->type = type;
   entry->handler = handler;
   entry->next = protocols;
   protocols = entry;

   // Exercise ここまで

   infof("registered, type=%u", entry->type);
   return 0;
}


static void
ip_input(const uint8_t*data, size_t len, struct net_device*dev)
{
   struct ip_hdr *hdr;
   uint8_t v;
   uint16_t hlen, total, offset;
   struct ip_iface *iface;
   char addr[IP_ADDR_STR_LEN];
   struct ip_protocol *proto;

   if (len < IP_HDR_SIZE_MIN) {
      errorf("too short");
      return;
   }
   hdr = (struct ip_hdr *)data; // 入力データをIPヘッダ構造体のポインタへキャストする。

   /* Exercise 6-1 IPデータグラムの検証 */

   // バージョンのチェック
   // v = (hdr->vhl & 0xf0) >> 4;
   v = hdr->vhl >> 4;
   if ( v != IP_VERSION_IPV4) {
      errorf("mismatched version");
      return;
   }

   // ヘッダ長のチェック（入力データの長さ（len)がヘッダ長よりも小さい場合は中断する）
   hlen = (hdr->vhl & 0x0f) << 2;
   if (len < hlen) {
      errorf("len is too small than hlen");
      return;
   }

   // トータル長のチェック（入力データの長さ（len）がトータル長よりも小さい場合は中断する）
   total = ntoh16(hdr->total);
   if (len < total) {
      errorf("len is too small than total");
      return;
   }

   // チェックサム
   if (cksum16((uint16_t *) hdr, hlen, 0) != 0) {
      // errorf("checksum unmatched");
      errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, hlen, -hdr->sum) ));
      return;
   }

   /* Exerciseここまで */

   offset = ntoh16(hdr->offset);
   if (offset & 0x2000 || offset & 0x1fff) {
      errorf("fragments does not support");
      return;
   }

   /* Exercise 7-6: IPデータグラムのフィルタリング */
   // デバイスに紐づくIPインタフェースを取得する。IPインタフェースを取得できなければ中断する
   // iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
   iface = (struct ip_iface *) net_device_get_iface(dev, NET_IFACE_FAMILY_IP); //正解できず
   if (!iface) {
      return;
   }
   // 宛先IPアドレスの検証
   if (hdr->dst != iface->unicast) {
      if (hdr->dst != IP_ADDR_BROADCAST && hdr->dst != iface->broadcast) {
         infof("hoge");
         return;
      }
   }
   // Exerciseここまで

   debugf("dev=%s, iface=%s, protocol=%u, total=%u",
       dev->name, ip_addr_ntop(iface->unicast, addr, sizeof(addr)), hdr->protocol, total);
   ip_dump(data, total);

   /* Exercise 9-3: プロトコルの検索 */
   for (proto = protocols; proto; proto = proto->next) {
      if (hdr->protocol == proto->type) {
         // proto->handler(hdr+1, len-hlen, hdr->src, hdr->dst, iface); // 間違い
         proto->handler((uint8_t *)hdr+hlen, total - hlen, hdr->src, hdr->dst, iface); // 正解
         return;
      }
   }
   /* unsupported protocol */
   
}

static int
ip_output_device(struct ip_iface *iface, const uint8_t *data, size_t len, ip_addr_t dst)
{
   uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};
   int ret;

   if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_ARP) {
      if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST) {
         memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast, NET_IFACE(iface)->dev->alen);
      } else {
         /*Exercise 14-5: arp_resolve()を呼び出してアドレスを解決する*/
         ret = arp_resolve(NET_IFACE(iface), dst, hwaddr);
         if (ret != ARP_RESOLVE_FOUND) {
            return ret; 
         }
      }
   }
   // Exercise 8-4: デバイスからの送信
   // return net_device_output(NET_IFACE(iface)->dev, NET_DEVICE_TYPE_LOOPBACK, data, len, &dst); // 間違い
   return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IP, data, len, &dst); // 正解
   // Exerciseここまで
}

static ssize_t
ip_output_core(struct ip_iface *iface, uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, uint16_t id, uint16_t offset)
{
   uint8_t buf[IP_TOTAL_SIZE_MAX];
   struct ip_hdr *hdr;
   uint16_t hlen, total;
   char addr[IP_ADDR_STR_LEN];

   hdr = (struct ip_hdr *)buf;

   /* Exercise 8-3: IPデータグラムの作成*/
   hlen = sizeof(*hdr);
   hdr->vhl = (IP_VERSION_IPV4<<4) | (hlen >> 2);
   hdr->tos = 0;

   // total = (hlen>>2) + len;
   total = hlen + len;
   hdr->total = hton16(total);
   
   hdr->id = hton16(id);
   hdr->offset = hton16(offset);
   hdr->ttl = 0xff;
   hdr->protocol = protocol;

   // チェックサム
   hdr->sum = 0;
   hdr->src = src;
   hdr->dst = dst;

   hdr->sum = cksum16((uint16_t *)hdr, hlen, 0); /* Do not convert byte order*/

   // memcpy(&buf[sizeof(hdr)], data, len);
   memcpy(hdr+1, data, len);

   /* Exerciseここまで*/

   debugf("dev=%s, dst=%s, protocol=%u, total=%u",
      NET_IFACE(iface)->dev->name, ip_addr_ntop(dst, addr, sizeof(addr)), protocol, total);
   ip_dump(buf, total);
   return ip_output_device(iface, buf, total, dst); // 生成したIPデータグラムを実際にデバイスから送信するための関数にわたす。

}

static uint16_t
ip_generate_id(void)
{
   static mutex_t mutex = MUTEX_INITIALIZER;
   static uint16_t id = 128;
   uint16_t ret;

   mutex_lock(&mutex);
   ret = id++;
   mutex_unlock(&mutex);
   return ret;
}

ssize_t
ip_output(uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
   struct ip_iface *iface;
   char addr[IP_ADDR_STR_LEN];
   uint16_t id;

   if (src == IP_ADDR_ANY) {
      errorf("ip routing does not implement");
      return -1;
         // まだIPルーティングを実装していないので送信元IPアドレスが指定されない場合はエラーを返す
   } else { /* NOTE: I'll rewrite this block later. */
      /*Exercise 8-1: IPインタフェースの検索する */
      iface = ip_iface_select(src);
      if (!iface) {
         errorf("ip_iface_select() failure");
         return -1;
      }
      /*Exercise 8-2: 宛先へ到達可能か確認する */
      // 宛先アドレスdstが条件に合致しない場合はエラーを返す（到達不能）
      if ((iface->unicast & iface->netmask) != (dst & iface->netmask)) {
         if (dst != IP_ADDR_BROADCAST) {
            errorf("unreachable dst=%s", ip_addr_ntop(dst, addr, sizeof(addr)));
            return -1;
         }
      }
   }

   // フラグメンテーションをサポートしないのでMTUを超える場合はエラーを返す
   if (NET_IFACE(iface)->dev->mtu < IP_HDR_SIZE_MIN+len ) {
      errorf("too long, dev=%s, mtu=%u < %zu", 
         NET_IFACE(iface)->dev->name, NET_IFACE(iface)->dev->mtu, IP_HDR_SIZE_MIN+len);
   }
   id = ip_generate_id(); // IPデータグラムのIDを採番する
   if (ip_output_core(iface, protocol, data, len, iface->unicast, dst, id, 0) == -1) {
      errorf("ip_output_core() failure");
      return -1;
   }

   return len;
}

int
ip_init(void)
{
   // プロトコルスタックにIPの入力関数を登録する
   if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1) {
      errorf("net_protocol_register() failure");
      return -1;
   }
   return 0;
}