#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"

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

const ip_addr_t IP_ADDR_ANY       = 0x00000000; /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; /* 255.255.255.255 */


/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex. */
static struct ip_iface *ifaces;

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

static void
ip_input(const uint8_t*data, size_t len, struct net_device*dev)
{
   struct ip_hdr *hdr;
   uint8_t v;
   uint16_t hlen, total, offset;
   struct ip_iface *iface;
   char addr[IP_ADDR_STR_LEN];

   if (len < IP_HDR_SIZE_MIN) {
      errorf("too short");
      return;
   }
   hdr = (struct ip_hdr *)data; // 入力データをIPヘッダ構造体のポインタへキャストする。

   /* Exercise 6-1 IPデータグラムの検証 */

   // バージョンのチェック
   v = (hdr->vhl & 0xf0) >> 4;
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
      if (hdr->dst != 0xffffffff && hdr->dst != iface->broadcast) {
        return;
      }
   }
   // Exerciseここまで

   debugf("dev=%s, iface=%s, protocol=%u, total=%u",
       dev->name, ip_addr_ntop(iface->unicast, addr, sizeof(addr)), hdr->protocol, total);
   ip_dump(data, total);
   
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