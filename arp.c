#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"

/* see https://www.iana.org/assignments/arp-parameters/arp-parameters.txt */
#define ARP_HRD_ETHER 0x0001
/* NOTE: use same value as the Ethernet types*/
#define ARP_PRO_IP ETHER_TYPE_IP

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

#define ARP_CACHE_SIZE 32
#define ARP_CACHE_TIMEOUT 30 /* seconds */

#define ARP_CACHE_STATE_FREE       0 
#define ARP_CACHE_STATE_INCOMPLETE 1
#define ARP_CACHE_STATE_RESOLVED   2
#define ARP_CACHE_STATE_STATIC     3

// ARPヘッダの構造体
struct arp_hdr {
   uint16_t hrd;  // Hardware Address Space
   uint16_t pro;  // Protocol Address Space
   uint8_t hln;   // Hardware Address Length
   uint8_t pln;   // Protocol Address Length
   uint16_t op;
};

// Ethenet/IPペアのためのARPメッセージ構造体（アラインメントに注意）
struct arp_ether_ip {
   struct arp_hdr hdr;
   uint8_t sha[ETHER_ADDR_LEN]; // 48bit
   uint8_t spa[IP_ADDR_LEN];    // 32bit
   uint8_t tha[ETHER_ADDR_LEN]; // 48bit
   uint8_t tpa[IP_ADDR_LEN];    // 32bit
};

struct arp_cache {
   unsigned char state;          // キャッシュの状態
   ip_addr_t pa;                 // プロトコルアドレス
   uint8_t ha[ETHER_ADDR_LEN];   // ハードウェアアドレス
   struct timeval timestamp;     // 最終更新時刻
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct arp_cache caches[ARP_CACHE_SIZE]; // ARPテーブル

static char *
arp_opcode_ntoa(uint16_t opcode)
{
   switch (ntoh16(opcode)) {
   case ARP_OP_REQUEST:
      return "Request";
   case ARP_OP_REPLY:
      return "Reply";
   }
   return "Unknown";
}

static void
arp_dump(const uint8_t *data, size_t len)
{
   struct arp_ether_ip *message;
   ip_addr_t spa, tpa;
   char addr[128];

   message = (struct arp_ether_ip *)data; // ここではEthenet/IPペアのメッセージとみなす
   flockfile(stderr);
   fprintf(stderr, "        hrd: 0x%04x\n", ntoh16(message->hdr.hrd));
   fprintf(stderr, "        pro: 0x%04x\n", ntoh16(message->hdr.pro));
   fprintf(stderr, "        hln: %u\n", message->hdr.hln);
   fprintf(stderr, "        pln: %u\n", message->hdr.pln);
   fprintf(stderr, "         op: %u (%s)\n", ntoh16(message->hdr.op), arp_opcode_ntoa(message->hdr.op));
   fprintf(stderr, "        sha: %s\n", ether_addr_ntop(message->sha, addr, sizeof(addr)));
   memcpy(&spa, message->spa, sizeof(spa)); // spaがuint8_t[4]なので一旦memcpy()でip_addr_tの変数へ取り出す。
   fprintf(stderr, "        spa: %s\n", ip_addr_ntop(spa, addr, sizeof(addr)));
   fprintf(stderr, "        tha: %s\n", ether_addr_ntop(message->tha, addr, sizeof(addr)));
   memcpy(&tpa, message->tpa, sizeof(tpa));
   fprintf(stderr, "        tpa: %s\n", ip_addr_ntop(tpa, addr, sizeof(addr)));
#ifdef HEXDUMP
   hexdump(stderr, data, len);
#endif
   funlockfile(stderr);

   // ハードウェアアドレス（sha/tha）はEthernetアドレス（MACアドレス）
   // プロトコルアドレス（spa/tpa）はIPアドレス

   /* 境界アクセスの制約が厳しいアーキテクチャだと *(ip_addr_t *)&message->spaとやると起こられる（32ビットデータは32ビット境界でアクセスする）
    * しかし、x86(x64も含む)は境界アクセスの制約が緩いので正常に動作する。
    */
}

/*
 * ARP Cache
 *
 * NOTE: ARP Cache functions must be called after mutex locked
 */
static void
arp_cache_delete(struct arp_cache *cache)
{
   char addr1[IP_ADDR_STR_LEN];
   char addr2[ETHER_ADDR_STR_LEN];

   debugf("DELETE: pa=%s, ha=%s", ip_addr_ntop(cache->pa, addr1, sizeof(addr1)), ether_addr_ntop(cache->ha, addr2, sizeof(addr2)));

   /* Exercise 14-1: キャッシュのエントリを削除する */
   cache->state = ARP_CACHE_STATE_FREE;
   memcpy(cache->ha, ETHER_ADDR_ANY, sizeof(cache->ha));
   cache->pa = IP_ADDR_ANY;
   timerclear(&cache->timestamp);
   /* Exerciseここまで */
}

static struct arp_cache *
arp_cache_alloc(void)
{
   struct arp_cache *entry, *oldest = NULL;

   for (entry = caches; entry < tailof(caches); entry++) { // ARPキャッシュのテーブルを巡回する
      // 使用されていないエントリを探す
      if (entry->state == ARP_CACHE_STATE_FREE) {
         return entry;
      }

      // 空きがなかったときのために一番古いエントリも一緒に探す
      if (!oldest || timercmp(&oldest->timestamp, &entry->timestamp, >)) {
         oldest = entry;
      }
   }
   arp_cache_delete(oldest);  // 現在登録されている内容を削除する
   return oldest;             // 空きが無かったら一番古いエントリを返す
}

static struct arp_cache *
arp_cache_select(ip_addr_t pa)
{
   /* Exercise 14-2: キャッシュの中からプロトコルアドレスが一致するエントリを探して返す */
   struct arp_cache *entry;

   for (entry = caches; entry < tailof(caches); entry++) {
      // 念の為FREE状態ではないエントリの中から探す
      if (entry->state != ARP_CACHE_STATE_FREE && entry->pa == pa) {
            return entry;
      }
   }
   
   // 見つからなかったらNULLを返す
   return NULL;
}

static struct arp_cache *
arp_cache_update(ip_addr_t pa, const uint8_t *ha)
{
   struct arp_cache *cache;
   char addr1[IP_ADDR_STR_LEN];
   char addr2[ETHER_ADDR_STR_LEN];

   /* Exercise 14-3: キャッシュに登録されている情報を更新する */
   // 1. arp_cache_select()でエントリを検索する
   cache = arp_cache_select(pa);
   //    見つからなかったらNULLを返す
   if (!cache) {
      /* not found*/
      return NULL;
   }

   // 2. エントリの情報を更新する
   //    stateはRESOLVEDの状態にする
   cache->state = ARP_CACHE_STATE_RESOLVED;
   memcpy(cache->ha, ha, ETHER_ADDR_LEN);
   //    timestampはgettimeofday()で設定する
   gettimeofday(&cache->timestamp, NULL); 
   /* Exerciseここまで */

   debugf("UPDATE: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));
   return cache;
}

static struct arp_cache *
arp_cache_insert(ip_addr_t pa, const uint8_t *ha)
{
   struct arp_cache *cache;
   char addr1[IP_ADDR_STR_LEN];
   char addr2[ETHER_ADDR_STR_LEN];

   /* Exercise 14-4: キャッシュを新しくエントリに追加する */
   cache = arp_cache_alloc();
   if (!cache) {
      errorf("arp_cache_alloc() failure");
      return NULL;
   }

   // エントリの情報を設定する
   cache->state = ARP_CACHE_STATE_RESOLVED;
   cache->pa = pa;
   memcpy(cache->ha, ha, ETHER_ADDR_LEN);
   gettimeofday(&cache->timestamp, NULL);

   /* Exerciseここまで */
   debugf("INSERT: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));
   return cache;
}

static int
arp_request(struct net_iface *iface, ip_addr_t tpa)
{
   struct arp_ether_ip request;
   /* Exercise 15-2: ARP要求のメッセージを生成する*/
   request.hdr.hrd = hton16(ARP_HRD_ETHER);
   request.hdr.pro = hton16(ARP_PRO_IP);
   request.hdr.hln = ETHER_ADDR_LEN;
   request.hdr.pln = IP_ADDR_LEN;
   request.hdr.op = hton16(ARP_OP_REQUEST);
   memcpy(request.sha, iface->dev->addr, sizeof(iface->dev->addr));
   memcpy(request.spa, &((struct ip_iface*)iface)->unicast, IP_ADDR_LEN);
   memcpy(request.tha, ETHER_ADDR_BROADCAST, ETHER_ADDR_LEN);
   memcpy(request.tpa, &tpa, IP_ADDR_LEN);
   /* Exerciseここまで */

   debugf("dev=%s, len=%zu", iface->dev->name, sizeof(request));
   arp_dump((uint8_t *)&request, sizeof(request));

   /*Exercise 15-3: デバイスの送信関数を呼び出してARP要求のメッセージを送信する */
   return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&request, sizeof(request), ETHER_ADDR_BROADCAST);
}

static int
arp_reply(struct net_iface *iface, const uint8_t *tha, ip_addr_t tpa, const uint8_t *dst)
{
   struct arp_ether_ip reply;

   /* Exercise 13-3: ARP応答メッセージの生成 */
   reply.hdr.hrd = hton16(ARP_HRD_ETHER);
   reply.hdr.pro = hton16(ARP_PRO_IP);
   reply.hdr.hln = ETHER_ADDR_LEN;
   reply.hdr.pln = IP_ADDR_LEN;
   reply.hdr.op = hton16(ARP_OP_REPLY); // hton16()を使うのを忘れない
   
   // spa/sha - インタフェースのIPアドレスと紐づくデバイスのMACアドレスを設定する
   memcpy(reply.sha, iface->dev->addr, sizeof(iface->dev->addr));
   // memcpy(&reply.spa, iface->);
   memcpy(reply.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN); // 分からなかった

   // tpa/tha - ARP要求を送ってきたノードのIPのアドレスとMACアドレスを設定する
   // reply.tha = tha;                     // 間違い
   memcpy(reply.tha, tha, ETHER_ADDR_LEN); // 正解
   memcpy(reply.tpa, &tpa, IP_ADDR_LEN);
   /* Exerciseここまで*/

   debugf("dev=%s, len=%zu", iface->dev->name, sizeof(reply));
   arp_dump((uint8_t *)&reply, sizeof(reply));
   return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&reply, sizeof(reply), dst); // デバイスからARPメッセージを送信する
}

int
arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha)
{
   struct arp_cache *cache;
   char addr1[IP_ADDR_STR_LEN];
   char addr2[ETHER_ADDR_STR_LEN];

   // 念の為、物理デバイスと論理インタフェースがそれぞれEthernetとIPであることを確認する
   if (iface->dev->type != NET_DEVICE_TYPE_ETHERNET) {
      debugf("unsupported hardware address type");
      return ARP_RESOLVE_ERROR;
   }
   if (iface->family != NET_IFACE_FAMILY_IP) {
      debugf("unsupported protocol address type");
      return ARP_RESOLVE_ERROR;
   }

   mutex_lock(&mutex);
   cache = arp_cache_select(pa); // プロトコルアドレスをキーにARPキャッシュを検索する
   if (!cache) {

      debugf("cache not found, pa=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)));

      /* Exercise15-1: ARPキャッシュに問い合わせ中のエントリを追加する*/
      // 新しいエントリにスペースを確保する。
      cache = arp_cache_alloc();
      if (!cache) {
         debugf("arp_cache_alloc() failure");
         mutex_unlock(&mutex);
         return ARP_RESOLVE_ERROR;
      }
      // エントリの各フィールドに値を設定する
      cache->state = ARP_CACHE_STATE_INCOMPLETE;
      cache->pa = pa;
      gettimeofday(&cache->timestamp, NULL);
      
      /* Exerciseここまで */

      mutex_unlock(&mutex);
      arp_request(iface, pa); // 
      return ARP_RESOLVE_INCOMPLETE; // 見つからなければエラーを返す
   }

   // 見つかったエントリがINCOMPLETEのままだった場合はパケロスしているかもしれないので念の為再送する（タイムスタンプは更新しない）
   if (cache->state == ARP_CACHE_STATE_INCOMPLETE) {
      mutex_unlock(&mutex);
      arp_request(iface, pa); /* just in case of packet loss*/
      return ARP_RESOLVE_INCOMPLETE;
   }

   memcpy(ha, cache->ha, ETHER_ADDR_LEN); // 見つかったハードウェアアドレスをコピーする
   mutex_unlock(&mutex);
   debugf("resolved, pa=%s, ha=%s", 
      ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));
   return ARP_RESOLVE_FOUND; // 見つかったのでFOUNDを返す
}

static void
arp_input(const uint8_t *data, size_t len, struct net_device *dev)
{
   struct arp_ether_ip *msg;
   ip_addr_t spa, tpa;
   struct net_iface *iface;
   int merge = 0;

   // 期待するARPメッセージのサイズよりも小さければエラーを返す
   if (len < sizeof(*msg)) {
      errorf("too short");
      return;
   }
   msg = (struct arp_ether_ip *)data;

   /* Exercise 13-1: 対応可能なアドレスペアのメッセージのみ受け入れる*/
   // ハードウェアアドレスのチェック
   if (ntoh16(msg->hdr.hrd) != ARP_HRD_ETHER || msg->hdr.hln != ETHER_ADDR_LEN) {
      // アドレス種別とアドレス長がEthernetと合致しなければ中断
      errorf("hrd or hln mismatched.");
      return;
   }
   // プロトコルアドレスのチェック
   if (ntoh16(msg->hdr.pro) != ETHER_TYPE_IP || msg->hdr.pln != IP_ADDR_LEN) {
      // アドレス種別とアドレス長がIPと合致しなければ中断
      errorf("pro or pln mismatched.");
      return;
   }
   /* Exerciseここまで */

   debugf("dev=%s, len=%zu", dev->name, len);
   arp_dump(data, len);
   memcpy(&spa, msg->spa, sizeof(spa));
   memcpy(&tpa, msg->tpa, sizeof(tpa)); // spa/tpaをmemcpy()でip_addr_tの変数へ取り出す

   mutex_lock(&mutex); // キャッシュへのアクセスをミューテックスで保護する
   if (arp_cache_update(spa, msg->sha)) {
       // ARPメッセージを受診したら、まず送信元アドレスのキャッシュ情報を更新する（更新なので未登録の場合は失敗する）
      /* updated */
      merge = 1;
   }
   mutex_unlock(&mutex); // アンロックを忘れずに


   iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP); // デバイスに紐づくIPインタフェースを取得する   
   if (iface && ((struct ip_iface *)iface)->unicast == tpa) {
      if (!merge) { //先の処理で送信元アドレスのキャッシュ情報が更新されていなかったら（まだ未登録だったら）
         mutex_lock(&mutex);
         arp_cache_insert(spa, msg->sha); //送信元アドレスのキャッシュ情報を新規登録する
         mutex_unlock(&mutex);
      }
      
      /*Exercise 13-2: ARP要求への応答*/
      // メッセージ種別がARP要求ならば、arp_reply()を呼び出してARP応答を送信する
      if (ntoh16(msg->hdr.op) == ARP_OP_REQUEST) {
         // arp_reply(iface, msg->hdr.hrd, spa, msg->spa); // 間違い
         arp_reply(iface, msg->sha, spa, msg->sha);
         return;
      }
   }
}

static void
arp_timer_handler(void)
{
   struct arp_cache *entry;
   struct timeval now, diff;

   mutex_lock(&mutex);
   gettimeofday(&now, NULL);
   for (entry = caches; entry < tailof(caches); entry++) {
      // 未使用のエントリと静的エントリは除外する
      if (entry->state != ARP_CACHE_STATE_FREE && entry->state != ARP_CACHE_STATE_STATIC) {
         /* Exercise 16-3: タイムアウトしたエントリの削除 */
         timersub(&now, &entry->timestamp, &diff);
         // タイムアウト時間
         if (diff.tv_sec > ARP_CACHE_TIMEOUT) {
            arp_cache_delete(entry);
         }
         // Exerciseここまで
      }
   }
   mutex_unlock(&mutex);
}

int
arp_init(void)
{
   struct timeval interval = {1, 0};  /* 1s */ // ARPのタイマーハンドラを呼び出す際のインターバル

   /* Exercise 16-4: ARPのタイマーハンドラを登録する*/
   if (net_timer_register(interval, arp_timer_handler) == -1) {
      errorf("net_timer_register() failure");
      return -1;
   }
   /* Exerciseここまで */

   /* Exercise 13-4: プロトコルスタックにARPを登録する */
   // 分からなかった
   if (net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input) == -1) {
      errorf("net_protocol_register() failure");
      return -1;
   }
   /* Exerciseここまで */
   return 0;
}