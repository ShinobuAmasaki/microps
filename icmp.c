#include <stdint.h>
#include <stddef.h>

#include "util.h"
#include "ip.h"
#include "icmp.h"

// ICMPヘッダ構造体（メッセージ固有のフィールドは単なる32ビットの値として扱う）
struct icmp_hdr {
   uint8_t type;
   uint8_t code;
   uint16_t sum;
   uint32_t values;
};

// Echo/EchoReplyメッセージ構造体（メッセージ種別が判別した段階でこちらにキャストする）
struct icmp_echo {
   uint8_t type;
   uint8_t code;
   uint16_t sum;
   uint16_t id;
   uint16_t seq;
};

static char *
icmp_type_ntoa(uint8_t type) {
   switch (type)
   {
   case ICMP_TYPE_ECHOREPLY:
      return "EchoReply";
   case ICMP_TYPE_DEST_UNREACH:
      return "DestinationUnreachable";
   case ICMP_TYPE_SOURCE_QUENCH:
      return "SourceQuench";
   case ICMP_TYPE_REDIRECT:
      return "Redirect";
   case ICMP_TYPE_ECHO:
      return "Echo";
   case ICMP_TYPE_TIME_EXCEEDED:
      return "TimeExceeeded";
   case ICMP_TYPE_PARAM_PROBLEM:
      return "ParameterProblem";
   case ICMP_TYPE_TIMESTAMP:
      return "Timestamp";
   case ICMP_TYPE_TIMESTAMPREPLY:
      return "TimestampReply";
   case ICMP_TYPE_INFO_REQUEST:
      return "InfomationRequest";
   case ICMP_TYPE_INFO_REPLY:
      return "InformationReply";
   }
   return "Unknown";
}

static void
icmp_dump(const uint8_t *data, size_t len)
{
   struct icmp_hdr *hdr;
   struct icmp_echo *echo;

   flockfile(stderr);
   hdr = (struct icmp_hdr *) data;
   // 全メッセージ共通のフィールド
   fprintf(stderr, "       type: %u (%s)\n", hdr->type, icmp_type_ntoa(hdr->type));
   fprintf(stderr, "       code: %u\n", hdr->code);
   fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
   
   switch (hdr->type) {
   // Echo/EchoReplyの場合は詳細を出力する。
   case ICMP_TYPE_ECHOREPLY:
   case ICMP_TYPE_ECHO:
      echo = (struct icmp_echo *)hdr;
      fprintf(stderr, "         id: %u\n", ntoh16(echo->id));
      fprintf(stderr, "        seq: %u\n", ntoh16(echo->seq));
      break;
   default: // その他のメッセージの場合には32ビット値をそのまま出力する。
      fprintf(stderr, "     values: 0x%08x\n", ntoh32(hdr->values));
      break;
   }
#ifdef HEXDUMP
   hexdump(stderr, data, len);
#endif
   funlockfile(stderr);
}

void
icmp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
   struct icmp_hdr *hdr;
   char addr1[IP_ADDR_STR_LEN];
   char addr2[IP_ADDR_STR_LEN];

   /* Exercise 10-1: ICMPメッセージの検証*/
   hdr = (struct icmp_hdr *)data;
   if (len < sizeof(*hdr)) {
      errorf("too short ICMP message, len=%u < %u", len, sizeof(*hdr));
      return;
   }

   if (cksum16((uint16_t *)data, sizeof(data), 0) == 0) {
      errorf("checksum unmatched, sum=%zu", cksum16((uint16_t *)data, sizeof(data), 0));
      return;
   }


   debugf("%s => %s, len=%zu", ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(dst, addr2, sizeof(addr2)), len);
   icmp_dump(data, len);
}

int
icmp_init(void)
{
   /* Exercise 9-4: ICMPの入力関数（icmp_init）をIPに登録する
    * プロトコル番号はip.hに定義してある定数を使う
    */
   if (ip_protocol_register(IP_PROTOCOL_ICMP, icmp_input) == -1){
      errorf("ip_protocol_register() failure");
      return -1;
   }
   // Exerciseここまで

   return 0;
}