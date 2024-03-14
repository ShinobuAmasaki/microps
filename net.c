#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "arp.h"

struct net_protocol {
	struct net_protocol *next; // 次のプロトコルへのポインタ
	uint16_t type; // プロトコルの種別
	struct queue_head queue; /*input queue 受信キュー*/
	void (*handler)(const uint8_t *data, size_t len, struct net_device *dev); //プロトコルの入力関数へのポインタ
};

// 受信キューのエントリの構造体
struct net_protocol_queue_entry {
	struct net_device *dev;
	size_t len;
	uint8_t data[];
};

// タイマーの構造体
struct net_timer {
	struct net_timer *next;  // 次のタイマーへのポインタ
	struct timeval interval; // 発火のインターバル
	struct timeval last;		 // 最後の発火時間
	void (*handler)(void);	 // 発火時に呼び出す関数へのポインタ
};

/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex. */

// デバイスリスト（リストの先頭を指すポインタ）
static struct net_device *devices;

// 登録されているプロトコルのリスト（グローバル変数）
static struct net_protocol *protocols;

// タイマーリスト
static struct net_timer *timers;

struct net_device *
net_device_alloc(void)
{
	struct net_device *dev;

	// デバイス構造体のサイズのメモリを確保する。
	dev = memory_alloc(sizeof(*dev));

	// 確保に失敗した場合の処理
	if (!dev) {
		errorf("memory_alloc() failure");
		return NULL;
	}

	return dev;
}

/* NOTE: must not be call after net_run() */
int
net_device_register(struct net_device *dev)
{
	static unsigned int index = 0;

	// デバイスのインデックス番号を設定する。
	dev->index = index++;

	// デバイス名を生成する。
	snprintf(dev->name, sizeof(dev->name), "net%d", dev->index); // generate device name
	
	// デバイスリストの先頭に追加する。
	dev->next = devices;
	devices = dev;

	// infoメッセージを出力する。
	infof("registered, dev=%s, type=0x%04x", dev->name, dev->type);
	
	return 0;
}

/* NOTE: must not be call after net_run() */
int
net_timer_register(struct timeval interval, void (*handler)(void))
{
	struct net_timer *timer;

	/* Exercise 16-1: タイマーの登録 */
	timer = memory_alloc(sizeof(*timer));
	if (!timer) {
		errorf("memory_alloc() failure");
		return -1;
	}

	gettimeofday(&timer->last, NULL);
	timer->interval = interval;
	timer->handler = handler;
	
	timer->next = timers;
	timers = timer;
	/* Exercise ここまで */

	infof("registered: interval={%d, %d}", interval.tv_sec, interval.tv_usec);
	return 0;
}

int
net_timer_handler(void)
{
	struct net_timer *timer;
	struct timeval now, diff;

	for (timer = timers; timer; timer = timer->next) {
		gettimeofday(&now, NULL);
		timersub(&now, &timer->last, &diff);
		if (timercmp(&timer->interval, &diff, <) != 0) { // true (!0) or false(0) // 発火時刻を迎えているかどうか
			// Exercise 16-2: タイマーの発火
			timer->handler();
			gettimeofday(&timer->last, NULL);
		}
	}
	return 0;
}

static int
net_device_open(struct net_device *dev)
{
	// デバイスの状態を確認する（すでにUP状態の場合はエラーを返す）
	if (NET_DEVICE_IS_UP(dev)) {
		errorf("already opened, dev=%s", dev->name);
		return -1;
	}

	// デバイスドライバのオープン関数を呼び出す（オープン関数が設定されていない場合は呼び出しをスキップする）
	if (dev->ops->open) {
		// エラーが返されたら、この関数もエラーを返す。
		if (dev->ops->open(dev) == -1) {
			errorf("failure, dev=%s", dev->name);
			return -1;
		}
	}

	// UPフラグを立てる
	dev->flags |= NET_DEVICE_FLAG_UP;

	infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
	return 0;
}

static int
net_device_close(struct net_device *dev)
{
	// デバイスの状態を確認する（UPでない場合はエラーを返す）
	if (!NET_DEVICE_IS_UP(dev)) {
		errorf("not opened, dev=%s", dev->name);
		return -1;
	}

	// デバイスドライバのクローズ関数を呼び出す（クローズ関数が設定されていない場合は呼び出しをスキップする）
	if (dev->ops->close) {
		// エラーが返されたら、この関数もエラーを返す
		if (dev->ops->close(dev) == -1) {
			errorf("failure, dev=%s", dev->name);
			return -1;
		}
	}

	// UPフラグを落とす
	dev->flags &= ~NET_DEVICE_FLAG_UP;
	infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
	return 0;
}

/* NOTE: must not be call after net_run() */
int
net_device_add_iface(struct net_device *dev, struct net_iface *iface)
{
	struct net_iface *entry;

	for (entry = dev->ifaces; entry; entry = entry->next) {
		if (entry->family == iface->family) {
			/* NOTE: For simplicity, only one iface can be added per family. */
			errorf("already exists, dev=%s, family=%s", dev->name, entry->family);
			return -1;
		}
	}
	iface->dev = dev;
	
	/* Exercise 7-1: デバイスのインタフェースリストの先頭にifaceを挿入する*/
	iface->next = dev->ifaces;
	dev->ifaces = iface;
	/* Exerciseここまで*/
	
	return 0;
}

struct net_iface *
net_device_get_iface(struct net_device *dev, int family)
{
	struct net_iface *entry;
	/* Exercise 7-2: デバイスに紐づくインタフェースを検索する*/
	// デバイスのインタフェースリストを巡回する
	for (entry = dev->ifaces; entry; entry = entry->next) {
		// familyが一致するインタフェースを返す
		if (entry->family == family) {
			return entry;
		}
	}
	// 一致するインタフェースを発見できなかったらNULLを返す
	return NULL; 
		
	/* Exerciseここまで*/
}

int
net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
	// デバイスの状態を確認する（UPでなければ送信できないのでエラーを返す）
	if (!NET_DEVICE_IS_UP(dev)) {
		errorf("not opened, dev=%s", dev->name);
		return -1;
	}
	// データのサイズを確認する（デバイスのMTUを超えるサイズのデータは送信できないので、エラーを返す）
	if (len > dev->mtu) {
		errorf("too long, dev=%s, mtu=%u, len=%zu", dev->name, dev->mtu, len);
		return -1;
	}


	debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
	debugdump(data, len);

	// デバイスドライバの出力関数を呼び出す（エラーが返されたらこの関数もエラーを返す）
	if (dev->ops->transmit(dev, type, data, len, dst) == -1) {
		errorf("device transmit failure, dev=%s, len=%zu", dev->name, len);
		return -1;
	}
	return 0;
}

/* NOTE: must not be call after net_run() */
int
net_protocol_register(uint16_t type, void (*handler)(const uint8_t *data, size_t len, struct net_device *dev))
{
	struct net_protocol *proto;

	// 重複登録の確認
	for (proto = protocols; proto; proto = proto->next) {
		if (type == proto->type) {
			errorf("already registered, type=0x%04x", type);
			return -1;
		}
	}

	// プロトコル構造体のメモリを確保する
	proto = memory_alloc(sizeof(*proto));
	if (!proto) {
		errorf("memory_alloc() failure");
		return -1;
	}

	// プロトコルの種別と入力関数を設定する。
	proto->type = type;
	proto->handler = handler;

	// プロトコルリストの先頭に追加
	proto->next = protocols;
	protocols = proto;

	infof("registered, type=0x%04x", type);
	return 0;
}

int
net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev)
{
	/*デバイスが受信したパケットをプロトコルスタックに渡す関数*/

	struct net_protocol *proto;
	struct net_protocol_queue_entry *entry;

	for (proto = protocols; proto; proto = proto->next) {
		if (proto->type == type) {

			/* Exercise 4-1*/
			// 新しいエントリのメモリを確保
			entry = memory_alloc(sizeof(*entry)+len);
			if (!entry) {
				errorf("memory_alloc failure");
				return -1;
			}

			// 新しいエントリへメタデータの設定と受信データのコピー
			entry->dev = dev;
			entry->len = len;
			memcpy(entry->data, data, len);

			// キューに新しいエントリを挿入する。
			if (queue_push(&(proto->queue), entry) == NULL) {
				errorf("queue_push failure");
				return -1;
			}
			/* Exercise ここまで*/

			debugf("queue pushed (num:%u), dev=%s, type=0x%04x, len=%zu",
				proto->queue.num, dev->name, type, len);
			debugdump(data, len);

			// 受信キューへエントリを追加した後に、ソフトウェア割り込みを発生させる
			intr_raise_irq(INTR_IRQ_SOFTIRQ);

			return 0;
		}
	}
	/* unsupported protocol */
	/* プロトコルが見つからなかったら、黙って捨てる*/
	infof("dropped, type=0x%04x", type);
	return 0;
}

// ソフトウェア割り込みが発生した際に呼び出してもらう関数
int
net_softirq_handler(void)
{
	struct net_protocol *proto;
	struct net_protocol_queue_entry *entry;

	for (proto = protocols; proto; proto = proto->next) {
		while (1) {

			// 受信キューからエントリを取り出す
			entry = queue_pop(&proto->queue);
			if (!entry) {
				break;
			}

			debugf("queue poped (num:%u), dev=%s, type=0x%04x, len=%zu", proto->queue.num, entry->dev->name, proto->type, entry->len);
			debugdump(entry->data, entry->len);

			proto->handler(entry->data, entry->len, entry->dev); // プロトコルの入力関数を呼び出す
			memory_free(entry); // 使い終わったエントリのメモリを開放する
		}
	}
	return 0;
}

int
net_run(void)
{
	struct net_device *dev;

	// 割り込み機構の起動
	if (intr_run() == -1) {
		errorf("intr_run() failure");
		return -1;
	}

	debugf("open all devices...");
	// 登録済みの全デバイスをオープンする
	for (dev = devices;dev; dev = dev->next) {
		net_device_open(dev);
	}

	debugf("running...");
	return 0;
}

void
net_shutdown(void)
{
	struct net_device *dev;

	debugf("close all devices...");
	// 登録済みの全デバイスをクローズする
	for (dev = devices; dev; dev = dev->next) {
		net_device_close(dev);
	}
	intr_shutdown(); // 割り込み機構の終了
	debugf("shutting down");
}

int
net_init(void)
{
	if (intr_init() == -1) {
		errorf("intr_init() failure");
		return -1;
	}

	/* Exercise 13-5: ARPの初期化関数を呼び出す*/
	if  (arp_init() == -1) {
		errorf("arp_init() failure");
		return -1;
	}
	/* Exerciseここまで */

	// プロトコルスタック初期化時にIPの初期化関数を呼び出す
	if (ip_init() == -1) {
		errorf("ip_init() failure");
		return -1;
	}

	// ICMPの初期化関数を呼び出す。
	if (icmp_init() == -1) {
		errorf("icmp_init() failure");
		return -1;
	}

	infof("initialized");
	return 0;
}

