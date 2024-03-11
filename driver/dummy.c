#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include "platform.h"

#include "util.h"
#include "net.h"

#define DUMMY_MTU UINT16_MAX /* maximum size of IP datagram */

#define DUMMY_IRQ INTR_IRQ_BASE

static int
dummy_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
	debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
	debugdump(data, len);
	/* drop data */
	intr_raise_irq(DUMMY_IRQ); // テスト用に割り込みを発生させる
	return 0;
}

static int
dummy_isr(unsigned int irq, void *id)
{
	debugf("irq=%u, dev=%s", irq, ((struct net_device *)id)->name); //呼び出されたことが分かれば良いのでデバッグ出力のみ
	return 0;
}

// デバイスドライバが実装している関数のアドレスを保持する構造体へのポインタを設定する。
static struct net_device_ops dummy_ops= {
	.transmit = dummy_transmit,
};

struct net_device *
dummy_init(void)
{
	struct net_device *dev;

	// デバイスを生成する
	dev = net_device_alloc();
	if (!dev) {
		errorf("net_device_alloc() failure");
		return NULL;
	}

	dev->type = NET_DEVICE_TYPE_DUMMY; // net.hで定義されている
	dev->mtu = DUMMY_MTU;	// 上で定義
	dev->hlen = 0;
	dev->alen = 0;	// ヘッダーもアドレスもなし
	dev->ops = &dummy_ops; // デバイスドライバが実装している関数のアドレスを保持する構造体へのポインタを設定する。

	// デバイスを登録する
	if (net_device_register(dev) == -1) {
		errorf("net_device_register() failure");
		return NULL;
	}
	intr_request_irq(DUMMY_IRQ, dummy_isr, INTR_IRQ_SHARED, dev->name, dev); // 割り込みハンドラとしてdummy_isrを登録する。

	debugf("initialized, dev=%s", dev->name);
	return dev;
}

