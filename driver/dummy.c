#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include "util.h"
#include "net.h"

#define DUMMY_MTU UINT16_MAX /* maximum size of IP datagram */

static int
dummy_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
	debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
	debugdump(data, len);
	/* drop data */
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

	debugf("initialized, dev=%s", dev->name);
	return dev;
}

