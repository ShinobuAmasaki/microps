#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include "platform.h"

#include "util.h"
#include "net.h"

/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex. */

// デバイスリスト（リストの先頭を指すポインタ）
static struct net_device *devices;

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

int
net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev)
{
	/*デバイスが受信したパケットをプロトコルスタックに渡す関数*/

	debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
	debugdump(data, len);
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

	infof("initialized");
	return 0;
}

