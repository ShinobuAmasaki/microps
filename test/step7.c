#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"
#include "ip.h"

#include "driver/loopback.h"
#include "test.h"

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
	(void)s;
	terminate = 1;
}

int main(int argc, char *argv[])
{
	struct net_device *dev;
	struct ip_iface *iface;

	// シグナルハンドラの設定(Ctrl+Cが押下された場合、on_signalを呼び出して行儀よく終了するように)
	signal(SIGINT, on_signal);

	// プロトコルスタックの初期化
	if (net_init() == -1) {
		errorf("net_init() failure");
		return -1;
	}

	// ダミーデバイスの初期化（デバイスドライバがプロトコルスタックへの登録まで済ませる）
	dev = loopback_init();
	if (!dev) {
		errorf("loopback_init() failure");
		return -1;
	}
	
	// IPアドレスとサブネットマスクを指定してIPインタフェースを生成する。
	iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
	if (!iface) {
		errorf("ip_iface_alloc() failure");
		return -1;
	}
	// IPインタフェースの登録（devにifaceが紐付けられる）
	if (ip_iface_register(dev, iface) == -1) {
		errorf("ip_iface_register() failure");
		return -1;
	}
	
	// プロトコルスタックの起動
	if (net_run() == -1) {
		errorf("net_run() failure");
		return -1;
	}

	while (!terminate) { // Ctrl+Cが押されるとシグナルハンドラon_signal()の中でterminateに1が設定される。
		
		// 1秒おきにデバイスへパケットを書き込む
		if (net_device_output(dev, NET_PROTOCOL_TYPE_IP, test_data, sizeof(test_data), NULL) == -1) {
			errorf("net_device_output() failure");
			break;
		}
		sleep(1);
	}
	
	// プロトコルスタックの停止
	net_shutdown();
	return 0;
}
