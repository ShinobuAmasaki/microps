#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"

#include "driver/dummy.h"
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

	// シグナルハンドラの設定(Ctrl+Cが押下された場合、on_signalを呼び出して行儀よく終了するように)
	signal(SIGINT, on_signal);

	// プロトコルスタックの初期化
	if (net_init() == -1) {
		errorf("net_init() failure");
		return -1;
	}

	// ダミーデバイスの初期化（デバイスドライバがプロトコルスタックへの登録まで済ませる）
	dev = dummy_init();
	if (!dev) {
		errorf("dummy_init() failure");
		return -1;
	}
	
	// プロトコルスタックの起動
	if (net_run() == -1) {
		errorf("net_run() failure");
		return -1;
	}

	while (!terminate) { // Ctrl+Cが押されるとシグナルハンドラon_signal()の中でterminateに1が設定される。
		
		// 1秒おきにデバイスへパケットを書き込む
		if (net_device_output(dev, 0x0800, test_data, sizeof(test_data), NULL) == -1) {
			errorf("net_device_output() failure");
			break;
		}
		sleep(1);
	}
	
	// プロトコルスタックの停止
	net_shutdown();
	return 0;
}
