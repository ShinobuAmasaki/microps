#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"

#include "driver/loopback.h"
#include "test.h"

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
	(void)s;
	terminate = 1;
}

static int
setup(void)
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
	return 0;
}

static void
cleanup(void)
{
	net_shutdown();
}

int main(int argc, char *argv[])
{
	ip_addr_t src, dst;
	uint16_t id, seq = 0;
	size_t offset = IP_HDR_SIZE_MIN + ICMP_HDR_SIZE;

	if (setup() == -1) {
		errorf("setup() failure");
		return -1;
	}

	ip_addr_pton(LOOPBACK_IP_ADDR, &src);
	dst = src;

	id = getpid() % UINT16_MAX; // pidからidを採番する

	infof("seq = %zu", seq);
	while (!terminate) { // Ctrl+Cが押されるとシグナルハンドラon_signal()の中でterminateに1が設定される。
		
		// 1秒おきにインタフェースへパケットを送信する
		// if (ip_output(IP_PROTOCOL_ICMP, test_data + offset, sizeof(test_data) - offset, src, dst) == -1) {
		// ip_output()からicmp_output()へ変更する。
		if (icmp_output(ICMP_TYPE_ECHO, 0, hton32(id << 16 | ++seq), test_data+offset, sizeof(test_data) - offset, src, dst) == -1 ){
			errorf("icmp_output() failure");
			break;
		}
		sleep(1);
	}
	
	cleanup();
	return 0;
}
