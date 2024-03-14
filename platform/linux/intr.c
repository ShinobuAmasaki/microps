#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "platform.h"

#include "util.h"
#include "net.h"

// 割り込み要求（IRQ）の構造体（デバイスと同様にリスト構造で管理する）
struct irq_entry {
   struct irq_entry *next; // 次のIRQ構造体へのポインタ
   unsigned int irq;       // 割り込み番号
   int (*handler)(unsigned int irq, void*dev); // 割り込みハンドラ（割り込みが発生した際に呼び出す関数へのポインタ）
   int flags;  // フラグ（INTR_IRQ_SHAREDが指定された場合はIRQ番号を共有可能）
   char name[16]; // デバッグ出力で識別するための名前
   void *dev;     // 割り込み発生元となるデバイス（struct net_device以外にも対応できるようにvoid*で保持する）
};

/* Note: if you want to add/delete the entries after intr_run(), you need to protect these lists with a mutex. */
static struct irq_entry *irqs; // IRQリスト（リストの先頭を指すポインタ） 

static sigset_t sigmask; // シグナル集合（シグナルマスク用）

static pthread_t tid; // 割り込みスレッドのスレッドID
static pthread_barrier_t barrier; // スレッド間の同期のためのバリア

int
intr_request_irq(unsigned int irq, int (*handler)(unsigned int irq, void*dev), int flags, const char*name, void*dev)
{
   struct irq_entry *entry;

   debugf("irq=%u, flags=%d, name=%s", irq, flags, name);

   // IRQ番号がすでに登録されている場合、IRQ番号の共有が許可されているかどうかをチェックする
   // どちらかが共有を許可していない場合はエラーを返す
   for (entry = irqs; entry; entry = entry->next) {
      if (entry->irq == irq) {
         if (entry->flags ^ INTR_IRQ_SHARED || flags ^ INTR_IRQ_SHARED) {
            errorf("conflicts with already registered IRQs");
            return -1;
         }
      }
   }

   // IRQリストへ新しいエントリを追加する
   entry = memory_alloc(sizeof(*entry));
   if (!entry) {
      errorf("memory_alloc() failure");
      return -1;
   }

   // IRQ構造体の値を設定する
   entry->irq = irq;
   entry->handler = handler;
   entry->flags = flags;
   strncpy(entry->name, name, sizeof(entry->name)-1);
   entry->dev = dev;

   // IRQリストの先頭に挿入する
   entry->next = irqs;
   irqs = entry;

   // シグナル集合へ新しいシグナルを追加する
   sigaddset(&sigmask, irq);
   debugf("registered: irq=%u, name=%s", irq, name);

   return 0;
}

int
intr_raise_irq(unsigned int irq)
{
   return pthread_kill(tid, (int)irq); // 割り込み処理スレッドへシグナルを送信する。
}

static int
intr_timer_setup(struct itimerspec *interval)
{
   timer_t id;

   // タイマーの作成
   if (timer_create(CLOCK_REALTIME, NULL, &id) == -1) {
      errorf("timer_create: %s", strerror(errno));
      return -1;
   }

   // インターバルの設定
   if (timer_settime(id, 0, interval, NULL) == -1) {
      errorf("timer_settime: %s", strerror(errno));
      return -1;
   }
   return 0;
}


/* シグナル受診時に非同期で実行されるシグナルハンドラでは、実行できる処理が大きく制限されるため、
   割り込み処理のために専用のスレッドを起動してシグナルの発生を待ち受けて処理する。
*/
static void*
intr_thread(void*arg) // 割り込みスレッドのエントリポイント
{
   int terminate = 0, sig, err;
   struct irq_entry *entry;
   const struct timespec ts = {0, 1000000}; /* 1ms */
   struct itimerspec interval = {ts, ts};

   debugf("start...");
   pthread_barrier_wait(&barrier);

   if (intr_timer_setup(&interval) == -1) {
      errorf("intr_timer_setup() failure");
      return NULL;
   }


   while (!terminate) {
      err = sigwait(&sigmask, &sig);
      if (err) {
         errorf("sigwait() %s", strerror(err));
         break;
      }

      // 発生したシグナルの種類に応じた処理を記述する
      switch (sig)   
      {
      case SIGHUP:
         terminate = 1; // SIGHUP割り込みスレッドへ終了を通知するためのシグナル（terminateを1にしてループを抜ける）
         break;
      
      case SIGUSR1:
         net_softirq_handler(); // ソフトウェア割り込み用のシグナルを補足した場合の処理を追加する
         break;

      case SIGALRM:
         net_timer_handler(); // 周期処理用タイマーが発火した際の処理
            // 登録されているタイマーを確認するためにnet_timer_handler()を呼び出す
         break;

      default:
         // デバイス割り込み用のシグナル
         for (entry = irqs; entry; entry=entry->next) { // IRQリストを巡回する
            if (entry->irq == (unsigned int)sig) {
               // IRQ番号が一致するエントリの割り込みハンドラを呼び出す
               debugf("irq=%d, name=%s", entry->irq, entry->name);
               entry->handler(entry->irq, entry->dev);
            }
         }
         break;
      }
   }
   debugf("terminated");
   return NULL;
}

int
intr_run(void)
{
   int err;
   
   // シグナルマスクの設定
   err = pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
   if (err) {
      errorf("pthread_sigmask() %s", strerror(err));
      return -1;
   }

   // 割り込み処理スレッドの起動
   err = pthread_create(&tid, NULL, intr_thread, NULL);
   if (err) {
      errorf("pthread_create() %s", strerror(err));
      return -1;
   }

   // スレッドが動き出すまで待つ
   // 他のスレッドが同じようにpthread_barrier_wait()を呼び出して、バリアのカウントが指定の数になるまでスレッドを停止する。
   pthread_barrier_wait(&barrier);
   return 0;
}

void
intr_shutdown(void)
{
   //割り込み処理スレッドが起動済みかどうか確認する
   if (pthread_equal(tid, pthread_self()) != 0) {
      /* Thread not created */
      return;
   }

   // 割り込み処理スレッドにシグナル（SIGHUP）を送信する
   pthread_kill(tid, SIGHUP);

   // 割り込みスレッドが完全に終了するのを待つ
   pthread_join(tid, NULL);
}

int
intr_init(void)
{
   // スレッドIDの初期値に、メインスレッドのIDを設定する
   tid = pthread_self();

   // pthread_barrierの初期化（カウントを2に設定する）
   pthread_barrier_init(&barrier, NULL, 2);

   // シグナル集合を初期化する（空にする）
   sigemptyset(&sigmask);

   // シグナル集合にSIGHUPを追加する（割り込みスレッド終了通知用）
   sigaddset(&sigmask, SIGHUP);

   // シグナル集合にSIGUSR1を追加する
   sigaddset(&sigmask, SIGUSR1);

   // 周期処理用タイマー発火時に送信されるシグナルを追加する
   sigaddset(&sigmask, SIGALRM);

   return 0;
}