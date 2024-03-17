#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "platform.h"

int
sched_ctx_init(struct sched_ctx *ctx)
{
   // 初期化する
   pthread_cond_init(&ctx->cond, NULL);
   ctx->interrupted = 0;
   ctx->wc = 0;
   return 0;
}

int
sched_ctx_destroy(struct sched_ctx *ctx)
{
   return pthread_cond_destroy(&ctx->cond); // 条件変数の破棄
   // 待機中のスレッドが存在する場合にのみエラーが返る
}

int
sched_sleep(struct sched_ctx *ctx, mutex_t *mutex, const struct timespec *abstime)
{
   int ret;

   // interruptのフラグが立っていたらerrnoにEINTRを設定してエラーを返す
   if (ctx->interrupted) {
      errno = EINTR;
      return -1;
   }
   ctx->wc++; // waitカウントをインクリメントする

   /* pthread_cond_broadcast()が呼ばれたらスレッドを休止させる
    * abstimeが指定されていたら指定時刻に起床するpthread_cond_timewait()を使用する
    * 休止する際にはmutexがアンロックされ、起床する際にロックされた状態で戻ってくる
    */

   if (abstime) {
      ret = pthread_cond_timedwait(&ctx->cond, mutex, abstime);
   } else {
      ret = pthread_cond_wait(&ctx->cond, mutex);
   }

   ctx->wc--; // waitカウントをデクリメントする
   if (ctx->interrupted) { // 休止中だったスレッドすべてが起床したらinterruptedフラグを下げる
      if (!ctx->wc) {
         ctx->interrupted = 0;
      }
      errno = EINTR; // errnoにEINTRを設定してエラーを返す
      return -1;
   }
   return ret;
}

int
sched_wakeup(struct sched_ctx *ctx)
{
   return pthread_cond_broadcast(&ctx->cond); // 休止しているスレッドを起こす
}

int
sched_interrupt(struct sched_ctx *ctx)
{
   ctx->interrupted = 1;
   return pthread_cond_broadcast(&ctx->cond);
}