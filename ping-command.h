#ifndef _PING_COMMAMD_H_
#define _PING_COMMAMD_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#endif

typedef struct {
    const char* ip_address;
    int* result;
#ifndef _WIN32
    pthread_t thread_id;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int finished;
#endif
} PingData;


/* 判断一组ip地址是否可以ping通，最终判断结果的返回在result数组中, 1表示可以ping通，其他值无法ping通
   注意调用时需要在函数外手动管理内存申请释放
   参数：
   ip_addresses：字符串指针数组
   int* results：结果指针数组,1表示成功，其他值为失败
   int num_ips： 字符串数组和结果指针数组的大小
*/

void ping_multiple_ips(const char** ip_addresses, int* results, int num_ips);

void ping_multiple_ips_on_win(const char** ip_addresses, int* results, int num_ips);

void ping_multiple_ips_on_unix(const char** ip_addresses, int* results, int num_ips);

#endif // !_PING_COMMAMD_H_