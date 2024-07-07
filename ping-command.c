#include "ping-command.h"

int REQUEST_COUNT = 3;             // 单个ping命令执行时，指定发送的请求数
int SINGLE_REQUEST_TIMEOUT = 1000; // 单个ping命令执行时，等待每次回复的超时时间，单位毫秒（如发送三个请求，每个最多等待1s，一共等待3s）注意linux上存在差异
int MAX_TIMEOUT = 10000;           // 等待系统命令执行返回的最大超时时间, 单位毫秒

int main()
{
    // 定义要ping的IP地址数组
    const char *ip_addresses[] = {
        "192.168.1.1",
        "192.168.255.255",
        "8.8.8.8",
        "8.8.4.4"};

    // IP地址的数量
    int num_ips = sizeof(ip_addresses) / sizeof(ip_addresses[0]);

    // 用于存储ping结果的数组
    int results[num_ips];

    // 调用 ping_multiple_ips 函数
    ping_multiple_ips(ip_addresses, results, num_ips);

    // 打印结果
    for (int i = 0; i < num_ips; i++)
    {
        printf("IP Address: %s, Ping Result: %d\n", ip_addresses[i], results[i]);
    }

    return 0;
}

void ping_multiple_ips(const char **ip_addresses, int *results, int num_ips)
{

    if (ip_addresses == NULL)
    {
        printf("in ping_multiple_ips, param error, ip_addresses is NULL");
        return;
    }
    if (results == NULL)
    {
        printf("in ping_multiple_ips, param error, results is NULL");
        return;
    }
    if (num_ips <= 0)
    {
        printf("in ping_multiple_ips, param error, num_ips:%d is less than or equal to 0", num_ips);
        return;
    }

#ifdef _WIN32
    ping_multiple_ips_on_win(ip_addresses, results, num_ips);
#else
    ping_multiple_ips_on_unix(ip_addresses, results, num_ips);
#endif
}

#ifdef _WIN32

DWORD WINAPI PingThreadOnWin(LPVOID lpParam)
{
    PingData *pingData = (PingData *)lpParam;
    const char *ip_address = pingData->ip_address;

    /* windows ping 命令参数
       -w timeout：指定等待每个回复的超时时间，单位毫秒
       -n count：指定发送的请求数
    */
    char command[100];
    snprintf(command, sizeof(command), "ping -w %d -n %d %s >NUL 2>&1", SINGLE_REQUEST_TIMEOUT, REQUEST_COUNT, ip_address);
    printf("command:%s\n", command);

    // CreateProcess variables
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // Hide the window
    ZeroMemory(&pi, sizeof(pi));

    // Add the command to cmd.exe
    char full_command[200];
    snprintf(full_command, sizeof(full_command), "cmd.exe /C %s", command);

    if (CreateProcess(NULL, full_command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        // Wait until child process exits.
        WaitForSingleObject(pi.hProcess, INFINITE);

        // Get the exit code.
        DWORD exit_code;
        GetExitCodeProcess(pi.hProcess, &exit_code);

        // Close process and thread handles.
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        switch (exit_code)
        {
        case 0:
            // Alive
            *(pingData->result) = 1;
            break;
            // Unreachable or unknown host
        case 1:
        case 68:
        default:
            // Unreachable, unknown host, or other errors
            *(pingData->result) = -1;
            break;
        }
    }
    else
    {
        printf("CreateProcess failed...");
        *(pingData->result) = -1;
    }
    return 0;
}

void ping_multiple_ips_on_win(const char **ip_addresses, int *results, int num_ips)
{
    HANDLE *threads = (HANDLE *)malloc(num_ips * sizeof(HANDLE));
    PingData *pingData = (PingData *)malloc(num_ips * sizeof(PingData));

    if (threads == NULL || pingData == NULL)
    {
        printf("Memory allocation failed");
        if (threads)
            free(threads);
        if (pingData)
            free(pingData);
        return;
    }

    for (int i = 0; i < num_ips; i++)
    {
        pingData[i].ip_address = ip_addresses[i];
        pingData[i].result = &results[i];
        threads[i] = CreateThread(NULL, 0, PingThreadOnWin, &pingData[i], 0, NULL);
        if (threads[i] == NULL)
        {
            printf("CreateThread failed for IP %s", ip_addresses[i]);
            results[i] = -1; // Mark as failed
        }
    }
    // Wait for all threads to complete, with a timeout
    DWORD wait_result = WaitForMultipleObjects(num_ips, threads, TRUE, MAX_TIMEOUT);
    if (wait_result == WAIT_TIMEOUT)
    {
        printf("Timeout waiting for threads to complete.");
    }

    // Check each thread result
    for (int i = 0; i < num_ips; i++)
    {
        DWORD exit_code;
        if (threads[i] == NULL)
        {
            continue;
        }
        if (GetExitCodeThread(threads[i], &exit_code))
        {
            if (exit_code == STILL_ACTIVE)
            {
                printf("Thread for IP %s did not complete in time.", ip_addresses[i]);
                results[i] = -1; // Mark as failed
            }
        }
        else
        {
            printf("Failed to get exit code for thread %d.", i);
            results[i] = -1; // Mark as failed
        }
        CloseHandle(threads[i]);
    }

    free(threads);
    free(pingData);
}
#else

void *PingThreadOnLinux(void *arg)
{
    PingData *pingData = (PingData *)arg;
    const char *ip_address = pingData->ip_address;

    /*  linux ping 命令参数
        -w timeout：指定总的超时时间，单位是秒，即多少秒后退出，与windows上存在差异
        -c count：指定发送的请求数
    */
    int REQUEST_TOTAL_TIMEOUT_LINUX = (SINGLE_REQUEST_TIMEOUT / 1000) * REQUEST_COUNT; // （ms --> s） * （单个请求等待时间）
    char command[100];
    snprintf(command, sizeof(command), "ping -w %d -c %d %s >/dev/null 2>&1", REQUEST_TOTAL_TIMEOUT_LINUX, REQUEST_COUNT, ip_address);
    // printf("command:%s", command);

    int response = WEXITSTATUS(system(command));

    switch (response)
    {
    case 0:
        // Alive
        *(pingData->result) = 1;
        break;
    case 1:   // For Unix, 1 indicates unreachable
    case 2:   // For Unix, 2 indicates unknown host
    case 256: // For some Unix systems, 256 indicates unreachable
    default:
        // Unreachable, unknown host, or other errors
        *(pingData->result) = -1;
        break;
    }
    pthread_mutex_lock(&pingData->mutex);
    pingData->finished = 1;
    pthread_cond_signal(&pingData->cond);
    pthread_mutex_unlock(&pingData->mutex);

    return NULL;
}

void ping_multiple_ips_on_unix(const char **ip_addresses, int *results, int num_ips)
{
    PingData *pingData = (PingData *)malloc(num_ips * sizeof(PingData));
    if (pingData == NULL)
    {
        printf("Memory allocation failed");
        return;
    }

    for (int i = 0; i < num_ips; i++)
    {
        pingData[i].ip_address = ip_addresses[i];
        pingData[i].result = &results[i];
        pingData[i].finished = 0;
        pthread_mutex_init(&pingData[i].mutex, NULL);
        pthread_cond_init(&pingData[i].cond, NULL);

        if (pthread_create(&pingData[i].thread_id, NULL, PingThreadOnLinux, &pingData[i]) == ETIMEDOUT)
        {
            printf("pthread_create");
            results[i] = -1; // Mark as failed if thread creation fails
        }
    }

    struct timespec end_tm;
    clock_gettime(CLOCK_REALTIME, &end_tm);
    end_tm.tv_sec += (MAX_TIMEOUT / 1000);

    for (int i = 0; i < num_ips; i++)
    {
        pthread_mutex_lock(&pingData[i].mutex);
        while (!pingData[i].finished)
        {
            int res = pthread_cond_timedwait(&pingData[i].cond, &pingData[i].mutex, &end_tm);
            if (res != 0)
            {
                if (res == ETIMEDOUT)
                {
                    printf("Timeout waiting for thread %d", i);
                }
                else
                {
                    printf("Error waiting for thread %d: %s", i, strerror(res));
                }
                results[i] = -1;
                break;
            }
        }
        pthread_mutex_unlock(&pingData[i].mutex);

        pthread_mutex_destroy(&pingData[i].mutex);
        pthread_cond_destroy(&pingData[i].cond);
    }

    for (int i = 0; i < num_ips; i++)
    {
        pthread_join(pingData[i].thread_id, NULL);
    }
    free(pingData);
}
#endif
