//
// Created by iskey on 2021/12/17.
//

#include "imap.h"
#include "memStatistics.h"
#include <execinfo.h>
#include <functional>
#include <csignal>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#define SaveStackFrames(stack_cnt, stack, stack_size)\
{\
    int index = backtrace(stack, stack_size);\
    stack_cnt = index;  \
    for (; index < stack_size; index++) {\
        stack[index] = nullptr;\
    }\
}

#define DumpLog(fmt, args...)   \
{   \
    if (MemStatistics::m_log_fd != -1) {    \
        dprintf(MemStatistics::m_log_fd, fmt, ##args);\
    } else {    \
        printf(fmt, ##args);   \
    }\
}

// global instance.
MemStatistics * MemStatistics::m_memStatistics = nullptr;
static char g_raw_memStatics[sizeof(MemStatistics)];

int MemStatistics::m_log_fd = -1;
int MemStatistics::m_malloc_status_fd = -1;
void *MemStatistics::m_malloc_info_fd = nullptr;

bool MemStatistics::m_statistics_running = false;
thread_local bool MemStatistics::sm_statistics_locking = false;
thread_local pid_t MemStatistics::thread_id = 0;

extern "C" int malloc_trim(size_t pad) __attribute__((weak));

// signal for command line.
enum SigMemTrace{
    SigMemTrace_start   = 35,
    SigMemTrace_stop    = 36,
    SigMemTrace_clear   = 37,
    SigMemTrace_dump    = 38,
    SigMemTrace_debug   = 39,
    SigMemTrace_append  = 40,
    SigMemTrace_trim    = 41
};

void sigHandler(int sigNum, siginfo_t *siginfo, void *arg)
{
    switch (sigNum) {
        case SigMemTrace_start: {
            void *bt = nullptr;
            backtrace(&bt, 1);
            MemIst.m_statistics_running = true;
            MemIst.m_thread_running_flag = true;
            break;
        }
        case SigMemTrace_stop:
            MemIst.m_statistics_running = false;
            MemIst.m_thread_running_flag = true;
            break;
        case SigMemTrace_dump:
            MemIst.m_dump_once = true;
            break;
        case SigMemTrace_debug:
            MemIst.m_debug_flag = !MemIst.m_debug_flag;
            break;
        case SigMemTrace_append:
            MemIst.m_append_modle = !MemIst.m_append_modle;
            break;
        case SigMemTrace_clear:
            MemIst.clearAllMemNodes();
            break;
        case SigMemTrace_trim:
            MemIst.m_malloc_trim_once = true;
            break;
        default:
            break;
    }
}

void regSigaction()
{
    struct sigaction sigact;

    sigact.sa_sigaction = sigHandler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_SIGINFO,
    sigaction(SigMemTrace_start, &sigact, nullptr);

    sigact.sa_sigaction = sigHandler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_SIGINFO,
    sigaction(SigMemTrace_stop, &sigact, nullptr);

    sigact.sa_sigaction = sigHandler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_SIGINFO,
    sigaction(SigMemTrace_dump, &sigact, nullptr);

    sigact.sa_sigaction = sigHandler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_SIGINFO,
    sigaction(SigMemTrace_debug, &sigact, nullptr);

    sigact.sa_sigaction = sigHandler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_SIGINFO,
    sigaction(SigMemTrace_append, &sigact, nullptr);

    sigact.sa_sigaction = sigHandler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_SIGINFO,
    sigaction(SigMemTrace_trim, &sigact, nullptr);

    sigact.sa_sigaction = sigHandler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_SIGINFO,
    sigaction(SigMemTrace_clear, &sigact, nullptr);
}

extern "C" void malloc_stats(void) __attribute__((weak));
void dump_malloc_stats()
{
    int save_err_fd = -1;

    if(MemIst.m_malloc_status_fd == -1) {
        return;
    }

    ftruncate(MemIst.m_malloc_status_fd, 0);
    save_err_fd = dup(fileno(stderr));
    if (-1 == dup2(MemIst.m_malloc_status_fd, fileno(stderr))) {
        dup2(save_err_fd, fileno(stderr));
        close(save_err_fd);
        return;
    }
    malloc_stats();
    dup2(save_err_fd, fileno(stderr));
    close(save_err_fd);
}

extern "C" int malloc_info(int options, FILE *stream) __attribute__((weak));
void dump_malloc_info()
{
    if(MemIst.m_malloc_info_fd == nullptr) {
        return;
    }

    fseek((FILE*)MemIst.m_malloc_info_fd, 0, 0);
    ftruncate(fileno((FILE*)MemIst.m_malloc_info_fd), 0);

    malloc_info(0, (FILE*)MemIst.m_malloc_info_fd);
}

MemStatistics::MemStatistics(size_t size):
m_dump_once(false),
m_debug_flag(false),
m_append_modle(true),
m_malloc_trim_once(false),
m_thread_running_flag(false),
m_init_flag(false),
m_seq(0),
m_allocatedMemSize(0),
m_activeMemSize(0),
m_activeMemCnt(0),
m_appendMemSize(0),
m_appendMemCnt(0),
m_peakActiveMemSize(0),
m_addr_map(size)
{
    m_addr_map.reg_dump_func(std::bind(&MemStatistics::procMemNode, this, std::placeholders::_1));
}

MemStatistics::~MemStatistics()
{
    m_thread.join();
}

void MemStatistics::initMemStatistics(size_t size)
{
    regSigaction();

    m_memStatistics = reinterpret_cast<MemStatistics *>(g_raw_memStatics);

    new (m_memStatistics)MemStatistics(size);

    MemIst.m_thread = std::thread(&MemStatistics::procCmd, &MemIst);
}

MemStatistics &MemStatistics::get()
{
    return *m_memStatistics;
}

[[noreturn]] void MemStatistics::procCmd()
{
    m_log_fd = open(DUMP_LOG_FILE, O_CREAT | O_RDWR, 600);
    lseek(m_log_fd, 0, SEEK_END);

    m_malloc_info_fd = (void*)fopen("/opt/log/malloc_info", "w+");
    m_malloc_status_fd = open("/opt/log/malloc_stats", O_CREAT | O_RDWR, 600);

    uint64_t counter = 0;

    while(true){
        if(MemIst.m_thread_running_flag) {
            // dump memory statistics.
            if (MemIst.m_dump_once) {
                MemIst.m_seq++;
                MemIst.m_dump_once = false;
                MemIst.sm_statistics_locking = true;
                MemIst.dumpMemNodes();
                MemIst.sm_statistics_locking = false;
            }
            // malloc_trim
            if (MemIst.m_malloc_trim_once) {
                MemIst.m_malloc_trim_once = false;
                malloc_trim(0);
            }
            // dump malloc info.
            if (MemIst.m_debug_flag && counter % 10 == 0) {
                dump_malloc_info();
                dump_malloc_stats();
            }
        }
        sleep(1);
        counter ++;
    }
}

static void localtime_safe(time_t time, long timezone, struct tm *tm_time)
{
    const char Days[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    uint32_t n32_Pass4year;
    uint32_t n32_hpery;

    time = time + (timezone * 60 * 60);

    if (time < 0) {
        time = 0;
    }
    tm_time->tm_sec = (int)(time % 60);
    time /= 60;
    tm_time->tm_min = (int)(time % 60);
    time /= 60;
    n32_Pass4year = ((unsigned int)time / (1461L * 24L));
    tm_time->tm_year = (n32_Pass4year << 2) + 70;
    time %= 1461L * 24L;
    for (;;) {
        n32_hpery = 365 * 24;
        if ((tm_time->tm_year & 3) == 0) {
            n32_hpery += 24;
        }
        if (time < n32_hpery) {
            break;
        }
        tm_time->tm_year++;
        time -= n32_hpery;
    }
    tm_time->tm_hour = (int)(time % 24);
    time /= 24;
    time++;
    if ((tm_time->tm_year & 3) == 0) {
        if (time > 60) {
            time--;
        } else {
            if (time == 60) {
                tm_time->tm_mon = 1;
                tm_time->tm_mday = 29;
                return;
            }
        }
    }
    for (tm_time->tm_mon = 0; Days[tm_time->tm_mon] < time; tm_time->tm_mon++) {
        time -= Days[tm_time->tm_mon];
    }

    tm_time->tm_mday = (int)(time);
    return;
}

void MemStatistics::procMemNode(void *data)
{
    auto* node = (struct mem_node*)data;
    uint32_t current_seq = MemIst.m_seq - 1;
    tm local_time;
    localtime_safe(node->time_stamp, 0, &local_time);
#ifdef TRACE_BACKTRACE
    char **symbols = nullptr;
    DumpLog("###### time=%d-%02d-%02d_%02d:%02d:%02d, tid=%u, current_seq=%u, node_seq=%u, size=%u, addr=%p ",
            local_time.tm_year + 1900, local_time.tm_mon + 1, local_time.tm_mday, local_time.tm_hour, local_time.tm_min, local_time.tm_sec,
            node->tid, current_seq, node->seq, node->size, node->addr);
    if (MemIst.m_append_modle && (node->seq == current_seq)) {
        symbols = backtrace_symbols(node->stack, sizeof(node->stack) / sizeof(node->stack[0]));
        for (int index = 1; index < sizeof(node->stack) / sizeof(node->stack[0]) && index < node->stack_cnt; index++) {
            DumpLog(" @Frame-%u: %s", index, symbols[index]);
        }
        m_appendMemSize += node->size;
        m_appendMemCnt += 1;
    }
    DumpLog("\n");
#endif
    m_activeMemSize += node->size;
    m_activeMemCnt += 1;
#ifdef TRACE_BACKTRACE
    if (symbols != nullptr)
        free(symbols);
#endif
}

void MemStatistics::addMemNode(void* addr, size_t size) {
    auto *node = (mem_node *)IMap::i_alloc(sizeof(mem_node));

    node->addr = addr;
    node->size = size;
    node->seq = MemIst.m_seq;

    // 更新时间戳
    node->time_stamp = time(nullptr);

    // 更新线程ID
    if(MemIst.thread_id == 0) {
        MemIst.thread_id = syscall(SYS_gettid);
    }
    node->tid = MemIst.thread_id;

    SaveStackFrames(node->stack_cnt, node->stack, sizeof(node->stack) / sizeof(node->stack[0]));

    m_addr_map.insert((uintptr_t)addr, node);

    m_allocatedMemSize += size;
}

int MemStatistics::removeMemNode(void *addr)
{
    return m_addr_map.remove((uintptr_t)addr);
}

void MemStatistics::clearAllMemNodes()
{
    m_addr_map.clear();
}

void MemStatistics::dumpMemNodes()
{
    m_activeMemSize = 0;
    m_activeMemCnt = 0;
    m_appendMemSize = 0;
    m_appendMemCnt = 0;
    DumpLog("Memory statistics start >>>>>>>>>> \n");

    m_addr_map.dump();

    DumpLog("Total Append Cnt : %lu\n", m_appendMemCnt);
    DumpLog("Total Append Size : %lu\n", m_appendMemSize);
    DumpLog("Total Activate Cnt : %lu\n", m_activeMemCnt);
    DumpLog("Total Activate Size : %lu\n", m_activeMemSize);
    DumpLog("Total Allocated Size : %lu\n", m_allocatedMemSize);
}
