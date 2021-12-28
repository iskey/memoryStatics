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

#define SaveStackFrames(stack, frame_cnt)\
{\
    int index = backtrace(stack, frame_cnt);\
    for (; index < frame_cnt; index++) {\
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

    while(true){
        if(MemIst.m_thread_running_flag) {
            if (MemIst.m_dump_once) {
                MemIst.m_seq++;
                MemIst.m_dump_once = false;
                MemIst.sm_statistics_locking = true;
                MemIst.dumpMemNodes();
                MemIst.sm_statistics_locking = false;
            }
            if (MemIst.m_malloc_trim_once) {
                MemIst.m_malloc_trim_once = false;
                malloc_trim(0);
            }
        }
        sleep(1);
    }
}

void MemStatistics::procMemNode(void *data)
{
    auto* node = (struct mem_node*)data;
    uint32_t current_seq = MemIst.m_seq - 1;
    tm *local_time = localtime(&node->time_stamp);
#ifdef TRACE_BACKTRACE
    char **symbols = nullptr;
    DumpLog("########################### current seq = %u, node seq = %u, size = %u\n", current_seq, node->seq, node->size);
    if (MemIst.m_append_modle && (node->seq == current_seq)) {
        DumpLog("Node info: tid=%u, current seq = %u, node seq = %u, size = %u, time = %d-%02d %02d:%02d:%02d ",
                node->tid, current_seq, node->seq, node->size, local_time->tm_year + 1900, local_time->tm_mon, local_time->tm_hour, local_time->tm_min, local_time->tm_sec);
        symbols = backtrace_symbols(node->stack, sizeof(node->stack) / sizeof(node->stack[0]));
        for (int index = 1; index < sizeof(node->stack) / sizeof(node->stack[0]); index++) {
            DumpLog(" @Frame-%u: %p %s", index, node->stack[index], symbols[index]);
        }
        if (MemStatistics::m_log_fd != -1) {
            dprintf(MemStatistics::m_log_fd, "\n");
        }
        m_appendMemSize += node->size;
        m_appendMemCnt += 1;
    }
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

    SaveStackFrames(node->stack, sizeof(node->stack) / sizeof(node->stack[0]));

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
