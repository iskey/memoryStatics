//
// Created by iskey on 2021/12/17.
//

#ifndef BIN_REPOS_MEMSTATICS_H
#define BIN_REPOS_MEMSTATICS_H

#include "stdint.h"
#include "stddef.h"
#include <functional>
#include <mutex>
#include <thread>
#include "imap.h"

#define TRACE_BACKTRACE

namespace {
    const char *DUMP_LOG_FILE = "/usr/alg_model/mem_dump.log";
    const uint8_t STACK_DEPTH = 30;
    const uint32_t HASH_BUCKET_SIZE = 3000;
}

struct mem_node {
    uint32_t seq;
    void* addr;
    uint32_t size;
    pid_t tid;
    uint8_t stack_cnt;
    void* stack[STACK_DEPTH];
    time_t time_stamp;
};

class MemStatistics {
public:
    explicit MemStatistics(size_t size);
    ~MemStatistics();

    /************ static area **************/
    static MemStatistics &get();
    static void initMemStatistics(size_t size);

    // whether statistics is running
    static bool m_statistics_running;

    [[noreturn]] // Process Command
    void procCmd() ;

    // 添加内存分配节点
    void addMemNode(void* addr, size_t size);

    // 删除内存分配节点
    int removeMemNode(void *addr);

    // 清空所有记录
    void clearAllMemNodes();

    // 打印内存分配节点
    void dumpMemNodes();

    // 内存节点处理函数
    void procMemNode(void *data);

    bool m_dump_once;
    bool m_debug_flag;
    // 增量打印模式
    bool m_append_modle;
    // malloc trim
    bool m_malloc_trim_once;
    bool m_thread_running_flag;

    static int m_log_fd;
    static int m_malloc_status_fd;
    static void *m_malloc_info_fd;

    // 是否正在进行统计工作
    static thread_local bool sm_statistics_locking;
    // 线程号
    static thread_local pid_t thread_id;

private:
    std::thread m_thread;

    // 初始化标识
    bool m_init_flag;
    // 全局序号，用于跟踪每次输出之间的增量标识
    uint32_t m_seq;

    uint64_t m_allocatedMemSize;
    uint64_t m_activeMemSize;
    uint64_t m_activeMemCnt;
    uint64_t m_appendMemSize;
    uint64_t m_appendMemCnt;
    uint64_t m_peakActiveMemSize;
    IMap m_addr_map;

    // static area
    static MemStatistics *m_memStatistics;
};

#define MemIst MemStatistics::get()

#endif //BIN_REPOS_MEMSTATICS_H
