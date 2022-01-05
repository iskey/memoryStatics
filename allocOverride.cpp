//
// Created by iskey on 2021/12/17.
//

#include "memStatistics.h"
#include <dlfcn.h>
#include <sys/mman.h>
#include <iostream>
#include <new>
#include <thread>
#include <atomic>

#define SRVFS_MEMORY_OVERRIDE

#define CONCAT_INNER(a, b) a ## b
#define CONCAT(a, b) CONCAT_INNER(a, b)
#define REL_FUNC_T(x) CONCAT(real_t_, x)
#define REL_FUNC(x) CONCAT(real_, x)

#define FUNC_X(func, ret, params)\
using REL_FUNC_T(func) = ret (*) params;    \
ret func params

#define FUNC_C_X(func, ret, params)\
using REL_FUNC_T(func) = ret (*) params;    \
extern "C" ret func params

#define LIBC_FUNC(func) __libc_ ## func

#define DECLARE_REAL_SYMBOL_NEXT(symbol)    \
    static REL_FUNC_T(symbol) REL_FUNC(symbol) = nullptr;   \
    if(REL_FUNC(symbol) == nullptr) {   \
        REL_FUNC(symbol) = (REL_FUNC_T(symbol))dlsym(RTLD_NEXT, #symbol);  \
    }

#define DECLARE_REAL_SYMBOL(lib, symbol)    \
    static void *handle = nullptr;  \
    static REL_FUNC_T(symbol) REL_FUNC(symbol) = nullptr;   \
    if (REL_FUNC(symbol) == nullptr) {  \
        handle = dlopen(#lib, RTLD_LAZY);    \
        if (handle) {   \
            REL_FUNC(symbol) = (REL_FUNC_T(symbol))dlsym(handle, #symbol);    \
        }   \
    }

#define ADD_TO_MEM_STATISTICS(addr, size) \
{   \
    if (MemIst.m_statistics_running && !MemStatistics::sm_statistics_locking) {    \
        MemIst.addMemNode(addr, size);  \
    }   \
}

#define REMOVE_FROM_MEM_STATISTICS(addr) \
{ \
    if (MemIst.m_statistics_running && !MemStatistics::sm_statistics_locking) {    \
        MemIst.removeMemNode(addr); \
    }   \
}

#define REMOVE_FROM_MEM_STATISTICS_ALL(addr) \
{ \
    int ret;\
    if (MemIst.m_statistics_running && !MemStatistics::sm_statistics_locking) {    \
        do {    \
            ret = MemIst.removeMemNode(addr); \
        } while(ret == 0);\
    }   \
}

// 使用弱符号方便获取实际符号
extern "C" void *__libc_malloc(size_t size) __attribute__((weak));
extern "C" void __libc_free(void *ptr) __attribute__((weak));
extern "C" void *__libc_realloc(void *ptr, size_t size) __attribute__((weak));
extern "C" void *__libc_calloc(size_t nmemb, size_t size) __attribute__((weak));

namespace {
    std::once_flag g_init_mem_statistics;
}

FUNC_C_X(malloc, void *, (size_t size))
{
    void *ptr;

    ptr = LIBC_FUNC(malloc)(size);

    ADD_TO_MEM_STATISTICS(ptr, size);

    std::call_once(g_init_mem_statistics, MemStatistics::initMemStatistics, HASH_BUCKET_SIZE);

    return ptr;
}

FUNC_C_X(free, void, (void *ptr))
{
    LIBC_FUNC(free)(ptr);

    REMOVE_FROM_MEM_STATISTICS(ptr);
}

FUNC_C_X(realloc, void *, (void *ptr, size_t size))
{
    void *new_ptr;

    new_ptr = LIBC_FUNC(realloc)(ptr, size);

    if(new_ptr != nullptr) {
        REMOVE_FROM_MEM_STATISTICS(ptr);
        ADD_TO_MEM_STATISTICS(new_ptr, size);
    } else {
        REMOVE_FROM_MEM_STATISTICS(ptr);
        ADD_TO_MEM_STATISTICS(ptr, size);
    }

    return new_ptr;
}

FUNC_C_X(calloc, void *, (size_t nmemb, size_t size))
{
    void *new_ptr;

    new_ptr = LIBC_FUNC(calloc)(nmemb, size);

    ADD_TO_MEM_STATISTICS(new_ptr, size * nmemb);

    return new_ptr;
}

void *operator new(size_t size)
{
    void *ptr;

    ptr = LIBC_FUNC(malloc)(size);

    ADD_TO_MEM_STATISTICS(ptr, size);

    return ptr;
}

void *operator new[](size_t size)
{
    void *ptr;

    ptr = LIBC_FUNC(malloc)(size);

    ADD_TO_MEM_STATISTICS(ptr, size);

    return ptr;
}

void* operator new(std::size_t count, const std::nothrow_t& tag)
{
    void *ptr;

    ptr = LIBC_FUNC(malloc)(count);

    ADD_TO_MEM_STATISTICS(ptr, count);

    return ptr;
}

void* operator new[](std::size_t count, const std::nothrow_t& tag)
{
    void *ptr;

    ptr = LIBC_FUNC(malloc)(count);

    ADD_TO_MEM_STATISTICS(ptr, count);

    return ptr;
}

#if (__cplusplus >= 201703L)
void* operator new(std::size_t n, std::align_val_t align)
{
    return nullptr;
}
#error "Not support Now."
#endif


void operator delete(void *ptr)
{
    LIBC_FUNC(free)(ptr);

    REMOVE_FROM_MEM_STATISTICS(ptr);
}

void operator delete[](void *ptr)
{
    LIBC_FUNC(free)(ptr);

    REMOVE_FROM_MEM_STATISTICS(ptr);
}

// Posix
FUNC_C_X(posix_memalign, int, (void** p, size_t alignment, size_t size))
{
    int ret;
    DECLARE_REAL_SYMBOL_NEXT(posix_memalign);
    ret = REL_FUNC(posix_memalign)(p, alignment, size);

    ADD_TO_MEM_STATISTICS(*p, size);

    return ret;
}

// Linux
FUNC_C_X(memalign, void *, (size_t alignment, size_t size))
{
    void *ptr;
    DECLARE_REAL_SYMBOL_NEXT(memalign);
    ptr = REL_FUNC(memalign)(alignment, size);

    ADD_TO_MEM_STATISTICS(ptr, size);

    return ptr;
}

FUNC_C_X(aligned_alloc, void *, (size_t alignment, size_t size))
{
    void *ptr;
    DECLARE_REAL_SYMBOL_NEXT(memalign);
    ptr = REL_FUNC(memalign)(alignment, size);

    ADD_TO_MEM_STATISTICS(ptr, size);

    return ptr;
}

FUNC_C_X(valloc, void *, (size_t size))
{
    void *ptr;
    DECLARE_REAL_SYMBOL_NEXT(valloc);
    ptr = REL_FUNC(valloc)(size);

    ADD_TO_MEM_STATISTICS(ptr, size);

    return ptr;
}

FUNC_C_X(pvalloc, void *, (size_t size))
{
    void *ptr;
    DECLARE_REAL_SYMBOL_NEXT(pvalloc);
    ptr = REL_FUNC(pvalloc)(size);

    ADD_TO_MEM_STATISTICS(ptr, size);

    return ptr;
}

#ifdef SRVFS_MEMORY_OVERRIDE
struct pool;
// ***************** For libsrvfs
FUNC_C_X(pcreate, pool *, (size_t page_size))
{
    pool *new_pool;
    DECLARE_REAL_SYMBOL(libunkown.so, pcreate);

    new_pool = REL_FUNC(pcreate)(page_size);

    return new_pool;
}

FUNC_C_X(pdestroy, void, (struct pool *pool_s))
{
    DECLARE_REAL_SYMBOL(libunkown.so, pdestroy);

    REL_FUNC(pdestroy)(pool_s);

    REMOVE_FROM_MEM_STATISTICS_ALL(pool_s);
}

FUNC_C_X(pcalloc, void *, (struct pool *pool_s, size_t size))
{
    void *ptr;
    DECLARE_REAL_SYMBOL(libunkown.so, pcalloc);

    ptr = REL_FUNC(pcalloc)(pool_s, size);

    ADD_TO_MEM_STATISTICS(pool_s, size);

    return ptr;
}

FUNC_C_X(palloc, void *, (struct pool *pool_s, size_t size))
{
    void *ptr;
    DECLARE_REAL_SYMBOL(libunkown.so, palloc);

    ptr = REL_FUNC(palloc)(pool_s, size);

    ADD_TO_MEM_STATISTICS(pool_s, size);

    return ptr;
}

FUNC_C_X(pnalloc, void *, (const struct pool *pool_s, size_t size))
{
    void *ptr;
    DECLARE_REAL_SYMBOL(libunkown.so, pnalloc);

    ptr = REL_FUNC(pnalloc)(pool_s, size);

    ADD_TO_MEM_STATISTICS((void *)pool_s, size);

    return ptr;
}

FUNC_C_X(pncalloc, void *, (struct pool *pool_s, size_t size))
{
    void *ptr;
    DECLARE_REAL_SYMBOL(libunkown.so, pncalloc);

    ptr = REL_FUNC(pncalloc)(pool_s, size);

    ADD_TO_MEM_STATISTICS(pool_s, size);

    return ptr;
}

FUNC_C_X(mmap, void *, (void *addr, size_t length, int prot, int flags, int fd, off_t offset))
{
    void *ptr = nullptr;
    DECLARE_REAL_SYMBOL_NEXT(mmap);

    ptr = REL_FUNC(mmap)(addr, length, prot, flags, fd, offset);
    if (ptr == (void *)(-1)) {
        return nullptr;
    }

    ADD_TO_MEM_STATISTICS(ptr, length);

    return ptr;
}

FUNC_C_X(munmap, int, (void *addr, size_t length))
{
    int ret;
    DECLARE_REAL_SYMBOL_NEXT(munmap);

    ret = REL_FUNC(munmap)(addr, length);

    REMOVE_FROM_MEM_STATISTICS(addr);

    return ret;
}

#endif
