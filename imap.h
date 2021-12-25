//
// Created by iskey on 2021/4/20.
//
#include "stdint.h"
#include "stddef.h"
#include <mutex>
#include <functional>

#ifndef BIN_REPOS_IMAP_H
#define BIN_REPOS_IMAP_H

#define ALLOW_CACHE_NODES

struct list_node;

namespace {
    const uint32_t g_mutex_cnt = 30;
}

using dumpDataFunc = std::function<void(void *data)> ;

class IMap {
public:
    explicit IMap(size_t size);
    ~IMap() = default;

    // insert to map.
    int insert(uintptr_t key, void *data);
    // remove from map with key.
    int remove(uintptr_t key);
    // clear the map.
    int clear();

    // dump the map. will call function of reg_dump_func
    void dump();

    void reg_dump_func(dumpDataFunc dumpFunc);

    static void *i_alloc(size_t size);
    static void i_free(void *ptr);

private:
    uint32_t hashKey(uintptr_t key) const;
    static uint32_t hash(uintptr_t key);
    static void *i_alloc_node(size_t size);
    void i_free_node(struct list_node *node);
    static thread_local struct list_node m_free_node_list;

    dumpDataFunc m_dumpDataFunc;
    pthread_mutex_t m_mutex[g_mutex_cnt]{};
    int initHash(size_t size);
    struct list_node *m_hash_map = nullptr;
    size_t m_hash_map_size = 0;
};

#endif // BIN_REPOS_IMAP_H
