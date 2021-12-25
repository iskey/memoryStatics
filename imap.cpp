//
// Created by iskey on 2021/4/20.
//

#include "imap.h"
#include "stdlib.h"
#include <iostream>
#include <utility>
#include "stddef.h"
#include <dlfcn.h>

struct list_node{
    uintptr_t key;
    void *data;

    struct list_node *pre;
    struct list_node *next;
};

extern "C" void *__libc_malloc(size_t size) __attribute__((weak));
extern "C" void __libc_free(void *ptr) __attribute__((weak));

using hash_malloc_t = void *(*)(size_t size);
inline void* hash_malloc(int size)
{
    return __libc_malloc(size);
}

using hash_free_t = void *(*)(void* addr);
inline void hash_free(void* addr)
{
    __libc_free(addr);
}

thread_local struct list_node IMap::m_free_node_list{};

IMap::IMap(size_t size): m_dumpDataFunc(nullptr)
{
    initHash(size);

    for(auto item: m_mutex) {
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutex_init(&item, &attr);
        pthread_mutexattr_destroy(&attr);
    }
}

#include <string.h>
int IMap::initHash(size_t size) {
    if(m_hash_map != nullptr) {
        return 0;
    }

    // 向上取g_mutex_cnt的整数倍
    size_t real_size = g_mutex_cnt * ((size + g_mutex_cnt - 1)/g_mutex_cnt);
    m_hash_map = static_cast<struct list_node*>(hash_malloc(real_size * sizeof(list_node) + 1));
    memset((void*)m_hash_map, 0, real_size * sizeof(list_node) + 1);
    m_hash_map_size = real_size;

    return 0;
}


uint32_t IMap::hash(uintptr_t key)
{
    key = (~key) + (key << 18); // key = (key << 18) - key - 1;
    key = key ^ (key >> 31);
    // key = key * 21; // key = (key + (key << 2)) + (key << 4);
    key = (key + (key << 2)) + (key << 4);
    key = key ^ (key >> 11);
    key = key + (key << 6);
    key = key ^ (key >> 22);
    return (uint32_t) key;
}

uint32_t IMap::hashKey(uintptr_t key) const
{
    return hash((uintptr_t)key) % m_hash_map_size;
}

void *IMap::i_alloc(size_t size)
{
    return hash_malloc(size);
}

void *IMap::i_alloc_node(size_t size)
{
#ifdef ALLOW_CACHE_NODES
    if (m_free_node_list.next != nullptr) {
        void *ret = m_free_node_list.next;
        m_free_node_list.next = m_free_node_list.next->next;
        return ret;
    } else {
#endif
        return hash_malloc(size * sizeof(struct list_node));
#ifdef ALLOW_CACHE_NODES
    }
#endif
}


void IMap::i_free_node(struct list_node *node)
{
#ifdef ALLOW_CACHE_NODES
    node->next = m_free_node_list.next;
    m_free_node_list.next = node;
#else
    hash_free((void*)node);
#endif
}

void IMap::i_free(void *ptr)
{
    hash_free(ptr);
}


int IMap::insert(uintptr_t key, void *data)
{
    if(m_hash_map == nullptr || data == nullptr) {
        return -1;
    }

    auto *node = (struct list_node *)i_alloc_node(1);

    node->key = key;
    node->data = data;

    uint32_t hash_key = hashKey(key);

    pthread_mutex_lock(&m_mutex[hash_key % g_mutex_cnt]);
    node->next = m_hash_map[hash_key].next;
    node->pre = &m_hash_map[hash_key];
    if (m_hash_map[hash_key].next != nullptr) {
        m_hash_map[hash_key].next->pre = node;
    }

    m_hash_map[hash_key].next = node;
    pthread_mutex_unlock(&m_mutex[hash_key % g_mutex_cnt]);

    return 0;
}
#include <inttypes.h>
int IMap::remove(uintptr_t key)
{
    static uint64_t cnt = 0;
    if(m_hash_map == nullptr) {
        return -1;
    }

    uint32_t hash_key = hashKey(key);

    pthread_mutex_lock(&m_mutex[hash_key % g_mutex_cnt]);
    struct list_node *node = m_hash_map[hash_key].next;
    while(node != nullptr) {
//        printf("%" PRIu64 "\n", cnt++);
        if(node->key == key) {
            if(node->next != nullptr) {
                node->next->pre = node->pre;
            }
            if(node->pre != nullptr) {
                node->pre->next = node->next;
            }

            i_free(node->data);
            node->data = nullptr;
            i_free_node(node);
            node = nullptr;
            pthread_mutex_unlock(&m_mutex[hash_key % g_mutex_cnt]);
            return 0;
        }
        node = node->next;
    }

    pthread_mutex_unlock(&m_mutex[hash_key % g_mutex_cnt]);
    return -1;
}

int IMap::clear()
{
    uint32_t index = 0;
    struct list_node *node;
    struct list_node *node_to_clear;
    for(index = 0; index < m_hash_map_size; index++) {

        pthread_mutex_lock(&m_mutex[index % g_mutex_cnt]);
        node = m_hash_map[index].next;
        while(node != nullptr) {
            node_to_clear = node;
            node = node->next;

            i_free(node_to_clear->data);
            node_to_clear->data = nullptr;
            i_free_node(node_to_clear);
            node_to_clear = nullptr;
        }
        pthread_mutex_unlock(&m_mutex[index % g_mutex_cnt]);
    }

    return -1;
}

void IMap::reg_dump_func(dumpDataFunc dumpFunc)
{
    m_dumpDataFunc = std::move(dumpFunc);
}

void IMap::dump()
{
    uint32_t index = 0;
    struct list_node *node;
    for(index = 0; index < m_hash_map_size; index++) {
        pthread_mutex_lock(&m_mutex[index % g_mutex_cnt]);
        node = m_hash_map[index].next;
        while(node != nullptr) {
            if (m_dumpDataFunc != nullptr) {
//                std::cout << "IKEY " << node->key << std::endl;
                m_dumpDataFunc(node->data);
            }
            node = node->next;
        }
        pthread_mutex_unlock(&m_mutex[index % g_mutex_cnt]);
    }
}
