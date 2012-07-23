#include "auto_test.h"

static HashList *new_HashList(const char *key, void *value)
{
    HashList *hl = (HashList *)safe_malloc(sizeof(HashList));
    hl->key = key;
    hl->value = value;
    return hl;
}

/**
 * An implementation of the djb2 hash function by Dan Bernstein.
 */
static unsigned long HashMap_makeHash(const char *_key, unsigned int len)
{
    char *key = (char *)_key;
    unsigned long hash = 5381;
    while (len--) {
        /* hash * 33 + c */
        hash = ((hash << 5) + hash) + *key++;
    }
    return hash;
}

static bool HashMap_existsKey(HashMap *map, const char *key)
{
    unsigned long hash = HashMap_makeHash(key, strlen(key)) % map->table_size;
    HashList *hl = map->hash_table[hash];
    while (hl) {
        if (match(hl->key, key)) {
            return true;
        }
        hl = hl->next;
    }
    return false;
}

static void HashMap_setValue(HashMap *map, const char *key, const char *value)
{
    unsigned long hash = HashMap_makeHash(key, strlen(key)) % map->table_size;
    HashList *hl = new_HashList(key, (void *)value);
    HashList *slot = map->hash_table[hash];
    while (slot) {
        slot = slot->next;
    }
    slot = hl;
}

static const void *HashMap_getValue(HashMap *map, const char *key)
{
    unsigned long hash = HashMap_makeHash(key, strlen(key)) % map->table_size;
    HashList *hl = map->hash_table[hash];
    while (hl) {
        if (match(hl->key, key)) {
            return hl->value;
        }
        hl = hl->next;
    }
    return NULL;
}

static HashMap *new_HashMap(size_t slot_size)
{
    HashMap *map = (HashMap *)safe_malloc(sizeof(HashMap));
    map->hash_table = (HashList **)safe_malloc(sizeof(HashList) * slot_size);
    map->table_size = slot_size;
    map->setValue = HashMap_setValue;
    map->getValue = HashMap_getValue;
    return map;
}
