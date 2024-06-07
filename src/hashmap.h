#include <stdbool.h>
#include <stddef.h>

struct hashmap_entry {
	void *key;
	void *value;
	struct hashmap_entry *next;
};

typedef size_t (*hashmap_hash_key)(void *key);
typedef bool (*hashmap_compare_key)(void *key1, void *key2);
typedef void (*hashmap_free_key)(void *key);
typedef void (*hashmap_free_value)(void *value);

struct hashmap {
	struct hashmap_entry **buckets;
	size_t size;
	hashmap_hash_key hash_key;
	hashmap_compare_key compare_key;
	hashmap_free_key free_key;
	hashmap_free_value free_value;
};

struct hashmap hashmap_create(size_t size,
		hashmap_hash_key hash_key, hashmap_compare_key compare_key,
		hashmap_free_key free_key, hashmap_free_value free_value);
extern void hashmap_free(struct hashmap *map);
extern struct hashmap_entry *hashmap_set(struct hashmap *map, void *key, void *value);
extern bool hashmap_remove(struct hashmap *map, void *key);
extern struct hashmap_entry *hashmap_get(struct hashmap *map, void *key);
extern void hashmap_loop(struct hashmap *map, bool (*callback)(void *key, void *value));
