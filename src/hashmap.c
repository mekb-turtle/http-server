#include "hashmap.h"
#include <stdlib.h>

struct hashmap WARN_UNUSED hashmap_create(size_t size,
                                          hashmap_hash_key hash_key, hashmap_compare_key compare_key,
                                          hashmap_free_key free_key, hashmap_free_value free_value) {
	// allocate memory for the map and initialize all buckets to NULL
	struct hashmap map;
	map.size = 0;
	size_t total_size = size * sizeof(struct hashmap_entry *);
	map.buckets = malloc(total_size);
	if (!map.buckets) return map;
	for (size_t i = 0; i < size; i++) {
		map.buckets[i] = NULL;
	}

	map.size = size;
	map.hash_key = hash_key;
	map.compare_key = compare_key;
	map.free_key = free_key;
	map.free_value = free_value;
	return map;
}

static void free_entry_kv(struct hashmap_entry *entry, struct hashmap *map) {
	if (!entry) return;
	// free key and value
	if (entry->key && map->free_key) map->free_key(entry->key);
	if (entry->value && map->free_value) map->free_value(entry->value);
	entry->key = NULL;
	entry->value = NULL;
}

static void free_entry(struct hashmap_entry *entry, struct hashmap *map) {
	if (!entry) return;
	free_entry_kv(entry, map);
	// free the entry
	free(entry);
}

void hashmap_free(struct hashmap *map) {
	if (!map) return;
	if (!map->buckets) return;
	// free all entries
	for (size_t i = 0; i < map->size; i++) {
		struct hashmap_entry *entry = map->buckets[i];
		while (entry) {
			struct hashmap_entry *next = entry->next;
			free_entry(entry, map);
			entry = next;
		}
	}
	// free buckets
	free(map->buckets);
}

static size_t internal_get_bucket_index(struct hashmap *map, void *key) {
	return map->hash_key(key) % map->size;
}

struct hashmap_entry *WARN_UNUSED hashmap_set(struct hashmap *map, void *key, void *value) {
	// get the bucket for the key, then iterate over the linked list to find the key
	size_t bucket_index = internal_get_bucket_index(map, key);
	struct hashmap_entry *entry = map->buckets[bucket_index];
	while (entry) {
		if (map->compare_key(entry->key, key)) {
			// free old key and value
			free_entry_kv(entry, map);
			// set the new key and value
			entry->key = key;
			entry->value = value;
			return entry;
		}
		if (!entry->next) break; // stop before we set entry to NULL
		entry = entry->next;
	}

	// if the key was not found, create a new entry
	struct hashmap_entry *new_entry = malloc(sizeof(struct hashmap_entry));
	if (!new_entry) return NULL;
	if (entry) {
		// update the previous entry's next pointer
		entry->next = new_entry;
	} else {
		// update the head entry's next pointer
		map->buckets[bucket_index] = new_entry;
	}
	// set the new key and value
	new_entry->key = key;
	new_entry->value = value;
	new_entry->next = NULL;
	return new_entry;
}

bool hashmap_remove(struct hashmap *map, void *key) {
	// get the bucket for the key, then iterate over the linked list to find the key
	size_t bucket_index = internal_get_bucket_index(map, key);
	struct hashmap_entry *head = map->buckets[bucket_index];
	struct hashmap_entry *entry = head, *prev = head;
	for (; entry; prev = entry, entry = entry->next) {
		// if the key was found, remove the entry
		if (map->compare_key(entry->key, key)) {
			if (head == entry) {
				// update the head entry's next pointer
				map->buckets[bucket_index] = entry->next;
			} else {
				// update the previous entry's next pointer
				prev->next = entry->next;
			}
			free_entry(entry, map);
			return true;
		}
	}
	return false;
}

struct hashmap_entry *WARN_UNUSED hashmap_get(struct hashmap *map, void *key) {
	// get the bucket for the key, then iterate over the linked list to find the key
	struct hashmap_entry *entry = map->buckets[internal_get_bucket_index(map, key)];
	for (; entry; entry = entry->next) {
		if (map->compare_key(entry->key, key)) return entry;
	}
	return NULL;
}

void hashmap_loop(struct hashmap *map, bool (*callback)(void *key, void *value)) {
	// iterate over all buckets and entries, calling the callback for each entry
	for (size_t i = 0; i < map->size; i++) {
		struct hashmap_entry *entry = map->buckets[i];
		for (; entry; entry = entry->next) {
			if (!callback(entry->key, entry->value)) return;
		}
	}
}
