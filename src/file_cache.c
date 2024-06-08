#include "hashmap.h"
#include "file_cache.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
static bool strcmp_compare(void *key1, void *key2) {
	return strcmp(key1, key2) == 0;
}
static size_t fnv_1a_hash_n(const void *data, size_t len) {
	// FNV-1a hash function
	uint32_t hash = 0x811c9dc5;
	for (size_t i = 0; i < len; i++) {
		hash ^= ((char *) data)[i];
		hash *= 0x01000193;
	}
	return hash;
}
static size_t fnv_1a_hash(void *data) {
	return fnv_1a_hash_n(data, strlen(data));
}
static void free_value(void *value_) {
	struct file_cache_item *value = (struct file_cache_item *) value_;
	free(value->data);
	free(value->mime_type);
	free(value);
}

enum cache_result get_file_cached(char *filepath, struct file_detail *file, struct file_cache_item *out) {
	static struct hashmap *cache_map = NULL;
	if (!cache_map) {
		// initialize the cache map
		static struct hashmap cache_map_;
		cache_map_ = hashmap_create(0x400, fnv_1a_hash, strcmp_compare, free, free_value);
		if (!cache_map_.buckets) return cache_fatal_error;
		cache_map = &cache_map_;
	}
	struct hashmap_entry *entry = hashmap_get(cache_map, filepath);
	if (entry) {
		// TODO: make cache expire after a certain time
		*out = *(struct file_cache_item *) entry->value;
		return cache_hit;
	}

	// TODO: read file into memory
	return cache_miss;
}
