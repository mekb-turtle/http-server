#include "hashmap.h"
#include "file_cache.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

// for hashmap functions
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
static struct hashmap *cache_map = NULL;

void free_file_cache(void) {
	hashmap_free(cache_map);
	cache_map = NULL;
}

enum cache_result get_file_cached(
        struct file_detail *file,
        bool fetch_new) {
	if (!file) return cache_fatal_error;
	if (!file->filepath) return cache_fatal_error;
	if (file->cache) goto cache_hit;

	if (!cache_map) {
		// initialize the cache map
		static struct hashmap cache_map_;
		cache_map_ = hashmap_create(0x400, fnv_1a_hash, strcmp_compare, free, free_value);
		if (!cache_map_.buckets) return cache_fatal_error;
		cache_map = &cache_map_;
	}
	struct hashmap_entry *entry = hashmap_get(cache_map, file->filepath);
	if (entry) {
		// TODO: make cache expire after a certain time
		file->cache = (struct file_cache_item *) entry->value;
	cache_hit:
		return cache_hit;
	}
	if (!fetch_new) return cache_miss;
	if (!file->fp) return cache_not_a_file;

	// create a new cache entry
	// copy the filepath to avoid dangling pointers
	size_t filepath_len = strlen(file->filepath) + 1;
	char *filepath = malloc(filepath_len);
	if (!filepath) return cache_fatal_error;
	memcpy(filepath, file->filepath, filepath_len);

	struct file_cache_item *cache_item = malloc(sizeof(struct file_cache_item));
	if (!cache_item) {
		free(filepath);
		return cache_fatal_error;
	}

	cache_item->size = file->stat.st_size;
	cache_item->data = malloc(cache_item->size);
	if (!cache_item->data) {
		free(filepath);
		free(cache_item);
		return cache_fatal_error;
	}

	size_t read = fread(cache_item->data, 1, file->stat.st_size, file->fp);
	if (read != file->stat.st_size || ferror(file->fp)) {
	read_error:
		eprintf("Error reading file: %s\n", file->filepath);
		if (read != file->stat.st_size)
			eprintf("Expected: %zu bytes, Read: %zu bytes\n", file->stat.st_size, read);
		else
			eprintf("File has more data than expected\n");
		eprintf("Error: %s, EOF: %s\n",
		        ferror(file->fp) ? "yes" : "no", feof(file->fp) ? "yes" : "no");
		free(filepath);
		free(cache_item->data);
		free(cache_item);
		return cache_fatal_error;
	}

	// check the file is at EOF
	if (fgetc(file->fp) != EOF) goto read_error;

	// TODO: determine if the file is binary (probably by checking for NULL bytes)
	// TODO: determine the MIME type (probably using libmagic)

	cache_item->is_binary = false;
	cache_item->mime_type = NULL;

	if (!hashmap_set(cache_map, filepath, cache_item)) {
		free(filepath);
		free(cache_item->data);
		free(cache_item);
		return cache_fatal_error;
	}

	// TODO: read file into memory
	file->cache = cache_item;
	return cache_miss;
}
