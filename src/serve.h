#ifndef SERVE_H
#define SERVE_H
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

#include <dirent.h>
#include <sys/stat.h>

#include <microhttpd.h>
#include <cjson/cJSON.h>

#ifdef __GNUC__
#define WARN_UNUSED __attribute__((warn_unused_result))
#else
#define WARN_UNUSED
#endif

struct server_config {
	char *base_file;
	char *not_found_file;
	bool dotfiles;
	bool follow_symlinks;
	bool list_directories;
	bool quiet;
	bool show_server_info;
};

extern enum MHD_Result answer_to_connection(void *cls, struct MHD_Connection *connection,
                                            const char *url,
                                            const char *method, const char *version,
                                            const char *upload_data,
                                            size_t *upload_data_size, void **req_cls);

struct file_detail {
	struct stat stat;
	DIR *dir;
	FILE *fp;
};

#include "file_cache.h"

extern bool valid_filename_n(const char *name, size_t len, const struct server_config *cls);
extern bool valid_filename(const char *name, const struct server_config *cls);

extern void close_file(struct file_detail *file_detail);
extern bool open_file(char *filepath, struct file_detail *out, const struct server_config *cls, bool open);

extern bool cjson_add_file_details(cJSON *obj, struct file_detail st, char *url, char *name, struct file_cache_item *file_data);

extern bool WARN_UNUSED construct_html_head(char **base);
extern bool WARN_UNUSED construct_html_body(char **base, char *title_class);
extern bool WARN_UNUSED construct_html_main(char **base);
extern bool WARN_UNUSED construct_html_end(char **base);
#define TITLE_START "<title>"
#define TITLE_END "</title>"

struct output_data {
	union {
		void *data;
		char *text;
	};
	enum MHD_ResponseMemoryMode data_memory;
	size_t size;
	unsigned int status;
	char *content_type; // derived from response_type or set manually from file
	cJSON *json_root;
	enum response_type {
		OUT_NONE,
		OUT_TEXT,
		OUT_HTML,
		OUT_JSON
	} response_type;
};

struct input_data {
	struct file_detail file;
	char *url;
	char *url_parent;
	char *filepath;
	char *filepath_parent;
	bool is_root_url;
	bool is_download;
};

enum serve_result {
	serve_error,
	serve_not_found,
	serve_ok
};

#endif
