#ifndef SERVE_H
#define SERVE_H
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

#include <dirent.h>
#include <sys/stat.h>

#include <microhttpd.h>
#include <cjson/cJSON.h>

#include "macro.h"

typedef const struct server_config {
	char *base_file;
	char *not_found_file;
	bool dotfiles;
	bool follow_symlinks;
	bool list_directories;
	bool quiet;
	bool show_footer;
} *server_config;

extern enum MHD_Result answer_to_connection(void *cls, struct MHD_Connection *connection,
                                            const char *url,
                                            const char *method, const char *version,
                                            const char *upload_data,
                                            size_t *upload_data_size, void **req_cls);

struct file_detail {
	struct stat stat;
	DIR *dir;
	FILE *fp;
	char *filepath;
	struct file_cache_item *cache;
};

#include "file_cache.h"

extern bool valid_filename_n(const char *name, size_t len, server_config cls);
extern bool valid_filename(const char *name, server_config cls);

extern void close_file(struct file_detail *file_detail);
extern bool open_file(
        char *filepath,
        struct file_detail *out,
        server_config cls,
        bool open);

extern size_t get_file_size(struct file_detail file);
extern bool cjson_add_file_details(cJSON *obj, struct file_detail st, char *url, char *name);

struct output_data {
	union {
		void *data;
		char *text;
	};
	enum MHD_ResponseMemoryMode data_memory;
	size_t size;
	unsigned int status;
	const char *content_type; // derived from response_type or set manually from file
	cJSON *json_root;
	struct response_type {
		enum {
			OUT_NONE,
			OUT_TEXT,
			OUT_HTML,
			OUT_JSON
		} type;
		bool explicit;
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
	bool is_found;
};

enum serve_result {
	serve_error,
	serve_not_found,
	serve_ok
};

extern bool has_parent_url(server_config cls, struct input_data *input);

extern bool WARN_UNUSED construct_html_head(server_config cls, struct input_data *input, struct output_data *output);
extern bool WARN_UNUSED construct_html_body(server_config cls, struct input_data *input, struct output_data *output, char *heading_class, char *parent_url_title);
extern bool WARN_UNUSED construct_html_main(server_config cls, struct input_data *input, struct output_data *output);
extern bool WARN_UNUSED construct_html_end(server_config cls, struct input_data *input, struct output_data *output);
#define TITLE_START "<title>"
#define TITLE_END "</title>"

extern bool WARN_UNUSED append_text_footer(server_config cls, struct output_data *output);

#endif
