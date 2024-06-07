#ifndef SERVE_H
#define SERVE_H
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

#include <dirent.h>
#include <sys/stat.h>

#include <microhttpd.h>

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

extern void close_file(struct file_detail *file_detail);
extern bool open_file(char *filepath, struct file_detail *out, const struct server_config *cls, bool open);
#endif
