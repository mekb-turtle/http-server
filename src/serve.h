#ifndef SERVE_H
#define SERVE_H
#include <stddef.h>
#include <stdbool.h>
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
#endif
