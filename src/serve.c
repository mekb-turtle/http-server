#include "serve.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>

#include <dirent.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <cjson/cJSON.h>
#include "util.h"
#include "format_bytes.h"

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

#ifdef _WIN32
#define PATH_SEPARATOR '\\'
#else
#define PATH_SEPARATOR '/'
#endif

static char *sockaddr_to_string(struct sockaddr *addr) {
	if (addr)
		switch (addr->sa_family) {
			case AF_INET: {
				char *ip = malloc(INET_ADDRSTRLEN);
				if (!ip) return NULL;
				inet_ntop(AF_INET, &((struct sockaddr_in *) addr)->sin_addr, ip, INET_ADDRSTRLEN);
				return ip;
			}
			case AF_INET6: {
				char *ip = malloc(INET6_ADDRSTRLEN);
				if (!ip) return NULL;
				inet_ntop(AF_INET6, &((struct sockaddr_in6 *) addr)->sin6_addr, ip, INET6_ADDRSTRLEN);
				return ip;
			}
		}
	return NULL;
}

static enum output_mode {
	OUT_NONE,
	OUT_TEXT,
	OUT_HTML,
	OUT_JSON
} get_output_mode(const char *accept_type) {
	if (accept_type) {
		size_t len = strlen(accept_type);
		if (len <= 1024) {                     // arbitrary limit
			char str[len + 8];                 // copy the string
			str[0] = ',';                      // add a comma to the start
			memcpy(str + 1, accept_type, len); // copy the string

			str[len + 1] = '\0';
			char *semi = strchrnul_(str, ';');
			semi[0] = ',';  // trim off the semicolon and replace it with the comma
			semi[1] = '\0'; // and null terminate

			if (strstr(str, "text/html")) return OUT_HTML;
			else if (strstr(str, "application/json"))
				return OUT_JSON;
		}
	}
	return OUT_TEXT;
}

struct stat_opt {
	struct stat stat;
	DIR *dir;
	FILE *fp;
};

static void close_stat(struct stat_opt *st) {
	if (st->dir) {
		closedir(st->dir);
		st->dir = NULL;
	}
	if (st->fp) {
		fclose(st->fp);
		st->fp = NULL;
	}
}

static bool stat_file(
        char *filepath,
        struct stat_opt *out,
        struct httpd_data *cls,
        bool open) {
start_stat_file:
	close_stat(out);

	// lstat to prevent symlink traversal
	if (lstat(filepath, &out->stat) != 0) {
		// file not found
		return false;
	}

	switch (out->stat.st_mode & S_IFMT) {
		case S_IFDIR:
			out->dir = opendir(filepath);
			if (!out->dir) {
				if (!cls->quiet)
					eprintf("Failed to open directory: %s: %s\n", filepath, strerror(errno));
				goto no_file;
			}
			break;
		case S_IFLNK:
			if (!cls->follow_symlinks) goto no_file; // symlink not allowed
			// follow symlink
			char filepath_[PATH_MAX];
			if (!realpath(filepath, filepath_)) {
				if (!cls->quiet)
					eprintf("Invalid symlink path: %s: %s\n", filepath_, strerror(errno));
				goto no_file;
			}
			memcpy(filepath, filepath_, PATH_MAX);
			goto start_stat_file; // repeat the check for the target
		case S_IFREG:             // regular file
			// TODO: caching
			out->fp = fopen(filepath, "rb");
			if (!out->fp) {
				if (!cls->quiet)
					eprintf("Failed to open file: %s: %s\n", filepath, strerror(errno));
				goto no_file;
			}
			break;
		default:
			// unsupported file type
			goto no_file;
	}
	if (!open) close_stat(out);
	return true;
no_file:
	return false;
}

enum MHD_Result answer_to_connection(void *cls_, struct MHD_Connection *connection,
                                     const char *url,
                                     const char *method, const char *version,
                                     const char *upload_data,
                                     size_t *upload_data_size, void **req_cls) {
	void *data = NULL;                                                     // response data
	enum MHD_ResponseMemoryMode data_memory_mode = MHD_RESPMEM_PERSISTENT; // what mhd should do with the data
	size_t size;                                                           // size of the response data
	unsigned int status = MHD_HTTP_OK;                                     // response status
	char *content_type = NULL;                                             // response content type
	cJSON *root = cJSON_CreateObject();                                    // for responding with JSON data
	char *result_file = NULL;                                              // used for logging
	bool not_found = false;

	// get accept content type
	const char *accept_type = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_ACCEPT);
	enum output_mode output_mode = get_output_mode(accept_type); // response content type enum

	struct httpd_data *cls = (struct httpd_data *) cls_;

	if (strcmp(method, MHD_HTTP_METHOD_GET) != 0) {
		status = MHD_HTTP_METHOD_NOT_ALLOWED;
		goto respond;
	}

	// validate url
	if (url[0] != '/') goto bad_request;
#ifdef _WIN32
	if (strpbrk(url, "\\:*?\"<>|")) goto not_found;
#endif

	char filepath[PATH_MAX]; // full path to file
	strcpy(filepath, cls->base_file);
	struct stat_opt st = {.dir = NULL, .fp = NULL};
	const char *urlpath = url;
	bool first = false, is_file = false;

	while (true) {
		if (first) {                           // allow filepath to be resolved for initial base directory
			while (*urlpath == '/') urlpath++; // skip leading slashes
			if (*urlpath == '\0') break;       // check for end of path
			if (is_file) goto not_found;       // file cannot have subdirectories

			const char *slash = strchrnul_(urlpath, '/'); // find next slash (or end of string)
			size_t segment_len = slash - urlpath;         // length of the path segment
			if (strncmp(urlpath, ".", segment_len) == 0) goto bad_request;
			if (strncmp(urlpath, "..", segment_len) == 0) goto bad_request;

			if (*urlpath == '.' && cls->dotfiles) goto not_found; // dotfiles not allowed

			size_t filepath_len = strlen(filepath);
			if (filepath_len + segment_len + 1 >= PATH_MAX) { // path too long
				status = MHD_HTTP_URI_TOO_LONG;
				goto respond;
			}

			// append path segment to filepath
			filepath[filepath_len] = PATH_SEPARATOR;
			filepath[filepath_len + 1] = '\0'; // null terminate
			strncat(filepath, urlpath, segment_len);

			// skip to the next segment
			urlpath = slash;
		} else
			first = true;

		// resolve the file
		if (!stat_file(filepath, &st, cls, true)) goto not_found;
	}

serve_file:
	if (st.fp) {
		//TODO
		result_file = filepath;
		output_mode = OUT_NONE;
		data = "test";
		size = 4;
		goto respond;
	} else if (st.dir) {
		if (!cls->list_directories) goto not_found; // directory listing not allowed
		result_file = filepath;
		cJSON *dir_array;
		if (output_mode == OUT_JSON) {
			dir_array = cJSON_CreateArray();
			cJSON_AddItemToObject(root, "children", dir_array);
		}

		struct dirent *entry;
		while ((entry = readdir(st.dir))) {
			printf("%s\n", entry->d_name);
			if (entry->d_name[0] == '.') {
				if (cls->dotfiles) continue;                                       // skip dotfiles
				if (entry->d_name[1] == '\0') continue;                            // skip "."
				if (entry->d_name[1] == '.' && entry->d_name[2] == '\0') continue; // skip ".."
			}

			if (!stat_file(cls->not_found_file, &st, cls, false)) continue; // skip if cannot open file

			switch (output_mode) {
				case OUT_NONE:
					break;
				case OUT_TEXT:
					break;
				case OUT_HTML:
					break;
				case OUT_JSON:;
					cJSON *dir_obj = cJSON_CreateObject();
					cJSON_AddStringToObject(dir_obj, "name", entry->d_name);
					cJSON_AddItemToArray(dir_array, dir_obj);
					break;
			}
		}
		close_stat(&st);
		goto respond;
	}
	goto not_found; // unsupported file typ

not_found:
	close_stat(&st);
	status = MHD_HTTP_NOT_FOUND;
	if (cls->not_found_file && !not_found) {
		// resolve the file
		if (!stat_file(cls->not_found_file, &st, cls, true)) goto not_found;
		goto serve_file;
	}
	goto respond;
bad_request:
	status = MHD_HTTP_BAD_REQUEST;
	goto respond;
respond:;
	close_stat(&st);
	struct MHD_Response *response;

	if (!data) { // if there is no data to respond with
		if (output_mode == OUT_JSON) {
			// set status code in JSON
			cJSON_AddNumberToObject(root, "status", status);

			// encode JSON data and respond with it
			char *json = cJSON_Print(root);
			data = json;
			size = strlen(json);
			data_memory_mode = MHD_RESPMEM_MUST_FREE; // free the data after responding
		} else {
			// respond with an empty response
			output_mode = OUT_NONE;
			size = 0;
		}
	}

	if (!content_type) {
		// set content type accordingly
		switch (output_mode) {
			case OUT_NONE:
				break;
			case OUT_TEXT:
				content_type = "text/plain";
				break;
			case OUT_HTML:
				content_type = "text/html";
				break;
			case OUT_JSON:
				content_type = "application/json";
				break;
		}
	}

	int ret;
	response = MHD_create_response_from_buffer(size, data, data_memory_mode);
	MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, content_type);
	ret = MHD_queue_response(connection, status, response);
	MHD_destroy_response(response);

	if (!cls->quiet) {
		struct sockaddr *addr = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;
		char *ip = sockaddr_to_string(addr);
		char *size_str = format_bytes(size, binary_i);
		// log the request and response
		printf(
		        "Request: %s%s%s %s\n"
		        "Response: %i, %s%s%s%s%s\n",
		        ip ? ip : "", ip ? ", " : "",
		        method, url,
		        status,
		        content_type ? content_type : "", content_type ? ", " : "",
		        result_file ? result_file : "", result_file ? ", " : "",
		        size_str);
		// all in one printf call to prevent interleaving of output from multiple threads
		free(ip);
		free(size_str);
	}
	cJSON_Delete(root);
	return ret;
}
