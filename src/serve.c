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

struct file_detail {
	struct stat stat;
	DIR *dir;
	FILE *fp;
};

static void close_file(struct file_detail *file_detail) {
	if (file_detail->dir) {
		closedir(file_detail->dir);
		file_detail->dir = NULL;
	}
	if (file_detail->fp) {
		fclose(file_detail->fp);
		file_detail->fp = NULL;
	}
}

static bool open_file(
        char *filepath,
        struct file_detail *out,
        struct httpd_data *cls,
        bool open) {
	struct file_detail st_;
	if (!out) {
		st_ = (struct file_detail){.dir = NULL, .fp = NULL};
		out = &st_;
	}

start_stat_file:
	close_file(out);

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
	if (!open) close_file(out);
	return true;
no_file:
	return false;
}

static bool valid_filename_n(const char *name, size_t len, struct httpd_data *cls) {
	if (len > 0 && name[0] == '.') {
		if (!cls->dotfiles)
			return false; // skip dotfiles
		if (len == 1)
			return false; // skip "."
		else if (len == 2 && name[1] == '.')
			return false; // skip ".."
	}
	for (size_t i = 0; i < len; ++i) {
		if (name[i] == '\0') return false;
#ifdef _WIN32
		if (strchr("\\/:*?\"<>|", name[i])) return false;
#endif
	}
	return true;
}

static bool valid_filename(const char *name, struct httpd_data *cls) {
	return valid_filename_n(name, strlen(name), cls);
}

static bool add_cjson_item(cJSON *root, struct file_detail st, char *url_dir, char *url_name) {
	if (url_name && url_dir) {
		char new_url[PATH_MAX];
		memcpy(new_url, url_dir, PATH_MAX);
		if (!concat_char(new_url, PATH_MAX, '/')) return false;
		if (!concat(new_url, PATH_MAX, url_name, strlen(url_name))) return false;
		url_dir = new_url;
	} else if (url_dir && url_dir[0] == '\0') {
		url_dir = "/";
	}
	if (url_dir) cJSON_AddStringToObject(root, "url", url_dir);
	if (url_name) cJSON_AddStringToObject(root, "name", url_name);
	if (st.dir) {
		cJSON_AddStringToObject(root, "type", "directory");
	} else if (st.fp) {
		cJSON_AddStringToObject(root, "type", "file");
	} else {
		return false;
	}
	if (st.fp) {
		cJSON_AddNumberToObject(root, "size", st.stat.st_size);
	}
	return true;
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

	char filepath[PATH_MAX]; // full path to file
	strcpy(filepath, cls->base_file);

	char url_clean[PATH_MAX];
	url_clean[0] = '\0';

	struct file_detail file = {.dir = NULL, .fp = NULL};
	bool is_file = false;

	if (!open_file(filepath, &file, cls, true)) goto not_found;

	for (const char *urlpath = url;;) {
		bool first = urlpath == url;

		while (*urlpath == '/') urlpath++; // skip leading slashes
		if (*urlpath == '\0') break;       // check for end of path
		if (is_file) goto not_found;       // file cannot have subdirectories

		const char *slash = strchrnul_(urlpath, '/'); // find next slash (or end of string)
		size_t segment_len = slash - urlpath;         // length of the path segment

		if (!valid_filename_n(urlpath, segment_len, cls)) goto bad_request;

		if (first)
			if (!concat_char(url_clean, PATH_MAX, '/')) goto too_long;
		if (!concat(url_clean, PATH_MAX, urlpath, segment_len)) goto too_long;

		if (!concat_char(filepath, PATH_MAX, PATH_SEPARATOR)) goto too_long;
		if (!concat(filepath, PATH_MAX, urlpath, segment_len)) goto too_long;

		// skip to the next segment
		urlpath = slash;

		// resolve the file
		if (!open_file(filepath, &file, cls, true)) goto not_found;
		if (file.fp) is_file = true;
	}

serve_file:
	if (file.fp) {
		//TODO
		result_file = filepath;
		output_mode = OUT_NONE;
		data = "test";
		size = 4;
		goto respond;
	} else if (file.dir) {
		if (!cls->list_directories) goto not_found; // directory listing not allowed
		result_file = filepath;
		cJSON *dir_array;
		if (output_mode == OUT_JSON) {
			dir_array = cJSON_CreateArray();
			cJSON_AddItemToObject(root, "children", dir_array);
		}
		add_cjson_item(root, file, url_clean, NULL);

		struct dirent *entry;
		while ((entry = readdir(file.dir))) {
			if (!valid_filename(entry->d_name, cls)) continue;

			struct file_detail child_file = {.dir = NULL, .fp = NULL};

			char child_path[PATH_MAX];
			memcpy(child_path, filepath, PATH_MAX);
			if (!concat_char(child_path, PATH_MAX, '/')) continue;
			if (!concat(child_path, PATH_MAX, entry->d_name, strlen(entry->d_name))) continue;
			if (!open_file(child_path, &child_file, cls, true)) continue; // skip if cannot open file

			switch (output_mode) {
				case OUT_NONE:
				case OUT_TEXT:
					break;
				case OUT_HTML:
					break;
				case OUT_JSON:;
					cJSON *child_obj = cJSON_CreateObject();
					add_cjson_item(child_obj, child_file, url_clean, entry->d_name);
					cJSON_AddItemToArray(dir_array, child_obj);
					break;
			}

			close_file(&child_file);
		}

		close_file(&file);
		goto respond;
	}
	goto not_found; // unsupported file typ

not_found:
	close_file(&file);
	status = MHD_HTTP_NOT_FOUND;
	if (cls->not_found_file && !not_found) {
		// resolve the file
		if (!open_file(cls->not_found_file, &file, cls, true)) goto not_found;
		goto serve_file;
	}
	goto respond;
too_long:
	status = MHD_HTTP_URI_TOO_LONG;
	goto respond;
bad_request:
	status = MHD_HTTP_BAD_REQUEST;
	goto respond;
respond:;
	close_file(&file);
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
		        method, url_clean[0] ? url_clean : "/",
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
