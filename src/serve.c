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
#include "status_code.h"

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

static bool add_cjson_item(cJSON *obj, struct file_detail st, char *url, char *name) {
	if (url) cJSON_AddStringToObject(obj, "url", url);
	if (name) cJSON_AddStringToObject(obj, "name", name);
	if (st.dir) {
		cJSON_AddStringToObject(obj, "type", "directory");
	} else if (st.fp) {
		cJSON_AddStringToObject(obj, "type", "file");
	} else {
		return false;
	}
	if (st.fp) {
		cJSON_AddNumberToObject(obj, "size", st.stat.st_size);
	}
	return true;
}

#define append(str) \
	if (!concat_expand(base, str)) return false
#define append_escape(str) \
	if (!escape_html(base, str)) return false

static bool WARN_UNUSED construct_html_start(char **base, char *title) {
	append("<html>\n<head>"
	       "<meta charset=\"utf-8\">"
	       "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
	append("<title>");
	append_escape(title);
	append("</title></head>\n<body><h1>");
	append_escape(title);
	append("</h1>\n");
	return true;
}

static bool WARN_UNUSED construct_html_end(char **base) {
	append("\n<hr/></body></html>");
	return true;
}
#undef append
#undef append_escape

enum MHD_Result answer_to_connection(void *cls_, struct MHD_Connection *connection,
                                     const char *user_url,
                                     const char *method, const char *version,
                                     const char *upload_data,
                                     size_t *upload_data_size, void **req_cls) {
#define char_data ((char **) &data)
#define append(str, label) \
	if (!concat_expand(char_data, str)) goto label
#define append_escape(str, label) \
	if (!escape_html(char_data, str)) goto label

	void *data = NULL;                                                     // response data
	enum MHD_ResponseMemoryMode data_memory_mode = MHD_RESPMEM_PERSISTENT; // what mhd should do with the data
	size_t size = 0;                                                       // size of the response data

	unsigned int status = MHD_HTTP_OK;  // response status
	char *content_type = NULL;          // response content type
	cJSON *root = cJSON_CreateObject(); // for responding with JSON data
	char *result_file = NULL;           // used for logging
	bool not_found = false;             // for custom 404 page

	// get accept content type
	const char *accept_type = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_ACCEPT);
	enum output_mode output_mode = get_output_mode(accept_type); // response content type enum

	struct httpd_data *cls = (struct httpd_data *) cls_;

	if (strcmp(method, MHD_HTTP_METHOD_GET) != 0) {
		status = MHD_HTTP_METHOD_NOT_ALLOWED;
		goto respond;
	}

	// validate url
	if (user_url[0] != '/') goto bad_request;

	char filepath[PATH_MAX]; // full path to file
	strcpy(filepath, cls->base_file);

	char url_clean[PATH_MAX];
	url_clean[0] = '\0';

	struct file_detail file = {.dir = NULL, .fp = NULL};
	bool is_file = false;

	if (!open_file(filepath, &file, cls, true)) goto not_found;

	for (const char *url_path = user_url;;) {
		bool first = url_path == user_url;

		while (*url_path == '/') url_path++; // skip leading slashes
		if (*url_path == '\0') break;        // check for end of path
		if (is_file) goto not_found;         // file cannot have subdirectories

		const char *slash = strchrnul_(url_path, '/'); // find next slash (or end of string)
		size_t segment_len = slash - url_path;         // length of the path segment

		if (!valid_filename_n(url_path, segment_len, cls)) goto bad_request;

		if (first)
			if (!concat_char(url_clean, PATH_MAX, '/')) goto too_long;
		if (!concat_n(url_clean, PATH_MAX, url_path, segment_len)) goto too_long;

		if (!concat_char(filepath, PATH_MAX, PATH_SEPARATOR)) goto too_long;
		if (!concat_n(filepath, PATH_MAX, url_path, segment_len)) goto too_long;

		// skip to the next segment
		url_path = slash;

		// resolve the file
		if (!open_file(filepath, &file, cls, true)) goto not_found;
		if (file.fp) is_file = true;
	}

#define url_clean_slash (url_clean[0] == '\0' ? "/" : url_clean)

serve_file:
	if (file.fp) {
		//TODO
		/*
		result_file = filepath;
		output_mode = OUT_NONE;
		data = "test";
		size = 4;
		*/
		status = MHD_HTTP_NOT_IMPLEMENTED;
		goto respond;
	} else if (file.dir) {
		if (!cls->list_directories) goto not_found; // directory listing not allowed
		result_file = filepath;
		cJSON *dir_array; // array of directory children
		switch (output_mode) {
			case OUT_NONE:
			case OUT_TEXT:
				data_memory_mode = MHD_RESPMEM_MUST_FREE;
				append("Index of ", server_error);
				append(url_clean_slash, server_error);
				append("\n\n", server_error);
				break;
			case OUT_HTML:
				data_memory_mode = MHD_RESPMEM_MUST_FREE;
				size_t title_len = strlen(url_clean_slash) + 32;
				char *title = malloc(title_len);
				if (!title) goto server_error;
				snprintf(title, title_len, "Index of %s", url_clean_slash);
				if (!construct_html_start(char_data, title)) goto server_error;
				free(title);
				append("<hr><ul>\n", server_error);
				break;
			case OUT_JSON:
				dir_array = cJSON_CreateArray();
				cJSON_AddItemToObject(root, "children", dir_array);
				add_cjson_item(root, file, url_clean_slash, NULL);
				break;
		}

		struct dirent *entry;
		while ((entry = readdir(file.dir))) {
			char *child_name = entry->d_name;

			if (!valid_filename(child_name, cls)) continue;

			struct file_detail child_file = {.dir = NULL, .fp = NULL};

			char child_path[PATH_MAX];
			memcpy(child_path, filepath, PATH_MAX);
			if (!concat_char(child_path, PATH_MAX, '/')) continue;
			if (!concat(child_path, PATH_MAX, child_name)) continue;
			if (!open_file(child_path, &child_file, cls, true)) continue; // skip if cannot open file

			char child_url[PATH_MAX];
			memcpy(child_url, url_clean, PATH_MAX);
			if (!concat_char(child_url, PATH_MAX, '/')) return false;
			if (!concat(child_url, PATH_MAX, child_name)) return false;

			off_t child_size = child_file.stat.st_size;
			char child_size_str[32];
			snprintf(child_size_str, 32, "%li", child_size);
			char *child_size_format = format_bytes(child_size, binary_i);

			switch (output_mode) {
				case OUT_NONE:
				case OUT_TEXT:
					append("- ", server_dir_error);
					append(child_name, server_dir_error);
					append(" - ", server_dir_error);
					if (child_file.dir) {
						append("directory", server_dir_error);
					} else if (child_file.fp) {
						append("file - ", server_dir_error);
						append(child_size_format, server_dir_error);
					}
					append("\n", server_dir_error);
					break;
				case OUT_HTML:
					append("<li><a href=\"", server_dir_error);
					append_escape(child_url, server_dir_error);
					append("\" title=\"", server_dir_error);
					append_escape(child_url, server_dir_error);
					append("\">", server_dir_error);
					append_escape(child_name, server_dir_error);
					append("</a>", server_dir_error);
					if (child_file.dir) {
						append(" - directory", server_dir_error);
					} else if (child_file.fp) {
						append(" - file - <span title=\"", server_dir_error);
						append_escape(child_size_str, server_dir_error);
						append(" bytes\">", server_dir_error);
						append_escape(child_size_format, server_dir_error);
						append("</span>", server_dir_error);
					}
					append("</li>\n", server_dir_error);
					break;
				case OUT_JSON:;
					cJSON *child_obj = cJSON_CreateObject();
					add_cjson_item(child_obj, child_file, child_url, child_name);
					cJSON_AddItemToArray(dir_array, child_obj);
					break;
			}

			free(child_size_format);
			close_file(&child_file);
			continue;
		server_dir_error:
			free(child_size_format);
			close_file(&child_file);
			goto server_error;
		}

		if (output_mode == OUT_HTML) {
			append("</ul>", server_error);
			if (!construct_html_end(char_data)) goto server_error;
		}

		if (output_mode != OUT_JSON) {
			append("\n", server_error);
			size = strlen(*char_data);
			data = *char_data;
		}

		close_file(&file);
		goto respond;
	}
	goto not_found; // unsupported file typ

not_found:
	close_file(&file);
	status = MHD_HTTP_NOT_FOUND;
	if (cls->not_found_file && !not_found) {
		not_found = true;
		// resolve the file
		if (!open_file(cls->not_found_file, &file, cls, true)) goto not_found;
		goto serve_file;
	}
	goto respond;
server_error:
	status = MHD_HTTP_INTERNAL_SERVER_ERROR;
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
		size = 0;

		if (status != MHD_HTTP_NO_CONTENT) {
			char *status_name = status_codes[status];

			size_t full_status_str_len = strlen(status_name) + 32;
			char full_status_str[full_status_str_len];
			snprintf(full_status_str, full_status_str_len, "%i - %s", status, status_name);

			bool is_error = status >= 400;

			// write out status code
			switch (output_mode) {
				case OUT_NONE:
					break;
				case OUT_TEXT:
					data_memory_mode = MHD_RESPMEM_MUST_FREE;
					append(full_status_str, server_error);
					append("\n", server_error);
					break;
				case OUT_HTML:
					data_memory_mode = MHD_RESPMEM_MUST_FREE;
					if (!construct_html_start(char_data, full_status_str)) goto server_error;
					append("<p><a href=\"/\">Main Page</a></p>\n", server_error);
					if (!construct_html_end(char_data)) goto server_error;
					break;
				case OUT_JSON:;
					// set status code in JSON
					cJSON *status_obj = cJSON_CreateObject();
					cJSON_AddNumberToObject(status_obj, "number", status);
					cJSON_AddStringToObject(status_obj, "message", status_name);
					cJSON_AddBoolToObject(status_obj, "ok", !is_error);
					cJSON_AddItemToObject(root, "status", status_obj);

					// encode JSON data and respond with it
					data = cJSON_Print(root);
					append("\n", server_error);
					data_memory_mode = MHD_RESPMEM_MUST_FREE; // free the data after responding
					break;
			}

			if (data) size = strlen(data);
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

	response = MHD_create_response_from_buffer(size, data, data_memory_mode);
	MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, content_type);
	int ret = MHD_queue_response(connection, status, response);
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
		        method, url_clean_slash,
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
