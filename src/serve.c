#include "serve.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>

#include <dirent.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include "util.h"
#include "format_bytes.h"
#include "status_code.h"

#include "serve_file.h"
#include "serve_directory.h"
#include "serve_result.h"

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

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

static bool get_is_download(struct MHD_Connection *connection) {
	const char *download = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "download");
	if (download) {
		if (download[0] == '\0') return false;
		if (strcmp(download, "0") == 0) return false;
		if (strcmp(download, "false") == 0) return false;
		if (strcmp(download, "no") == 0) return false;
		return true;
	}
	return false;
}

static enum response_type get_response_type(struct MHD_Connection *connection) {
	// get ?output query parameter
	const char *output = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "output");
	if (output) {
		if (strcmp(output, "none") == 0 || strcmp(output, "raw") == 0)
			return OUT_NONE;
		else if (strcmp(output, "text") == 0)
			return OUT_TEXT;
		else if (strcmp(output, "html") == 0)
			return OUT_HTML;
		else if (strcmp(output, "json") == 0)
			return OUT_JSON;
	}
	// get Accept header
	const char *accept_type = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_ACCEPT);
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
			else if (strstr(str, "text/plain"))
				return OUT_TEXT;
		}
	}
	return OUT_NONE;
}

void close_file(struct file_detail *file_detail) {
	if (file_detail->dir) {
		closedir(file_detail->dir);
		file_detail->dir = NULL;
	}
	if (file_detail->fp) {
		fclose(file_detail->fp);
		file_detail->fp = NULL;
	}
}

bool open_file(
        char *filepath,
        struct file_detail *out,
        const struct server_config *cls,
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

bool valid_filename_n(const char *name, size_t len, const struct server_config *cls) {
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

bool valid_filename(const char *name, const struct server_config *cls) {
	return valid_filename_n(name, strlen(name), cls);
}

bool cjson_add_file_details(cJSON *obj, struct file_detail st, char *url, char *name, struct file_cache_item *file_data) {
	if (st.dir) {
		cJSON_AddStringToObject(obj, "type", "directory");
	} else if (st.fp) {
		cJSON_AddStringToObject(obj, "type", "file");
		if (file_data) {
			cJSON_AddNumberToObject(obj, "size", file_data->size);
			cJSON_AddStringToObject(obj, "mime", file_data->mime_type);
			cJSON_AddBoolToObject(obj, "binary", file_data->is_binary);
		} else {
			cJSON_AddNumberToObject(obj, "size", st.stat.st_size);
		}
	} else
		return false;
	if (url) cJSON_AddStringToObject(obj, "url", url);
	if (name) cJSON_AddStringToObject(obj, "name", name);
	return true;
}

extern const char binary_site_css[];
extern size_t binary_site_css_len;

// TODO: use a template engine for this

bool WARN_UNUSED construct_html_head(char **base) {
	if (!concat_expand(base, "<html>\n<head>"
	                         "<meta charset=\"utf-8\">"
	                         "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")) return false;
	if (!concat_expand(base, "<style>")) return false;
	if (!concat_expand_n(base, binary_site_css, binary_site_css_len)) return false;
	if (!concat_expand(base, "</style>")) return false;
	return true;
}

bool WARN_UNUSED construct_html_body(char **base, char *title_class) {
	if (!concat_expand(base, "</head>\n<body><h1 class=\"main-title")) return false;
	if (title_class && title_class[0] != '\0') {
		if (!concat_expand_char(base, ' ')) return false;
		if (!concat_expand_escape(base, title_class)) return false;
	}
	if (!concat_expand(base, "\">")) return false;
	return true;
}

bool WARN_UNUSED construct_html_main(char **base) {
	return concat_expand(base, "</h1><hr/><div class=\"main\">\n");
}

bool WARN_UNUSED construct_html_end(char **base) {
	return concat_expand(base, "\n</div><hr/></body></html>");
}

#include "serve_file.h"

static void ensure_path_slash(char *path, char slash) {
	if (path[0] != '\0') return;
	path[0] = slash;
	path[1] = '\0';
}

enum MHD_Result answer_to_connection(void *cls_, struct MHD_Connection *connection,
                                     const char *user_url,
                                     const char *method, const char *version,
                                     const char *upload_data,
                                     size_t *upload_data_size, void **req_cls) {
#define append(str, label) \
	if (!concat_expand(&output.text, str)) goto label
#define append_escape(str, label) \
	if (!concat_expand_escape(&output.text, str)) goto label

	struct output_data output = {
	        .data = NULL,                          // response data
	        .data_memory = MHD_RESPMEM_PERSISTENT, // what mhd should do with the data
	        .size = 0,                             // size of the response data
	        .status = MHD_HTTP_OK,                 // response status
	        .content_type = NULL,                  // response content type
	        .json_root = cJSON_CreateObject(),     // for responding with JSON data
	        .response_type = get_response_type(connection), // response content type enum
	};

	struct input_data input = {
	        .file = {.fp = NULL, .dir = NULL}, // file details
	        .is_root_url = true,
	        .is_download = get_is_download(connection)  // if the file should be downloaded by the browser
	};

	if (input.is_download) output.response_type = OUT_NONE; // force raw output for downloads

	bool not_found = false; // for custom 404 page

	// get server config data
	const struct server_config *cls = (const struct server_config *) cls_;

	if (strcmp(method, MHD_HTTP_METHOD_GET) != 0) {
		output.status = MHD_HTTP_METHOD_NOT_ALLOWED;
		goto respond;
	}

	// validate url
	if (user_url[0] != '/') goto bad_request;

	// set up input data
	char url_[PATH_MAX], url_parent_[PATH_MAX], filepath_[PATH_MAX], filepath_parent_[PATH_MAX];
	input.url = url_;
	input.url_parent = url_parent_;
	input.filepath = filepath_;
	input.filepath_parent = filepath_parent_;

	input.url[0] = '\0';
	strcpy(input.filepath, cls->base_file);

	if (!open_file(input.filepath, &input.file, cls, true)) goto not_found;

	// set parent paths
	memcpy(input.url_parent, input.url, PATH_MAX);
	memcpy(input.filepath_parent, input.filepath, PATH_MAX);

	bool is_file = false;
	for (const char *segment = user_url;;) {
		while (*segment == '/') segment++; // skip leading slashes
		if (*segment == '\0') break;       // check for end of path
		if (is_file) goto not_found;       // file cannot have subdirectories

		input.is_root_url = false;
		// set parent paths
		memcpy(input.url_parent, input.url, PATH_MAX);
		memcpy(input.filepath_parent, input.filepath, PATH_MAX);

		const char *slash = strchrnul_(segment, '/'); // find next slash (or end of string)
		size_t segment_len = slash - segment;         // length of the path segment

		if (!valid_filename_n(segment, segment_len, cls)) goto bad_request;
		if (!join_url_path_n(input.url, PATH_MAX, segment, segment_len)) goto too_long;
		if (!join_filepath_n(input.filepath, PATH_MAX, segment, segment_len)) goto too_long;

		// skip to the next segment
		segment = slash;

		// resolve the file
		if (!open_file(input.filepath, &input.file, cls, true)) goto not_found;
		if (input.file.fp) is_file = true;
	}

	// ensure paths end with a slash
	ensure_path_slash(input.url, '/');
	ensure_path_slash(input.url_parent, '/');
	ensure_path_slash(input.filepath, PATH_SEPARATOR);
	ensure_path_slash(input.filepath_parent, PATH_SEPARATOR);

serve_logic:;
	enum serve_result result = not_found;
	if (input.file.fp) {
		result = serve_file(cls, &input, &output);
	} else if (input.file.dir) {
		if (not_found) goto not_found; // custom 404 page doesn't support directory listing
		result = serve_directory(cls, &input, &output);
	}
	switch (result) {
		case serve_not_found:
			goto not_found;
		case serve_ok:
			goto respond;
		case serve_error:
		default:
			goto server_error;
	}

not_found:
	close_file(&input.file);
	output.status = MHD_HTTP_NOT_FOUND;
	if (not_found) { // prevent infinite loop
		eprintf("Error reading 404 file: %s\n", cls->not_found_file);
	} else if (cls->not_found_file) {
		not_found = true;
		// resolve the file
		if (!open_file(cls->not_found_file, &input.file, cls, true)) goto not_found;
		goto serve_logic;
	}
	goto respond;
server_error:
	output.status = MHD_HTTP_INTERNAL_SERVER_ERROR;
	goto respond;
too_long:
	output.status = MHD_HTTP_URI_TOO_LONG;
	goto respond;
bad_request:
	output.status = MHD_HTTP_BAD_REQUEST;
	goto respond;
respond:;
	close_file(&input.file);
	struct MHD_Response *response;

	result = serve_result(cls, &input, &output);
	switch (result) {
		case serve_not_found:
			output.status = MHD_HTTP_NOT_FOUND;
			break;
		case serve_error:
			output.response_type = OUT_NONE; // force no content
			output.status = MHD_HTTP_INTERNAL_SERVER_ERROR;
			break;
		case serve_ok:
			break;
	}

	char *download_extension = NULL;

	if (!output.content_type) {
		// set content type accordingly
		switch (output.response_type) {
			case OUT_NONE:
				break;
			case OUT_TEXT:
				download_extension = "txt";
				output.content_type = "text/plain";
				break;
			case OUT_HTML:
				download_extension = "html";
				output.content_type = "text/html";
				break;
			case OUT_JSON:
				download_extension = "json";
				output.content_type = "application/json";
				break;
		}
	}

	if (!output.data) output.data_memory = MHD_RESPMEM_PERSISTENT; // no data to free
	if (output.data_memory == MHD_RESPMEM_MUST_FREE)
		response = MHD_create_response_from_buffer_with_free_callback(output.size, output.data, &free); // helps with portability
	else
		response = MHD_create_response_from_buffer(output.size, output.data, output.data_memory);
	if (input.is_download) {
		MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_DISPOSITION, "attachment"); // TODO: set filename + download_extension
	}
	if (output.content_type) MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, output.content_type);
	int ret = MHD_queue_response(connection, output.status, response);
	MHD_destroy_response(response);

	if (!cls->quiet) {
		struct sockaddr *addr = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;
		char *ip = sockaddr_to_string(addr);
		char *size_str = format_bytes(output.size, binary_i);
		char *response_type_str = NULL;
		switch (output.response_type) {
			case OUT_NONE:
				response_type_str = "Raw";
				break;
			case OUT_TEXT:
				response_type_str = "Text";
				break;
			case OUT_HTML:
				response_type_str = "HTML";
				break;
			case OUT_JSON:
				response_type_str = "JSON";
				break;
		}
		// log the request and response
		printf(
		        "Request: %s%s%s %s\n"
		        "Response: %i %s, %s%sType: %s, %s%s%s\n",
		        ip ? ip : "", ip ? ", " : "",
		        method, input.url,
		        output.status, status_codes[output.status],
		        output.content_type ? output.content_type : "", output.content_type ? ", " : "",
		        response_type_str,
		        input.filepath ? input.filepath : "", input.filepath ? ", " : "",
		        size_str);
		// all in one printf call to prevent interleaving of output from multiple threads
		free(ip);
		free(size_str);
	}
	cJSON_Delete(output.json_root);
	return ret;
}
