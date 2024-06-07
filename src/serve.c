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

static enum response_type {
	OUT_NONE,
	OUT_TEXT,
	OUT_HTML,
	OUT_JSON
} get_response_type(struct MHD_Connection *connection) {
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
        struct server_config *cls,
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

static bool valid_filename_n(const char *name, size_t len, struct server_config *cls) {
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

static bool valid_filename(const char *name, struct server_config *cls) {
	return valid_filename_n(name, strlen(name), cls);
}

static bool add_cjson_file(cJSON *obj, struct file_detail st, char *url, char *name) {
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

extern const char binary_site_css[];
extern size_t binary_site_css_len;

static bool WARN_UNUSED construct_html_start(char **base, char *title, char *title_class) {
	if (!concat_expand(base, "<html>\n<head>"
	                         "<meta charset=\"utf-8\">"
	                         "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")) return false;
	if (!concat_expand(base, "<style>")) return false;
	if (!concat_expand_n(base, binary_site_css, binary_site_css_len)) return false;
	if (!concat_expand(base, "</style>")) return false;
	if (!concat_expand(base, "<title>")) return false;
	if (!concat_expand_escape(base, title)) return false;
	if (!concat_expand(base, "</title></head>\n<body><h1 class=\"main-title")) return false;
	if (title_class && title_class[0] != '\0') {
		if (!concat_expand(base, " ")) return false;
		if (!concat_expand_escape(base, title_class)) return false;
	}
	if (!concat_expand(base, "\">")) return false;
	if (!concat_expand_escape(base, title)) return false;
	if (!concat_expand(base, "</h1><hr/><div class=\"main\">\n")) return false;
	return true;
}

static bool WARN_UNUSED construct_html_end(char **base) {
	return concat_expand(base, "\n</div><hr/></body></html>");
}

static bool add_dir_item(enum response_type response_type, char **data, struct file_detail file, char *url, char *name, cJSON *dir_array, char *class, char *custom_type) {
	off_t size = file.stat.st_size;
	char size_str[32];
	snprintf(size_str, 32, "%li", size);
	char *size_format = format_bytes(size, binary_i);

	switch (response_type) {
		case OUT_NONE:
		case OUT_TEXT:
			if (!concat_expand(data, "- ")) goto error;
			if (!concat_expand(data, name)) goto error;
			if (!concat_expand(data, " - ")) goto error;
			if (file.dir) {
				if (!concat_expand(data, "directory")) goto error;
			} else if (file.fp) {
				if (!concat_expand(data, "file - ")) goto error;
				if (!concat_expand(data, size_format)) goto error;
			}
			if (!concat_expand(data, "\n")) goto error;
			break;
		case OUT_HTML:
			if (!concat_expand(data, "<li class=\"file-item")) goto error;
			if (class && class[0] != '\0') {
				if (!concat_expand(data, " ")) return false;
				if (!concat_expand_escape(data, class)) return false;
			}
			if (!concat_expand(data, "\"><a href=\"")) return false;
			if (!concat_expand_escape(data, url)) goto error;
			if (!concat_expand(data, "\" title=\"")) goto error;
			if (!concat_expand_escape(data, url)) goto error;
			if (!concat_expand(data, "\">")) goto error;
			if (!concat_expand_escape(data, name)) goto error;
			if (!concat_expand(data, "</a>")) goto error;
			if (!concat_expand(data, " - <span class=\"file-type\">")) goto error;
			if (!custom_type) {
				if (file.dir) custom_type = "directory";
				else if (file.fp)
					custom_type = "file";
				else
					custom_type = "unknown";
			}
			if (!concat_expand_escape(data, custom_type)) goto error;
			if (!concat_expand(data, "</span>")) goto error;
			if (file.fp) {
				if (!concat_expand(data, " - <span class=\"file-size\" title=\"")) goto error;
				if (!concat_expand_escape(data, size_str)) goto error;
				if (!concat_expand(data, " bytes\">")) goto error;
				if (!concat_expand_escape(data, size_format)) goto error;
				if (!concat_expand(data, "</span>")) goto error;
			}
			if (!concat_expand(data, "</li>\n")) goto error;
			break;
		case OUT_JSON:;
			cJSON *obj = cJSON_CreateObject();
			add_cjson_file(obj, file, url, name);
			cJSON_AddItemToArray(dir_array, obj);
			break;
	}

	free(size_format);
	return true;
error:
	free(size_format);
	return false;
}

struct output_data {
	union {
		void *data;
		char *text;
	};
	enum MHD_ResponseMemoryMode data_memory;
	size_t size;
	unsigned int status;
	char *content_type;
};

struct input_data {
	struct file_detail file;
	char *url;
	char *url_parent;
	char *filepath;
	char *filepath_parent;
	bool is_root_url;
	enum response_type response_type;
	cJSON *json_root;
};

#define append(str, label) \
	if (!concat_expand(&output->text, str)) goto label
#define append_escape(str, label) \
	if (!concat_expand_escape(&output->text, str)) goto label

static bool serve_file(struct server_config *cls, struct input_data *input, struct output_data *output) {
	if (!input->file.fp) return false;
	//if (!get_file_cache(filepath, &file)) goto not_found;
	output->status = MHD_HTTP_NOT_IMPLEMENTED;
	return true;
}

static bool serve_directory(struct server_config *cls, struct input_data *input, struct output_data *output) {
	if (!input->file.dir) return false;
	if (!cls->list_directories) false; // directory listing not allowed
	cJSON *dir_array = NULL;           // array of directory children
	switch (input->response_type) {
		case OUT_NONE:
		case OUT_TEXT:
			input->response_type = OUT_TEXT;
			output->data_memory = MHD_RESPMEM_MUST_FREE;
			append("Index of ", server_error);
			append(input->url, server_error);
			append("\n\n", server_error);
			break;
		case OUT_HTML:
			output->data_memory = MHD_RESPMEM_MUST_FREE;
			size_t title_len = strlen(input->url) + 32;
			char *title = malloc(title_len);
			if (!title) goto server_error;
			snprintf(title, title_len, "Index of %s", input->url);
			if (!construct_html_start(&output->text, title, NULL)) goto server_error;
			free(title);
			append("<ul>\n", server_error);
			break;
		case OUT_JSON:
			dir_array = cJSON_CreateArray();
			cJSON_AddItemToObject(input->json_root, "children", dir_array);
			add_cjson_file(input->json_root, input->file, input->url, NULL);
			break;
	}

	bool res;
	if (!input->is_root_url) {
		// add parent directory link
		struct file_detail parent_file = {.dir = NULL, .fp = NULL};
		if (open_file(input->filepath_parent, &parent_file, cls, true)) {
			res = add_dir_item(input->response_type, &output->text, parent_file, input->url_parent, "..", dir_array, "parent", "parent directory");
			if (!res) {
				close_file(&parent_file);
				goto server_error;
			}
		}
	}

	struct dirent *entry;
	while ((entry = readdir(input->file.dir))) {
		char *child_name = entry->d_name;

		if (!valid_filename(child_name, cls)) continue;

		struct file_detail child_file = {.dir = NULL, .fp = NULL};

		char child_filepath[PATH_MAX];
		memcpy(child_filepath, input->filepath, PATH_MAX);
		if (!join_filepath(child_filepath, PATH_MAX, child_name)) continue;
		if (!open_file(child_filepath, &child_file, cls, true)) continue; // skip if cannot open file

		char child_url[PATH_MAX];
		memcpy(child_url, input->url, PATH_MAX);
		if (!join_url_path(child_url, PATH_MAX, child_name)) continue;

		res = add_dir_item(input->response_type, &output->text, child_file, child_url, child_name, dir_array, "child", NULL);

		close_file(&child_file);
		if (res)
			continue;
		else
			goto server_error;
	}

	if (input->response_type == OUT_HTML) {
		append("</ul>", server_error);
		if (!construct_html_end(&output->text)) goto server_error;
	}

	if (input->response_type != OUT_JSON) {
		append("\n", server_error);
		output->size = strlen(output->text);
	}
	return true;

server_error:
	return false;
}

static void ensure_path_slash(char *path, char slash) {
	if (path[0] != '\0') return;
	path[0] = slash;
	path[1] = '\0';
}

#undef append
#undef append_escape

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
	};

	struct input_data input = {
	        .file = {.fp = NULL, .dir = NULL}, // file details
	        .is_root_url = true,
	        .json_root = cJSON_CreateObject(), // for responding with JSON data
	        .response_type = get_response_type(connection)  // response content type enum
	};

	bool not_found = false;    // for custom 404 page
	bool server_error = false; // for server error

	// get server config data
	struct server_config *cls = (struct server_config *) cls_;

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

serve_file:
	if (input.file.fp) {
		if (!serve_file(cls, &input, &output)) goto not_found;
		goto respond;
	}
	if (input.file.dir) {
		if (not_found) goto not_found; // custom 404 page doesn't support directory listing
		if (!serve_directory(cls, &input, &output)) goto not_found;
		goto respond;
	}
	goto not_found; // unsupported file type

not_found:
	close_file(&input.file);
	output.status = MHD_HTTP_NOT_FOUND;
	if (not_found) { // prevent infinite loop
		eprintf("Error reading 404 file: %s\n", cls->not_found_file);
	} else if (cls->not_found_file) {
		not_found = true;
		// resolve the file
		if (!open_file(cls->not_found_file, &input.file, cls, true)) goto not_found;
		goto serve_file;
	}
	goto respond;
server_error:
	server_error = true;
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

	if (!output.data) { // if there is no data to respond with
		output.size = 0;

		output.content_type = NULL;

		if (output.status != MHD_HTTP_NO_CONTENT && !server_error) { // prevent infinite loop
			char *status_name = status_codes[output.status];

			size_t full_status_str_len = strlen(status_name) + 32;
			char full_status_str[full_status_str_len];
			snprintf(full_status_str, full_status_str_len, "%i - %s", output.status, status_name);

			bool is_error = http_status_is_error(output.status);

			output.data_memory = MHD_RESPMEM_MUST_FREE; // free the data after responding

			// write out status code
			switch (input.response_type) {
				case OUT_NONE:
				case OUT_TEXT:
					input.response_type = OUT_TEXT;
					append(full_status_str, server_error);
					append("\n", server_error);
					break;
				case OUT_HTML:
					if (!construct_html_start(&output.text, full_status_str, is_error ? "error" : "ok")) goto server_error;
					append("<p><a class=\"main-page\" href=\"/\">Main Page</a></p>\n", server_error);
					if (!construct_html_end(&output.text)) goto server_error;
					break;
				case OUT_JSON:;
					// set status code in JSON
					cJSON *status_obj = cJSON_CreateObject();
					cJSON_AddNumberToObject(status_obj, "number", output.status);
					cJSON_AddStringToObject(status_obj, "message", status_name);
					cJSON_AddBoolToObject(status_obj, "ok", !is_error);
					cJSON_AddItemToObject(input.json_root, "status", status_obj);

					// encode JSON data and respond with it
					output.data = cJSON_Print(input.json_root);
					append("\n", server_error);
					break;
			}

			if (output.data) output.size = strlen(output.data);
		}
	}

	if (!output.content_type) {
		// set content type accordingly
		switch (input.response_type) {
			case OUT_NONE:
				break;
			case OUT_TEXT:
				output.content_type = "text/plain";
				break;
			case OUT_HTML:
				output.content_type = "text/html";
				break;
			case OUT_JSON:
				output.content_type = "application/json";
				break;
		}
	}

	response = MHD_create_response_from_buffer(output.size, output.data, output.data_memory);
	if (output.content_type) MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, output.content_type);
	int ret = MHD_queue_response(connection, output.status, response);
	MHD_destroy_response(response);

	if (!cls->quiet) {
		struct sockaddr *addr = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;
		char *ip = sockaddr_to_string(addr);
		char *size_str = format_bytes(output.size, binary_i);
		// log the request and response
		printf(
		        "Request: %s%s%s %s\n"
		        "Response: %i, %s%s%s%s%s\n",
		        ip ? ip : "", ip ? ", " : "",
		        method, input.url,
		        output.status,
		        output.content_type ? output.content_type : "", output.content_type ? ", " : "",
		        input.filepath ? input.filepath : "", input.filepath ? ", " : "",
		        size_str);
		// all in one printf call to prevent interleaving of output from multiple threads
		free(ip);
		free(size_str);
	}
	cJSON_Delete(input.json_root);
	return ret;
}
