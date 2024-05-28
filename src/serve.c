#include "serve.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/stat.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>
#include "format_bytes.h"

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

#ifdef _WIN32
#define PATH_SEPARATOR '\\'
#else
#define PATH_SEPARATOR '/'
#endif

char *sockaddr_to_string(struct sockaddr *addr) {
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
	enum output_mode {
		OUT_NONE,
		OUT_TEXT,
		OUT_HTML,
		OUT_JSON
	} output_mode = OUT_TEXT;           // response content type enum
	cJSON *root = cJSON_CreateObject(); // for responding with JSON data
	char *result_file = NULL;           // used for logging

	// get accept content type
	const char *accept_type = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_ACCEPT);
	if (accept_type) {
		size_t len = strlen(accept_type);
		if (len <= 1024) {                     // arbitrary limit
			char str[len + 8];                 // copy the string
			str[0] = ',';                      // add a comma to the start
			memcpy(str + 1, accept_type, len); // copy the string

			str[len + 1] = '\0';
			char *semi = strchrnul(str, ';');
			semi[0] = ',';  // trim off the semicolon and replace it with the comma
			semi[1] = '\0'; // and null terminate

			if (strstr(str, "text/html"))
				output_mode = OUT_HTML;
			else if (strstr(str, "application/json"))
				output_mode = OUT_JSON;
		}
	}

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
	const char *urlpath = url;
	struct stat st;

	bool first = false, is_file = false;

	while (true) {
		if (first) {                           // allow filepath to be resolved for initial base directory
			while (*urlpath == '/') urlpath++; // skip leading slashes
			if (*urlpath == '\0') break;       // check for end of path
			if (is_file) goto not_found;       // file cannot have subdirectories

			const char *slash = strchrnul(urlpath, '/'); // find next slash (or end of string)
			size_t segment_len = slash - urlpath;        // length of the path segment
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

		// resolve the file and do some checks

	stat_file:
		// lstat to prevent symlink traversal
		if (lstat(filepath, &st) != 0) {
			// file not found
			goto not_found;
		}

		switch (st.st_mode & S_IFMT) {
			case S_IFDIR:
				break;
			case S_IFLNK:
				if (!cls->follow_symlinks) goto not_found; // symlink not allowed
				// follow symlink
				char filepath_[PATH_MAX];
				if (!realpath(filepath, filepath_)) {
					if (!cls->quiet)
						eprintf("Invalid symlink path: %s: %s\n", filepath_, strerror(errno));
					goto not_found;
				}
				memcpy(filepath, filepath_, PATH_MAX);
				goto stat_file; // repeat the check for the target
			case S_IFREG:       // regular file
				is_file = true;
				break;
			default:
				// unsupported file type
				goto not_found;
		}
	}

	if (S_ISREG(st.st_mode)) {
		result_file = filepath;
		output_mode = OUT_TEXT;
		data = "test";
		size = 4;
		goto respond;
	}

	if (!S_ISDIR(st.st_mode)) goto not_found; // unsupported file type

	if (!cls->list_directories) goto not_found; // directory listing not allowed
	result_file = filepath;
	output_mode = OUT_TEXT;
	data = "Directory listing";
	size = strlen(data);
	goto respond;

not_found:
	status = MHD_HTTP_NOT_FOUND;
	goto respond;
bad_request:
	status = MHD_HTTP_BAD_REQUEST;
	goto respond;
respond:
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
		free(size_str);
	}
	cJSON_Delete(root);
	return ret;
}
