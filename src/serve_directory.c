#include "serve_directory.h"
#include <string.h>
#include <stdlib.h>

#include "util.h"
#include "format_bytes.h"

#define append(str, label) \
	if (!concat_expand(data, str)) goto label
#define append_escape(str, label) \
	if (!concat_expand_escape(data, str)) goto label
static bool add_dir_item(enum response_type response_type, char **data, struct file_detail file, char *url, char *name, cJSON *dir_array, char *class, char *custom_type) {
	if (!custom_type) {
		if (file.dir)
			custom_type = "directory";
		else if (file.fp)
			custom_type = "file";
		else
			custom_type = "unknown";
	}

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
			if (!concat_expand(data, custom_type)) goto error;
			if (file.fp) {
				if (!concat_expand(data, " - ")) goto error;
				if (!concat_expand(data, size_format)) goto error;
			}
			if (!concat_expand(data, "\n")) goto error;
			break;
		case OUT_HTML:
			if (!concat_expand(data, "<li class=\"file-item")) goto error;
			if (class && class[0] != '\0') {
				if (!concat_expand(data, " ")) goto error;
				if (!concat_expand_escape(data, class)) goto error;
			}
			if (!concat_expand(data, "\"><a href=\"")) goto error;
			if (!concat_expand_escape(data, url)) goto error;
			if (!concat_expand(data, "\" title=\"")) goto error;
			if (!concat_expand_escape(data, url)) goto error;
			if (!concat_expand(data, "\">")) goto error;
			if (!concat_expand_escape(data, name)) goto error;
			if (!concat_expand(data, "</a>")) goto error;
			if (!concat_expand(data, " - <span class=\"file-type\">")) goto error;
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
			cjson_add_file_details(obj, file, url, name, NULL);
			cJSON_AddItemToArray(dir_array, obj);
			break;
	}

	free(size_format);
	return true;
error:
	free(size_format);
	return false;
}
#undef append
#undef append_escape

#define append(str, label) \
	if (!concat_expand(&output->text, str)) goto label
#define append_escape(str, label) \
	if (!concat_expand_escape(&output->text, str)) goto label
enum serve_result serve_directory(const struct server_config *cls, struct input_data *input, struct output_data *output) {
	if (!input->file.dir) return serve_not_found;
	if (!cls->list_directories) return serve_not_found; // directory listing not allowed
	cJSON *dir_array = NULL;                            // array of directory children
	switch (output->response_type) {
		case OUT_NONE:
		case OUT_TEXT:
			output->response_type = OUT_TEXT;
			append("Index of ", server_error);
			append(input->url, server_error);
			append("\n\n", server_error);
			break;
		case OUT_HTML:
			if (!construct_html_head(&output->text)) goto server_error;
			append(TITLE_START, server_error);
			append_escape("Index of ", server_error);
			append_escape(input->url, server_error);
			append(TITLE_END, server_error);
			if (!construct_html_body(&output->text, NULL)) goto server_error;
			append_escape("Index of ", server_error);
			append_escape(input->url, server_error);
			if (!construct_html_main(&output->text)) goto server_error;
			append("<ul>\n", server_error);
			break;
		case OUT_JSON:
			dir_array = cJSON_CreateArray();
			cJSON_AddItemToObject(output->json_root, "children", dir_array);
			cjson_add_file_details(output->json_root, input->file, input->url, NULL, NULL);
			break;
	}

	bool res;
	if (!input->is_root_url) {
		// add parent directory link
		struct file_detail parent_file = {.dir = NULL, .fp = NULL};
		if (open_file(input->filepath_parent, &parent_file, cls, true, false)) {
			res = add_dir_item(output->response_type, &output->text, parent_file, input->url_parent, "..", dir_array, "parent", "parent directory");
			close_file(&parent_file);
			if (!res) goto server_error;
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
		if (!open_file(child_filepath, &child_file, cls, true, false)) continue; // skip if cannot open file

		char child_url[PATH_MAX];
		memcpy(child_url, input->url, PATH_MAX);
		if (!join_url_path(child_url, PATH_MAX, child_name)) continue;

		res = add_dir_item(output->response_type, &output->text, child_file, child_url, child_name, dir_array, "child", NULL);

		close_file(&child_file);

		if (!res) goto server_error;
	}

	if (output->response_type == OUT_HTML) {
		append("</ul>", server_error);
		if (!construct_html_end(&output->text)) goto server_error;
	}

	if (output->response_type != OUT_JSON) {
		append("\n", server_error);
		output->data_memory = MHD_RESPMEM_MUST_FREE;
		output->size = strlen(output->text);
	}
	return serve_ok;

server_error:
	if (output->data) free(output->data); // free the data if it was allocated
	return serve_not_found;
}
