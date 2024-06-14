#include "serve_directory.h"
#include <string.h>
#include <stdlib.h>

#include "util.h"
#include "format_bytes.h"
#include "macro.h"

static bool add_dir_item(struct response_type response_type, char **base, struct file_detail file, char *url, char *name, cJSON *dir_array, char *class, char *custom_type) {
	char *size_format = NULL;

	if (!custom_type) {
		if (file.dir)
			custom_type = "directory";
		else if (file.fp)
			custom_type = "file";
		else
			custom_type = "unknown";
	}

	size_t size = get_file_size(file);
	char size_str[32];
	ASSERT(snprintf(size_str, 32, "%li", size) >= 0);
	size_format = format_bytes(size, binary_i);
	ASSERT(size_format);

	switch (response_type.type) {
		case OUT_NONE:
		case OUT_TEXT:
			append("- ");
			append(name);
			append(" - ");
			append(custom_type);
			if (file.fp) {
				append(" - ");
				append(size_format);
			}
			append("\n");
			break;
		case OUT_HTML:
			append("<li class=\"file-item");
			if (class && class[0] != '\0') {
				append(" ");
				append_escape(class);
			}
			append("\"><a href=\"");
			append_escape(url);
			append("\" title=\"");
			append_escape(url);
			append("\">");
			append_escape(name);
			append("</a>");
			append(" - <span class=\"file-type\">");
			append_escape(custom_type);
			append("</span>");
			if (file.fp) {
				append(" - <span class=\"file-size\" title=\"");
				append_escape(size_str);
				append(" bytes\">");
				append_escape(size_format);
				append("</span>");
			}
			append("</li>\n");
			break;
		case OUT_JSON:;
			cJSON *obj = cJSON_CreateObject();
			ASSERT(obj);
			ASSERT(cjson_add_file_details(obj, file, url, name));
			ASSERT(cJSON_AddItemToArray(dir_array, obj));
			break;
	}

	free(size_format);
	return true;
error:
	free(size_format);
	return false;
}

enum serve_result serve_directory(server_config cls, struct input_data *input, struct output_data *output) {
	if (!input->file.dir) return serve_not_found;
	if (!cls->list_directories) return serve_not_found; // directory listing not allowed
	cJSON *dir_array = NULL;                            // array of directory children
	char **base = &output->text;
	switch (output->response_type.type) {
		case OUT_NONE:
		case OUT_TEXT:
			output->response_type.type = OUT_TEXT;
			append("Index of ");
			append(input->url);
			append("\n\n");
			break;
		case OUT_HTML:
			ASSERT(construct_html_head(cls, input, output));
			append(TITLE_START);
			append_escape("Index of ");
			append_escape(input->url);
			append(TITLE_END);
			ASSERT(construct_html_body(cls, input, output, NULL, "Parent Directory"));
			append_escape("Index of ");
			append_escape(input->url);
			ASSERT(construct_html_main(cls, input, output));
			append("<ul>\n");
			break;
		case OUT_JSON:
			dir_array = cJSON_CreateArray();
			ASSERT(dir_array);
			ASSERT(cJSON_AddItemToObject(output->json_root, "children", dir_array));
			ASSERT(cjson_add_file_details(output->json_root, input->file, input->url, NULL));
			break;
	}

	bool res;
	if (has_parent_url(cls, input)) {
		// add parent directory link
		struct file_detail parent_file = {.dir = NULL, .fp = NULL};
		if (open_file(input->filepath_parent, &parent_file, cls, true)) {
			res = add_dir_item(output->response_type, &output->text, parent_file, input->url_parent, "..", dir_array, "parent", "parent directory");
			close_file(&parent_file);
			ASSERT(res);
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
		if (!join_url_path(child_url, PATH_MAX, child_name)) {
			close_file(&child_file);
			continue;
		}

		res = add_dir_item(output->response_type, &output->text, child_file, child_url, child_name, dir_array, "child", NULL);

		close_file(&child_file);

		ASSERT(res);
	}

	if (output->response_type.type == OUT_HTML) {
		append("</ul>");
		ASSERT(construct_html_end(cls, input, output));
	}

	ASSERT(append_text_footer(cls, output));

	if (output->response_type.type != OUT_JSON) {
		output->data_memory = MHD_RESPMEM_MUST_FREE;
		output->size = strlen(output->text);
	}
	return serve_ok;

error:
	if (output->data) free(output->data); // free the data if it was allocated
	return serve_error;
}
