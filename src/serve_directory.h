#ifndef SERVE_DIRECTORY_H
#define SERVE_DIRECTORY_H
#include "serve.h"
// serve directory listing
extern enum serve_result serve_directory(const struct server_config *cls, struct input_data *input, struct output_data *output);
#endif
