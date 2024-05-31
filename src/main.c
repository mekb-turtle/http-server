#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <signal.h>
#include <errno.h>

#include <arpa/inet.h>
#include <microhttpd.h>
#include "serve.h"

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

static struct MHD_Daemon *httpd;
static void signal_handler(int sig); // later in the code
static void handle_exit();

static struct option options_getopt[] = {
        {"help",      no_argument,       0, 'h'},
        {"version",   no_argument,       0, 'V'},
        {"address",   required_argument, 0, 'a'},
        {"port",      required_argument, 0, 'p'},
        {"quiet",     no_argument,       0, 'q'},
        {"dotfiles",  no_argument,       0, 'f'},
        {"symlink",   no_argument,       0, 's'},
        {"directory", no_argument,       0, 'd'},
        {"notfound",  required_argument, 0, 'n'},
        {"404",       required_argument, 0, 'n'},
        {0,           0,                 0, 0  }
};

int main(int argc, char *argv[]) {
	bool invalid = false;
	int opt;

	char *address = NULL;
	unsigned short int family = 0;
	uint16_t port;
	bool port_set = false;

	struct httpd_data data;
	memset(&data, 0, sizeof(data));

	// argument handling
	while ((opt = getopt_long(argc, argv, ":hVa:p:qfsdn:", options_getopt, NULL)) != -1) {
		switch (opt) {
			case 'h':
				printf("Usage: %s [option]... [directory/file]\n", TARGET);
				printf("-h --help: Shows help text\n");
				printf("-V --version: Shows the version\n");
				printf("-a --address [address]: Set the address to listen on\n");
				printf("-p --port [port]: Set the port to listen on\n");
				printf("-q --quiet: Don't output logs\n");
				printf("-f --dotfiles: Allow serving files starting with `.`\n");
				printf("-s --symlink: Follow symlinks\n");
				printf("-d --directory: List directories\n");
				printf("-n --notfound --404 [directory/file]: Set what file to serve on 404\n");
				return 0;
			case 'V':
				printf("%s %s\n", TARGET, VERSION);
				return 0;
			default:
				if (!invalid) {
					switch (opt) {
						case 'q':
							if (data.quiet) invalid = true;
							else
								data.quiet = true;
							break;
						case 'f':
							if (data.dotfiles) invalid = true;
							else
								data.dotfiles = true;
							break;
						case 's':
							if (data.follow_symlinks) invalid = true;
							else
								data.follow_symlinks = true;
							break;
						case 'd':
							if (data.list_directories) invalid = true;
							else
								data.list_directories = true;
							break;
						case 'n':
							if (data.not_found_file) {
								// already set
								invalid = true;
								break;
							}
							char *filename_ = optarg;
							char filename[PATH_MAX];
							if (!filename_) filename_ = ".";
							if (!realpath(filename_, filename)) {
								eprintf("404 path: %s: %s\n", filename_, strerror(errno));
								return 1;
							}
							data.not_found_file = filename;
							break;
						case 'a':
							if (address) {
								// already set
								invalid = true;
								break;
							}
							address = optarg;
							break;
						case 'p':
							if (port_set) {
								// already set
								invalid = true;
								break;
							}
							for (char *c = optarg; *c; c++) // check for valid number
								if (*c < '0' || *c > '9' || (c - optarg) > 4) {
									invalid = true;
									break;
								}
							port = strtol(optarg, NULL, 10);
							if (port < 1 || port > 0xffff)
								invalid = true;
							port_set = true;
							break;
						default:
							invalid = true;
							break;
					}
				}
				break;
		}
	}

	if (optind != argc || invalid) {
		eprintf("Invalid usage, try --help\n");
		return 1;
	}

	if (!address) address = "127.0.0.1";
	if (!port_set) port = 8080;

	// get real file path
	char *filename_ = argv[optind];
	char filename[PATH_MAX];
	if (!filename_) filename_ = ".";
	if (!realpath(filename_, filename)) {
		eprintf("Base path: %s\n", filename_);
		return 1;
	}

	data.base_file = filename;

	// parse IP address
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	void *addr = NULL;
	memset(&addr4, 0, sizeof(addr4));
	memset(&addr6, 0, sizeof(addr6));
	if (inet_pton(AF_INET, address, &addr4.sin_addr) == 1) {
		// valid ipv4 address
		family = addr4.sin_family = AF_INET;
		addr4.sin_port = htons(port);
		addr = &addr4;
	} else if (inet_pton(AF_INET6, address, &addr6.sin6_addr) == 1) {
		// valid ipv6 address
		family = addr6.sin6_family = AF_INET6;
		addr6.sin6_port = htons(port);
		addr = &addr6;
	} else {
		// invalid address
		eprintf("Invalid address: %s\n", address);
		return 1;
	}

	if (chdir(data.base_file) != 0) {
		eprintf("Failed to change directory to %s\n", data.base_file);
		return 1;
	}

	if (!data.quiet) {
		printf("Listening on %s port %i at %s\n", address, port, data.base_file);
		printf("Allow serving files starting with `.`: %s\n", data.dotfiles ? "yes" : "no");
		printf("Follow symlinks: %s\n", data.follow_symlinks ? "yes" : "no");
		printf("List directories: %s\n", data.list_directories ? "yes" : "no");
		printf("Not found page: %s\n", data.not_found_file ? data.not_found_file : "none");
		printf("\n");
	}

	// start http server
	httpd = MHD_start_daemon(
	        MHD_USE_INTERNAL_POLLING_THREAD | (family == AF_INET6 ? MHD_USE_IPv6 : 0),
	        port,
	        NULL, NULL,                   // accept policy callback
	        &answer_to_connection, &data, // access handler callback
	        MHD_OPTION_SOCK_ADDR, addr, MHD_OPTION_END);
	if (!httpd) {
		eprintf("Failed to start server\n");
		return 1;
	}

	// wait for exit
	atexit(handle_exit);
	for (int i = 0; i < NSIG; ++i) {
		if (i == SIGKILL || i == SIGSTOP) continue;
		signal(i, signal_handler);
	}
	while (true) pause();
}

static void signal_handler(int sig) {
	if (sig == SIGTSTP) return;
	printf("Caught signal %i\n", sig);
	exit(0x80 + sig);
}

static void handle_exit() {
	if (httpd) {
		MHD_stop_daemon(httpd);
		httpd = NULL;
		printf("Stopped server...\n");
	}
}
