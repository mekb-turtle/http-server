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
#include "file_cache.h"
#include "magic.h"
#include "attribute.h"

static struct MHD_Daemon *httpd;
static void signal_handler(int sig); // later in the code
static void handle_exit();
static void flush_file_cache_() {
	printf("Flushing file cache...\n");
	flush_file_cache();
}

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
        {"no-footer", no_argument,       0, 'F'},
        {0,           0,                 0, 0  }
};

int main(int argc, char *argv[]) {
	bool invalid = false;
	int opt;

	char *address = NULL;
	unsigned short int family = 0;
	uint16_t port;
	bool port_set = false;

	struct server_config config;
	memset(&config, 0, sizeof(config));
	config.show_footer = true;

	char nf_filename[PATH_MAX];

	// argument handling
	while ((opt = getopt_long(argc, argv, ":hVa:p:qfsdn:F", options_getopt, NULL)) != -1) {
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
				printf("-F --no-footer: Don't show footer with server info\n");
				printf("-n --notfound --404 [file]: Set what file to serve on 404\n");
				printf("SIGUSR1 - Flush file cache\n");
				return 0;
			case 'V':
				printf("%s %s\n", TARGET, VERSION);
				return 0;
			default:
				if (!invalid) {
					switch (opt) {
						case 'q':
							if (config.quiet) invalid = true;
							else
								config.quiet = true;
							break;
						case 'f':
							if (config.dotfiles) invalid = true;
							else
								config.dotfiles = true;
							break;
						case 's':
							if (config.follow_symlinks) invalid = true;
							else
								config.follow_symlinks = true;
							break;
						case 'd':
							if (config.list_directories) invalid = true;
							else
								config.list_directories = true;
							break;
						case 'F':
							if (!config.show_footer) invalid = true;
							else
								config.show_footer = false;
							break;
						case 'n':
							if (config.not_found_file) {
								// already set
								invalid = true;
								break;
							}
							if (!realpath(optarg, nf_filename)) {
								eprintf("404 file: %s: %s\n", optarg, strerror(errno));
								return 1;
							}
							config.not_found_file = nf_filename;
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

	if ((optind != argc && optind != argc - 1) || invalid) {
		eprintf("Invalid usage, try --help\n");
		return 1;
	}

	if (!address) address = "127.0.0.1";
	if (!port_set) port = 8080;

	// get real file path
	char *filename_ = optind == argc - 1 ? argv[optind] : ".";
	char filename[PATH_MAX];
	if (!realpath(filename_, filename)) {
		eprintf("Invalid base path: %s\n", filename_);
		return 1;
	}

	config.base_file = filename;

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

	// stat base file
	struct stat st;
	if (stat(config.base_file, &st) != 0) {
		eprintf("Invalid base path: %s\n", config.base_file);
		return 1;
	}
	if (S_ISDIR(st.st_mode) && chdir(config.base_file) != 0) {
		eprintf("Failed to change directory to %s\n", config.base_file);
		return 1;
	}

	if (!config.quiet) {
		printf("Listening on %s port %i at %s\n", address, port, config.base_file);
		printf("Allow serving files starting with `.`: %s\n", config.dotfiles ? "yes" : "no");
		printf("Follow symlinks: %s\n", config.follow_symlinks ? "yes" : "no");
		printf("List directories: %s\n", config.list_directories ? "yes" : "no");
		printf("Not found page: %s\n", config.not_found_file ? config.not_found_file : "none");
		printf("\n");
	}

	// start http server
	httpd = MHD_start_daemon(
	        MHD_USE_INTERNAL_POLLING_THREAD | (family == AF_INET6 ? MHD_USE_IPv6 : 0),
	        port,
	        NULL, NULL,                     // accept policy callback
	        &answer_to_connection, &config, // access handler callback
	        MHD_OPTION_SOCK_ADDR, addr, MHD_OPTION_END);
	if (!httpd) {
		eprintf("Failed to start server\n");
		return 1;
	}

	// wait for exit
	atexit(handle_exit);
	int signals[] = {
	        SIGABRT,
	        SIGALRM,
	        SIGHUP,
	        SIGINT,
	        SIGPIPE,
	        SIGQUIT,
	        SIGTERM,
	        SIGPOLL,
	        SIGPROF,
	        SIGVTALRM};
	for (int i = 0; i < sizeof(signals) / sizeof(signals[0]); i++)
		signal(signals[i], signal_handler);
	signal(SIGUSR1, flush_file_cache_);
	signal(SIGUSR2, signal_handler);
	while (true) pause();
}

static void signal_handler(int sig) {
	printf("Caught signal %i\n", sig);
	exit(0x80 + sig);
}

static void handle_exit() {
	if (httpd) {
		MHD_stop_daemon(httpd);
		httpd = NULL;
		printf("Stopped server...\n");
	}
	close_magic();
	free_file_cache();
}
