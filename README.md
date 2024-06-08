# http-server

### Simple file HTTP server in C [Work in progress]

This is a simple HTTP server that serves files from a directory. It is written in C and uses the libmicrohttpd library and cJSON.

The server supports directory listing and file preview.

Working on:

- [ ] Read files from disk to serve
  - [ ] File caching
- [ ] File preview
  - [ ] Text
    - [ ] Syntax highlighting
  - [ ] Images
  - [ ] Audio
  - [ ] Video
- [ ] Code cleanup

Planned features:

- [ ] Custom index page
- [ ] Custom cache control
- [ ] Signal to drop cache
