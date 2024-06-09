# http-server

### Simple file HTTP server in C [Work in progress]

This is a simple HTTP server that serves files from a directory. It is written in C and uses the libmicrohttpd library and cJSON.

The server supports directory listing and file preview.

Working on:

- [ ] Read files from disk to serve
  - [x] File caching
- [x] Directory listing
- [ ] File preview
  - [ ] Text
    - [ ] Syntax highlighting
  - [ ] Images
  - [ ] Audio
  - [ ] Video

Planned features:

- [ ] Code cleanup
- [ ] Documentation
- [ ] Finer control over the server
  - [ ] Cache control
  - [ ] Custom index page
  - [ ] Custom error pages
  - [ ] Set specific MIME types which are served as raw data (without file preview)
- [ ] Signal to drop cache
