#!/usr/bin/env python3
import http.server
import os

PORT = 5051
DIR = os.path.dirname(os.path.abspath(__file__))

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIR, **kwargs)

    def log_message(self, fmt, *args):
        print(f"[website] {fmt % args}")

if __name__ == '__main__':
    with http.server.HTTPServer(('', PORT), Handler) as httpd:
        print(f"Sentinel Core website running at http://localhost:{PORT}")
        httpd.serve_forever()
