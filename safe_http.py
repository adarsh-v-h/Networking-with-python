from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

class SafeHandler(SimpleHTTPRequestHandler):
    def send_error(self, code, message=None, explain=None):
        try:
            super().send_error(code, message, explain)
        except BrokenPipeError:
            # client closed connection while we were sending error body; ignore
            pass

    def finish(self):
        try:
            super().finish()
        except BrokenPipeError:
            pass

if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8080), SafeHandler)
    print("Serving on 0.0.0.0:8080")
    server.serve_forever()
