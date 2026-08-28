#!/usr/bin/env python3
"""Vulnerable test server for XSS scanner testing."""
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>VulnTest</title>
<script>
function domSink() {{
  var hash = location.hash;
  document.getElementById('hash-out').innerHTML = hash;
}}
</script>
</head><body>
<h1>Vulnerable Test Server</h1>
<form method="get" action="/">
  <input type="text" name="search" value="{search}">
  <input type="text" name="name" value="{name}">
  <button type="submit">Search</button>
</form>
<div id="result">Search: {search}</div>
<div id="name">Name: {name}</div>
<div id="ref">Referer: {ref}</div>
<div id="ua">UA: {ua}</div>
<div id="hash-out"></div>
<form method="post" action="/">
  <textarea name="comment">{comment}</textarea>
  <button type="submit">Post Comment</button>
</form>
<div id="comments">{comments}</div>
<script src="/test.js"></script>
</body></html>
"""

TEST_JS = """function updateContent() {
    var input = document.getElementById('user-input');
    if (input) document.getElementById('output').innerHTML = input.value;
}
function evilEval(data) { eval(data); }
function processMessage(event) {
    document.getElementById('msg').innerHTML = event.data;
}
window.addEventListener('message', processMessage);
"""

comments_store = []

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        search = params.get('search', [''])[0]
        name = params.get('name', [''])[0]
        ref = self.headers.get('Referer', '')
        ua = self.headers.get('User-Agent', '')
        comment = params.get('comment', [''])[0]

        if parsed.path == '/test.js':
            self.send_response(200)
            self.send_header('Content-Type', 'application/javascript')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(TEST_JS.encode())
            return

        comments_html = ''.join(f'<p>Comment: {c}</p>' for c in comments_store[-5:])
        html = HTML.format(
            search=search, name=name, ref=ref, ua=ua,
            comment=comment,
            comments=comments_html + (f'<p>Comment: {comment}</p>' if comment else '')
        )
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Set-Cookie', 'testcookie=testvalue; path=/')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode() if length else ''
        params = urllib.parse.parse_qs(body)
        comment = params.get('comment', [''])[0]
        if comment:
            comments_store.append(comment)
        search = params.get('search', [''])[0]
        name = params.get('name', [''])[0]
        ref = self.headers.get('Referer', '')
        ua = self.headers.get('User-Agent', '')
        comments_html = ''.join(f'<p>Comment: {c}</p>' for c in comments_store[-5:])
        html = HTML.format(
            search=search, name=name, ref=ref, ua=ua,
            comment='', comments=comments_html
        )
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def log_message(self, format, *args):
        pass

if __name__ == '__main__':
    server = HTTPServer(('127.0.0.1', 8089), Handler)
    print('Test server on http://127.0.0.1:8089')
    server.serve_forever()
