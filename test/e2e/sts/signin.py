"""Stand-in for https://signin.aws.amazon.com/saml, which saml2aws list-roles
POSTs the assertion to so it can read account names. Like AWS, it renders the
role chooser page from the Role attributes in the posted assertion, and with
exactly one role skips the chooser and redirects to the console."""
import base64, html, re, ssl, sys, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROLE = re.compile(rb"arn:aws:iam::(\d{12}):role/[\w+=,.@/-]+")

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        form = urllib.parse.parse_qs(body.decode())
        assertion = base64.b64decode(form.get("SAMLResponse", [""])[0] or b"")
        accounts = {}
        for m in ROLE.finditer(assertion):
            accounts.setdefault(m.group(1).decode(), set()).add(m.group(0).decode())
        if sum(len(r) for r in accounts.values()) == 1:
            self.send_response(302)
            self.send_header("Location", "https://console.aws.amazon.com/console/home")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        parts = []
        for acct, roles in sorted(accounts.items()):
            labels = "".join(
                f'<div class="saml-role"><input type="radio" name="roleIndex" value="{html.escape(r)}">'
                f'<label for="{html.escape(r)}" class="saml-role-description">{html.escape(r.split("/", 1)[1])}</label></div>'
                for r in sorted(roles))
            parts.append(f'<div class="saml-account"><div class="saml-account-name">Account: e2e ({acct})</div>{labels}</div>')
        page = f"<html><body><form><fieldset>{''.join(parts)}</fieldset></form></body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

server = ThreadingHTTPServer(("0.0.0.0", 443), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
