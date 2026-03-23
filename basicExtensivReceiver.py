#!/usr/bin/env python3
"""HTTP(S) webhook receiver for Extensiv 3PL Warehouse Manager.

This server listens for incoming webhook POST requests from Extensiv and
prints the connection security details, HTTP headers, and JSON payload to
the console.  It is intended as a starting point for integrators — you
will likely want to replace (or extend) the print statements with your
own business logic, e.g. writing to a database, forwarding to another
service, or triggering a workflow.

HOW EXTENSIV WEBHOOKS WORK
---------------------------
1. You configure a webhook URL in the Extensiv portal (your server's address).
2. When an event occurs in Extensiv (e.g. an order is confirmed), their
   system sends an HTTP POST to that URL.
3. The POST contains a JSON payload with event details.
4. Your server MUST reply with an HTTP 200 within 3 seconds.  Extensiv will
   retry failed deliveries for ~6 hours before moving to a dead-letter queue.
5. Extensiv signs each payload with an RSA private key.  The signature is
   included in the payload's "headers.Signature" field.  You can use this to
   verify the message has not been tampered with (see _print_rsa_status and
   the Extensiv documentation for validation details).

OBSERVED BEHAVIOR (Extensiv sandbox, March 2026)
-------------------------------------------------
POST / HTTP/1.1
Client: 3.15.26.72:52654
Transport: TLSv1.3 / TLS_AES_256_GCM_SHA384
Signature header sent as a top-level HTTP header (not inside the JSON body).

NOTE ON SELF-SIGNED CERTIFICATES
---------------------------------
Extensiv's webhook sender validates your server certificate against a trusted
CA.  Self-signed certificates will be rejected.  Use a certificate from a
public CA such as Let's Encrypt (see README.md for setup instructions).
"""

# ---------------------------------------------------------------------------
# Standard library imports
# ---------------------------------------------------------------------------
import json       # for parsing the JSON webhook payload
import logging    # for structured log output with timestamps and levels
import os         # for reading environment variables and file paths
import ssl        # for TLS (HTTPS) support
import sys        # for sys.exit() on fatal errors
import traceback  # for printing full stack traces when errors occur
from http.server import HTTPServer, BaseHTTPRequestHandler
#   HTTPServer      — the base TCP server that listens for connections
#   BaseHTTPRequestHandler — base class we subclass to handle POST/GET
from socketserver import ThreadingMixIn
#   ThreadingMixIn  — mixin that makes each connection run in its own thread,
#                     so multiple simultaneous webhook deliveries don't queue

# ---------------------------------------------------------------------------
# Third-party imports (install via: pip install -r requirements.txt)
# ---------------------------------------------------------------------------
from dotenv import load_dotenv
#   load_dotenv()   — reads key=value pairs from a .env file into os.environ,
#                     so we can configure the server without hardcoding values

# ---------------------------------------------------------------------------
# Logging setup
#
# The logging module writes timestamped messages to the console.  Each message
# has a level: DEBUG (most verbose) → INFO → WARNING → ERROR → CRITICAL.
# Setting level=DEBUG means ALL messages are shown.  Change to INFO to hide
# the debug-level request lines if the output becomes too noisy.
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DebugHTTPServer
#
# We subclass HTTPServer to add two capabilities:
#   1. Threading  — handle multiple connections at the same time
#   2. Better error logging — surface TLS handshake failures that would
#      otherwise be silently swallowed by the base server
# ---------------------------------------------------------------------------
class DebugHTTPServer(ThreadingMixIn, HTTPServer):
    """Threaded HTTPServer: each connection is handled in its own thread.

    ThreadingMixIn must come before HTTPServer in the MRO so that
    process_request() is overridden to spawn a thread per connection,
    allowing multiple simultaneous webhook deliveries without queuing.
    """

    # daemon_threads=True means worker threads are automatically killed when
    # the main program exits (e.g. Ctrl+C).  Without this, the server could
    # hang waiting for in-flight requests to finish.
    daemon_threads = True

    def get_request(self):
        # get_request() is called once per incoming TCP connection, before the
        # HTTP handler runs.  When TLS is enabled, the TLS handshake happens
        # here.  If the client sends garbage or plain HTTP instead of a TLS
        # ClientHello, Python raises ssl.SSLError.
        #
        # The base socketserver catches OSError (the parent of SSLError) and
        # silently discards it — we'd never see the error at all.  By catching
        # it here first, we can log it before re-raising.
        try:
            return super().get_request()
        except ssl.SSLError as e:
            logger.error("TLS handshake failed: %s", e)
            raise  # re-raise so the base class can clean up the socket

    def handle_error(self, request, client_address):
        # handle_error() is called when an exception escapes from the handler
        # (i.e. after a connection was successfully accepted and a handler was
        # running).  We log the full traceback at ERROR level so it's always
        # visible in the console.
        logger.error(
            "Connection error from %s:%s\n%s",
            client_address[0],
            client_address[1],
            traceback.format_exc(),
        )


# ---------------------------------------------------------------------------
# PostPrinterHandler
#
# This is where you will spend most of your time as an integrator.
#
# BaseHTTPRequestHandler gives us one method per HTTP verb: do_GET, do_POST,
# do_PUT, etc.  We implement do_POST (webhooks arrive as POSTs) and do_GET
# (for a quick browser health check).
#
# TO CUSTOMIZE: Look for the "--- YOUR BUSINESS LOGIC GOES HERE ---" section
# inside do_POST.  That is where you process the parsed payload.
# ---------------------------------------------------------------------------
class PostPrinterHandler(BaseHTTPRequestHandler):
    """Handles incoming HTTP requests and prints webhook details to the console."""

    # ------------------------------------------------------------------
    # Logging overrides
    #
    # By default, BaseHTTPRequestHandler writes log lines to stderr via
    # sys.stderr.write().  We redirect them through Python's logging
    # module so all output shares the same timestamp format and log level.
    # ------------------------------------------------------------------

    def log_message(self, format, *args):
        # Called for every successful request (e.g. "POST / 200")
        logger.info("%s - %s", self.address_string(), format % args)

    def log_error(self, format, *args):
        # Called when the handler itself encounters a protocol-level error
        # (e.g. a malformed request line)
        logger.error("%s - %s", self.address_string(), format % args)

    def log_request(self, code="-", size="-"):
        # Called at the end of each request with the status code and response
        # size.  We log at DEBUG so it doesn't clutter normal output.
        logger.debug("%s - %s %s", self.address_string(), self.requestline, code)

    # ------------------------------------------------------------------
    # _print_connection_security
    #
    # Inspects the underlying socket to determine whether the connection
    # is TLS-encrypted and, if so, what cipher suite and protocol version
    # were negotiated.
    # ------------------------------------------------------------------
    def _print_connection_security(self):
        """Print TLS encryption details (or warn that the connection is plain HTTP)."""
        sock = self.connection  # the raw socket for this connection

        # ssl.SSLSocket is a subclass of socket.socket that wraps a TLS
        # connection.  If TLS is disabled, this is a plain socket.socket.
        is_tls = isinstance(sock, ssl.SSLSocket)

        print("CONNECTION SECURITY:")
        if is_tls:
            tls_version = sock.version()
            # sock.cipher() returns a 3-tuple:
            #   (cipher_name, tls_protocol_version, key_length_in_bits)
            # e.g. ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
            cipher_name, proto, key_bits = sock.cipher()

            # getpeercert() returns the client's certificate if mutual TLS
            # (mTLS) was configured.  Extensiv does not send a client cert,
            # so this will normally be an empty dict.
            peer_cert = sock.getpeercert()

            print(f"  Transport     : TLS (encrypted)")
            print(f"  TLS version   : {tls_version}")
            print(f"  Cipher suite  : {cipher_name}")
            print(f"  Key strength  : {key_bits} bits")
            print(f"  Protocol      : {proto}")
            if peer_cert:
                # If a client certificate was presented, print its subject
                # (e.g. CN=client.example.com)
                subject = dict(x[0] for x in peer_cert.get("subject", []))
                print(f"  Client cert   : {subject}")
            else:
                print(f"  Client cert   : none (server-side TLS only)")
        else:
            # Plain HTTP — the connection is not encrypted.  Extensiv can be
            # configured at the portal level to send HTTP or HTTPS.
            print("  Transport     : plain HTTP (unencrypted)")

    # ------------------------------------------------------------------
    # _print_rsa_status
    #
    # Extensiv signs every webhook payload with an RSA private key.  The
    # base-64 encoded signature is included in the payload so you can verify
    # the message was really sent by Extensiv and has not been modified in
    # transit.  This method just prints the signature for inspection.
    #
    # TO ADD VALIDATION: See https://help.extensiv.com/en_US/rest-api/
    # implementing-webhooks for the public key endpoint and verification steps.
    # ------------------------------------------------------------------
    def _print_rsa_status(self, sig):
        """Print the Extensiv RSA signature value (or warn if it is absent)."""
        print("RSA SIGNATURE (Extensiv payload):")
        if sig:
            print(f"  Present       : yes")
            print(f"  Algorithm     : SHA-256 / RSA (base64-encoded)")
            print(f"  Value         : {sig}")
            # TODO: Perform actual signature validation here before you trust
            #       the payload in a production system.  See README.md for
            #       a link to Extensiv's validation documentation.
            print(f"  Validation    : not performed (capture mode)")
        else:
            # If the signature is missing, the payload should be treated as
            # unverified.  This may indicate a misconfigured sender or a
            # non-Extensiv source.
            print(f"  Present       : no  ← payload may be missing Signature header")

    # ------------------------------------------------------------------
    # do_POST  ← THIS IS THE MAIN ENTRY POINT FOR WEBHOOK EVENTS
    #
    # Python's BaseHTTPRequestHandler calls do_POST() automatically whenever
    # an HTTP POST request arrives.  Extensiv sends all webhook events as
    # POST requests.
    # ------------------------------------------------------------------
    def do_POST(self):
        # ------------------------------------------------------------------
        # Step 1: Read the request body
        #
        # HTTP POST bodies are preceded by a Content-Length header that tells
        # us exactly how many bytes to read.  We must read exactly that many
        # bytes — reading more would block waiting for a connection that has
        # already sent everything.
        # ------------------------------------------------------------------
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length) if content_length > 0 else b""

        # ------------------------------------------------------------------
        # Step 2: Send HTTP 200 immediately
        #
        # Extensiv's webhook system waits a maximum of 3 seconds for a
        # response before marking the delivery as failed and scheduling a
        # retry.  We respond with 200 OK RIGHT NOW, before doing any
        # processing, to avoid timeouts.
        #
        # If you change this to a non-2xx code (e.g. 500) Extensiv will treat
        # it as a failure and retry the delivery.
        # ------------------------------------------------------------------
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK\n")

        # ------------------------------------------------------------------
        # Step 3: Print connection and request details to the console
        # ------------------------------------------------------------------
        print("=" * 60)
        print(f"POST {self.path} {self.request_version}")
        print(f"Client: {self.client_address[0]}:{self.client_address[1]}")
        print("-" * 60)

        self._print_connection_security()
        print("-" * 60)

        # Print every HTTP header sent by Extensiv.  Headers include things
        # like Content-Type, Content-Length, Host, and the Signature.
        print("HTTP HEADERS:")
        for name, value in self.headers.items():
            print(f"  {name}: {value}")

        # Handle the case where no body was sent (unusual for webhooks, but
        # we guard against it to avoid errors)
        if not raw_body:
            self._print_rsa_status(None)
            print("(empty body)")
            print("=" * 60)
            print()
            return

        # ------------------------------------------------------------------
        # Step 4: Decode and parse the body
        #
        # Extensiv always sends UTF-8 encoded JSON.  We try to parse it and
        # extract the Extensiv-specific envelope structure:
        #
        #   {
        #     "headers": { "Signature": "<base64>" },
        #     "body": { ...event data... }
        #   }
        #
        # If the body is not valid JSON (e.g. during testing with curl), we
        # fall back to printing the raw text.
        # ------------------------------------------------------------------
        decoded = raw_body.decode("utf-8", errors="replace")

        try:
            payload = json.loads(decoded)

            # Extract the RSA signature from the Extensiv envelope.  Extensiv
            # wraps the actual event body inside a "body" key and puts the
            # signature in a nested "headers" dict.
            sig = None
            if isinstance(payload.get("headers"), dict):
                sig = payload["headers"].get("Signature")

            # The actual event data lives under the "body" key.  If the
            # structure is unexpected (e.g. a test payload), fall back to
            # printing the entire parsed object.
            body = payload.get("body", payload)

            print("-" * 60)
            self._print_rsa_status(sig)
            print("-" * 60)
            print("PAYLOAD:")
            # json.dumps with indent=2 pretty-prints the JSON so it is
            # easy to read in the console
            print(json.dumps(body, indent=2))

        except (json.JSONDecodeError, TypeError):
            # Not valid JSON — print as raw text.  This happens when testing
            # with tools like curl that send plain text bodies.
            self._print_rsa_status(None)
            print("-" * 60)
            print("RAW BODY:")
            print(f"  {decoded}")

        print("=" * 60)
        print()

        # ------------------------------------------------------------------
        # --- YOUR BUSINESS LOGIC GOES HERE ---
        #
        # At this point you have:
        #   body   — a Python dict with the parsed Extensiv event data
        #   sig    — the RSA signature string (or None)
        #
        # Example fields in `body` (varies by event type):
        #   body["eventType"]          — e.g. "OrderConfirm", "ReceiptPost"
        #   body["tplId"]              — your warehouse's ID in Extensiv
        #   body["wmsEventId"]         — unique event ID
        #   body["eventDateTimeUtc"]   — when the event occurred (UTC)
        #   body["resource"]["href"]   — REST API path to fetch the full resource
        #   body["data"]               — JSON string with key event fields
        #
        # Ideas for what to do here:
        #   - Parse body["eventType"] and route to different handlers
        #   - Write the event to a database or message queue
        #   - Call the Extensiv REST API to fetch additional details
        #   - Forward the event to another internal service
        #   - Send a notification (email, Slack, etc.)
        #
        # IMPORTANT: This code runs in a background thread (because we use
        # ThreadingMixIn).  If you access shared state (e.g. a global list or
        # a database connection pool), make sure it is thread-safe.
        # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # do_GET — simple health check endpoint
    #
    # Not used by Extensiv, but useful for checking that the server is
    # running by visiting the URL in a browser or with curl.
    # ------------------------------------------------------------------
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"POST endpoint ready.\n")


# ---------------------------------------------------------------------------
# main()
#
# Entry point: reads configuration from the .env file, optionally wraps
# the server socket in TLS, and starts listening for connections.
# ---------------------------------------------------------------------------
def main():
    # load_dotenv() reads the .env file in the current directory and copies
    # each KEY=VALUE line into os.environ.  Values already set in the
    # environment (e.g. from a systemd unit or Docker) take precedence.
    load_dotenv()

    # ------------------------------------------------------------------
    # Read configuration from environment variables
    # All of these can be set in the .env file (see .env.example).
    # ------------------------------------------------------------------

    # PORT — which TCP port to listen on.
    # 8443 is conventional for HTTPS on a non-standard port.
    # Ports below 1024 require root on Linux; 8443 does not.
    port = int(os.environ.get("SERVER_PORT", "8443"))

    # TLS certificate paths.  Both must be set to enable HTTPS.
    # Leave blank (or omit from .env) for plain HTTP.
    # IMPORTANT: Use fullchain.pem from Let's Encrypt, NOT cert.pem.
    #            Without the intermediate CA, clients will reject the cert.
    cert_file = os.environ.get("TLS_CERT_FILE", "").strip()
    key_file = os.environ.get("TLS_KEY_FILE", "").strip()

    # TLS is enabled only when BOTH paths are provided
    use_tls = bool(cert_file and key_file)

    # ------------------------------------------------------------------
    # Create the server
    #
    # "0.0.0.0" means "listen on all network interfaces" — the server
    # will accept connections on any IP address assigned to this machine.
    # Change to "127.0.0.1" to accept only local connections (useful for
    # development behind a reverse proxy like nginx).
    # ------------------------------------------------------------------
    server = DebugHTTPServer(("0.0.0.0", port), PostPrinterHandler)

    if use_tls:
        # Validate that the certificate and key files actually exist before
        # attempting to start — gives a clear error message instead of a
        # confusing Python exception later
        if not os.path.isfile(cert_file):
            logger.error("Certificate file not found: %s", cert_file)
            sys.exit(1)
        if not os.path.isfile(key_file):
            logger.error("Key file not found: %s", key_file)
            sys.exit(1)

        # SSLContext encapsulates TLS configuration (allowed protocol
        # versions, cipher suites, certificate, etc.)
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Enforce TLS 1.2 as the minimum.  TLS 1.0 and 1.1 are deprecated
        # and have known vulnerabilities.  Most clients (including Extensiv)
        # use TLS 1.2 or 1.3.
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Load the server's certificate chain and private key.
        # certfile should be the fullchain (server cert + intermediate CAs).
        ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)

        # Replace the plain TCP socket with a TLS-wrapped one.
        # server_side=True means this end performs the server role in the
        # TLS handshake (as opposed to the client role).
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    else:
        scheme = "http"
        logger.info("TLS_CERT_FILE / TLS_KEY_FILE not set — running plain HTTP")

    logger.info("Listening on %s://0.0.0.0:%s", scheme, port)

    # serve_forever() runs an event loop that accepts and dispatches
    # connections until interrupted.  Press Ctrl+C to stop.
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


# ---------------------------------------------------------------------------
# Standard Python entry-point guard.
#
# This block runs only when the script is executed directly:
#   python server.py
#
# It does NOT run when the file is imported as a module, which means other
# code could import PostPrinterHandler or DebugHTTPServer without starting
# the server.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    main()
