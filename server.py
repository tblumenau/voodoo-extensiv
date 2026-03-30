#!/usr/bin/env python3
"""Extensiv Webhook Receiver — Order & Pick Parser

This server listens for incoming webhook POST requests from Extensiv's
3PL Warehouse Manager, extracts actionable pick data from order events,
and forwards orders to the Voodoo Robotics API.

WHAT THIS DOES
--------------
When Extensiv sends a webhook (e.g. an OrderPickJobUserAssigned event),
this server:
  1. Responds with HTTP 200 immediately (Extensiv times out after 3 seconds)
  2. Parses the JSON payload to extract the Order ID
  3. Walks through each order item's "allocations" to build a pick list
  4. Prints the Order ID and pick list to the console
  5. Logs all activity to a log file (configured in .env)
  6. Forwards the order to (or removes it from) the Voodoo Robotics API
     depending on the event type

WHAT IS A "PICK"?
-----------------
In warehouse terminology, a "pick" is an instruction to go to a specific
location in the warehouse, grab a specific quantity of a specific SKU, and
bring it to the packing station.  Each allocation in the Extensiv payload
represents one pick — one location where inventory has been reserved for
this order.

HOW THE JSON IS STRUCTURED (simplified)
----------------------------------------
  payload
  └── resource
      └── body
          └── _embedded
              └── http://api.3plCentral.com/rels/orders/item  (array of order items)
                  └── readOnly
                      └── allocations  (array — one per pick location)
                          ├── qty                              → pick quantity
                          └── detail
                              ├── itemTraits
                              │   ├── itemIdentifier.sku       → SKU to pick
                              │   └── lotNumber                → lot (if present)
                              └── locationIdentifier
                                  └── nameKey.name             → warehouse location

See exampleOrder.json for a complete real-world payload.

SUPPORTED EVENTS
----------------
    Configured via a JSON task file referenced by TASKS_FILE. Example:

        {
            "OrderPickJobUserAssigned": ["DELETE", "ADD"],
            "OrderExcludedFromPickJob": ["DELETE"]
        }

  Available actions: DELETE (remove order from Voodoo), ADD (create order),
    LAUNCH (launch order), ABORT (abort order).
    Events not listed in the task file are logged and ignored.

CONFIGURATION (.env file)
-------------------------
    SERVER_PORT         — TCP port to listen on (default: 8443)
    TLS_CERT_FILE       — path to fullchain.pem (from Let's Encrypt)
    TLS_KEY_FILE        — path to privkey.pem
    LOG_LEVEL           — logging threshold (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    LOG_FILE            — path to the log file (default: webhook.log)
    VOODOO_API_ENDPOINT — base URL of the Voodoo Robotics Orders API
    VOODOO_API_KEY      — API key used to authenticate with Voodoo
    TASKS_FILE          — path to a JSON file mapping event types to action lists
                                                e.g. tasks.json
    TASKS               — legacy inline JSON mapping (still supported but not
                                                recommended for larger configurations)
    TIGHT_SECURITY      — set to "true" to require HTTPS and Extensiv signatures
    EXTENSIV_PUBLIC_KEY_CACHE_FILE — JSON cache file for Extensiv's webhook key
                                                response (publicKey + retrievalDateISO)
"""

# ---------------------------------------------------------------------------
# Standard library imports
# ---------------------------------------------------------------------------
import base64  # for decoding the base64-encoded RSA signature
import json  # for parsing the JSON webhook payload
import logging  # for structured logging to console AND file
import os  # for reading environment variables and file paths
import ssl  # for TLS (HTTPS) support
import sys  # for sys.exit() on fatal errors
import traceback  # for printing full stack traces on errors
from http.server import BaseHTTPRequestHandler, HTTPServer

#   HTTPServer             — the base TCP server that listens for connections
#   BaseHTTPRequestHandler — base class we subclass to handle POST/GET requests
from socketserver import ThreadingMixIn

import requests  # for making HTTP requests to Voodoo's API

#   ThreadingMixIn — makes each connection run in its own thread so multiple
#                    simultaneous webhook deliveries don't block each other
# ---------------------------------------------------------------------------
# Third-party imports (install via: pip install -r requirements.txt)
# ---------------------------------------------------------------------------
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

#   Used to verify RSA-SHA256 signatures from Extensiv when TIGHT_SECURITY is on
from dotenv import load_dotenv

#   load_dotenv() reads key=value pairs from a .env file into os.environ


EXTENSIV_WEBHOOK_KEY_URL = "https://secure-wms.com/events/webhook/key"


def parse_log_level(level_name):
    """Convert a LOG_LEVEL string into a Python logging level."""
    normalized_level = (level_name or "INFO").strip().upper()
    level = getattr(logging, normalized_level, None)
    if isinstance(level, int):
        return level, normalized_level

    return logging.INFO, "INFO"


def load_cached_extensiv_key(cache_file_path):
    """Load the cached Extensiv webhook key response from disk."""
    if not cache_file_path or not os.path.isfile(cache_file_path):
        return None

    try:
        with open(cache_file_path, "r", encoding="utf-8") as file_obj:
            key_payload = json.load(file_obj)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning(
            "Failed to read cached Extensiv key file %s: %s", cache_file_path, e
        )
        return None

    if not key_payload.get("publicKey"):
        logger.warning(
            "Cached Extensiv key file %s does not contain publicKey", cache_file_path
        )
        return None

    return key_payload


def write_cached_extensiv_key(cache_file_path, key_payload):
    """Persist the Extensiv webhook key response for future startups."""
    cache_dir = os.path.dirname(cache_file_path)
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)

    with open(cache_file_path, "w", encoding="utf-8") as file_obj:
        json.dump(key_payload, file_obj, indent=2)
        file_obj.write("\n")


def refresh_extensiv_public_key(cache_file_path):
    """Fetch the latest Extensiv webhook public key, using cached metadata when available."""
    cached_key_payload = load_cached_extensiv_key(cache_file_path)
    request_timeout = 10

    try:
        if cached_key_payload and cached_key_payload.get("retrievalDateISO"):
            response = requests.post(
                EXTENSIV_WEBHOOK_KEY_URL,
                json={
                    "previousRetrievalDateISO": cached_key_payload["retrievalDateISO"]
                },
                timeout=request_timeout,
            )

            if response.status_code == 304:
                logger.info(
                    "Extensiv public key unchanged since %s",
                    cached_key_payload["retrievalDateISO"],
                )
                return cached_key_payload["publicKey"]
        else:
            response = requests.get(EXTENSIV_WEBHOOK_KEY_URL, timeout=request_timeout)

        response.raise_for_status()
        key_payload = response.json()
        public_key = key_payload.get("publicKey", "").strip()
        retrieval_date_iso = key_payload.get("retrievalDateISO", "").strip()

        if not public_key:
            raise ValueError("Extensiv key response did not include publicKey")

        if not retrieval_date_iso:
            raise ValueError("Extensiv key response did not include retrievalDateISO")

        write_cached_extensiv_key(cache_file_path, key_payload)
        logger.info("Retrieved Extensiv public key from %s", EXTENSIV_WEBHOOK_KEY_URL)
        logger.info("Cached Extensiv public key metadata at %s", cache_file_path)
        return public_key

    except (requests.RequestException, ValueError, OSError) as e:
        logger.warning(
            "Failed to refresh Extensiv public key from %s: %s",
            EXTENSIV_WEBHOOK_KEY_URL,
            e,
        )

    if cached_key_payload and cached_key_payload.get("publicKey"):
        logger.warning("Using cached Extensiv public key from %s", cache_file_path)
        return cached_key_payload["publicKey"]

    return None


def load_tasks_config():
    """Load the event-to-actions mapping from TASKS_FILE or legacy TASKS."""
    tasks_file = os.environ.get("TASKS_FILE", "").strip()
    if tasks_file:
        try:
            with open(tasks_file, "r", encoding="utf-8") as file_obj:
                tasks = json.load(file_obj)
        except OSError as e:
            logger.error("Failed to read TASKS_FILE %s: %s", tasks_file, e)
            return None
        except json.JSONDecodeError as e:
            logger.error("Failed to parse TASKS_FILE %s as JSON: %s", tasks_file, e)
            return None

        logger.info("Loaded task configuration from %s", tasks_file)
        return tasks

    tasks_raw = os.environ.get("TASKS", "").strip()
    if not tasks_raw:
        logger.warning("TASKS_FILE or TASKS not set in .env file")
        return None

    try:
        tasks = json.loads(tasks_raw)
    except (json.JSONDecodeError, TypeError) as e:
        logger.error("Failed to parse TASKS env variable as JSON: %s", e)
        return None

    logger.warning("Using legacy TASKS env var. Prefer TASKS_FILE for maintainability.")
    return tasks


# ---------------------------------------------------------------------------
# setup_logging()
#
# Sets up Python's logging module to write messages to BOTH:
#   1. The console (stdout) — so you can see what's happening in real time
#   2. A log file           — so you have a persistent record
#
# The log file path comes from the LOG_FILE environment variable.  If the
# file doesn't exist yet, Python's logging module creates it automatically.
# ---------------------------------------------------------------------------
def setup_logging(log_file_path, log_level):
    """Configure logging to write to both the console and a log file.

    Args:
        log_file_path: Absolute or relative path to the log file.
                       Created automatically if it doesn't exist.
        log_level: Python logging level name to apply to the root logger and handlers.
    """
    resolved_log_level, resolved_log_level_name = parse_log_level(log_level)

    # Create the root logger — all log messages flow through this
    root_logger = logging.getLogger()
    root_logger.setLevel(resolved_log_level)
    root_logger.handlers.clear()

    # Define a consistent format for all log messages:
    #   2026-03-19 21:13:24,063 [INFO] Server started on port 8443
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    # --- Console handler ---
    # StreamHandler() defaults to sys.stderr; we use it so log messages
    # appear in the terminal alongside print() output.
    console_handler = logging.StreamHandler()
    console_handler.setLevel(resolved_log_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # --- File handler ---
    # FileHandler opens (or creates) the log file in append mode.
    # Log entries accumulate across restarts — the file is never truncated.
    # Make sure the directory for the log file exists.
    log_dir = os.path.dirname(log_file_path)
    if log_dir and not os.path.isdir(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    file_handler = logging.FileHandler(log_file_path)
    file_handler.setLevel(resolved_log_level)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    if (log_level or "").strip().upper() != resolved_log_level_name:
        root_logger.warning(
            "Invalid LOG_LEVEL %r; defaulting to %s",
            log_level,
            resolved_log_level_name,
        )

    return logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DebugHTTPServer
#
# A threaded HTTP server that handles each connection in its own thread and
# logs TLS handshake failures that the base class would silently discard.
# ---------------------------------------------------------------------------
class DebugHTTPServer(ThreadingMixIn, HTTPServer):
    """Threaded HTTPServer that logs connection-level errors.

    ThreadingMixIn must come first in the class definition so its
    process_request() runs instead of HTTPServer's, spawning a new thread
    for every incoming connection.  This prevents slow request handling
    from blocking other webhook deliveries.
    """

    # daemon_threads=True means worker threads are killed automatically when
    # the main program exits (e.g. via Ctrl+C).
    daemon_threads = True

    # Set by main() when TIGHT_SECURITY is enabled
    tight_security = False
    extensiv_public_key = None
    tasks_config = {}

    def get_request(self):
        # The TLS handshake happens inside get_request().  If a client sends
        # garbage or plain HTTP to an HTTPS port, ssl.SSLError is raised here.
        # The base class catches OSError (parent of SSLError) and silently
        # discards it.  We log it before re-raising so you can see the error.
        try:
            return super().get_request()
        except ssl.SSLError as e:
            logger.error("TLS handshake failed: %s", e)
            raise  # re-raise so the base class cleans up the socket

    def handle_error(self, request, client_address):
        # Called when an exception escapes from the request handler.
        # We log the full traceback so connection errors are always visible.
        logger.error(
            "Connection error from %s:%s\n%s",
            client_address[0],
            client_address[1],
            traceback.format_exc(),
        )


# ---------------------------------------------------------------------------
# parse_picks_from_payload()
#
# This is the core business logic.  It takes the raw Extensiv JSON payload
# and extracts:
#   - order_id  (string) — the Extensiv Order ID
#   - picks     (list of dicts) — one dict per allocation with:
#       - "qty"      (int)         — how many units to pick
#       - "sku"      (str)         — the SKU to pick
#       - "location" (str)         — warehouse location name
#       - "lot"      (str or None) — lot number, if present
#
# You can modify this function to extract additional fields as needed.
# See exampleOrder.json for the full structure.
# ---------------------------------------------------------------------------
def parse_picks_from_payload(payload):
    """Extract Order ID and a list of pick dictionaries from an Extensiv webhook payload.

    Args:
        payload: The parsed JSON dict from the webhook body.

    Returns:
        A tuple of (order_id, picks):
            order_id — string, e.g. "24422720"
            picks    — list of dicts, each with keys: qty, sku, location, lot
                       Example:
                       [
                           {"qty": 1, "sku": "RIT0304", "location": "03-19-01", "lot": None},
                           {"qty": 1, "sku": "BA04050", "location": "NOR-06-01", "lot": "DO0824USA0004"}
                       ]

        Returns (None, []) if the payload is not a recognized order event.
    """
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "Payload passed to parse_picks_from_payload:\n%s",
            json.dumps(payload, indent=2, sort_keys=True),
        )

    # -----------------------------------------------------------------------
    # Step 1: Extract the Order ID
    #
    # The Order ID can be found in two places:
    #   - payload["resource"]["body"]["readOnly"]["orderId"]  (integer)
    #   - payload["data"]  (a JSON-encoded string like '{"OrderId":"24422720"}')
    #
    # We try the first (more reliable) and fall back to the second.
    # -----------------------------------------------------------------------
    order_id = None
    picks = []

    # Navigate to the order body — this is where all the item data lives.
    # We use .get() at each level so a missing key returns None instead of
    # crashing with a KeyError.
    resource = payload.get("resource", {})
    body = resource.get("body", {})
    read_only = body.get("readOnly", {})

    # Try to get orderId from the structured body
    raw_order_id = read_only.get("orderId")
    if raw_order_id is not None:
        order_id = str(raw_order_id)
    else:
        # Fallback: parse the "data" field which is a JSON string
        # e.g. '{"OrderId":"24422720"}'
        data_str = payload.get("data", "")
        if data_str:
            try:
                data_dict = json.loads(data_str)
                order_id = str(data_dict.get("OrderId", ""))
            except (json.JSONDecodeError, TypeError):
                pass  # data was not valid JSON; order_id stays None

    if not order_id:
        # Not an order event, or the payload format is unexpected
        return None, []

    # -----------------------------------------------------------------------
    # Step 2: Walk through each order item's allocations to build picks
    #
    # The item array is nested under _embedded with a URL-style key:
    #   body["_embedded"]["http://api.3plCentral.com/rels/orders/item"]
    #
    # Each item can have multiple allocations (e.g. if the same SKU is
    # stored in two different locations and both are needed to fill the
    # order quantity).  Each allocation = one pick.
    # -----------------------------------------------------------------------

    # _embedded contains related resources keyed by their API "rel" URL
    embedded = body.get("_embedded", {})

    # The key for order items — this is a fixed string defined by Extensiv's API
    ITEMS_KEY = "http://api.3plCentral.com/rels/orders/item"

    # Get the list of order items (may be empty if no items are included)
    items = embedded.get(ITEMS_KEY, [])

    for item in items:
        # Each item has a "readOnly" section containing the allocations array
        item_read_only = item.get("readOnly", {})
        allocations = item_read_only.get("allocations", [])

        for alloc in allocations:
            # ----- Quantity -----
            # "qty" is the number of units allocated at this location
            qty = alloc.get("qty", 0)

            # ----- Detail block -----
            # "detail" contains nested info about the SKU, location, and lot
            detail = alloc.get("detail", {})

            # ----- SKU -----
            # Navigate: detail → itemTraits → itemIdentifier → sku
            item_traits = detail.get("itemTraits", {})
            item_identifier = item_traits.get("itemIdentifier", {})
            sku = item_identifier.get("sku", "UNKNOWN")

            # ----- Location -----
            # Navigate: detail → locationIdentifier → nameKey → name
            # This is the human-readable warehouse location (e.g. "03-19-01")
            location_id = detail.get("locationIdentifier", {})
            name_key = location_id.get("nameKey", {})
            location = name_key.get("name", "UNKNOWN")

            # ----- Lot Number (optional) -----
            # Not all items have lot tracking.  If the "lotNumber" field is
            # missing or empty, we store None.
            lot = item_traits.get("lotNumber") or None

            # Build the pick dictionary and add it to our list
            pick = {
                "qty": qty,
                "sku": sku,
                "location": location,
                "lot": lot,
            }
            picks.append(pick)

    return order_id, picks


# ---------------------------------------------------------------------------
# WebhookHandler
#
# Handles incoming HTTP requests.  The main method is do_POST(), which is
# called automatically by Python whenever an HTTP POST arrives.
# ---------------------------------------------------------------------------
class WebhookHandler(BaseHTTPRequestHandler):
    """Handles Extensiv webhook POST requests and extracts pick data."""

    # ------------------------------------------------------------------
    # Logging overrides
    #
    # Redirect the built-in HTTP server log messages through Python's
    # logging module so they go to both the console and the log file.
    # ------------------------------------------------------------------

    def log_message(self, format, *args):
        # Called for informational messages (e.g. "POST / 200")
        logger.info("%s - %s", self.address_string(), format % args)

    def log_error(self, format, *args):
        # Called for protocol-level errors (e.g. malformed request)
        logger.error("%s - %s", self.address_string(), format % args)

    def log_request(self, code="-", size="-"):
        # Called after each request with the HTTP status code
        logger.debug("%s - %s %s", self.address_string(), self.requestline, code)

    # ------------------------------------------------------------------
    # do_POST — main entry point for webhook events
    #
    # This is where incoming Extensiv webhooks are received and processed.
    # ------------------------------------------------------------------
    def do_POST(self):
        # ------------------------------------------------------------------
        # Step 1: Read the request body
        #
        # Content-Length tells us exactly how many bytes the client sent.
        # We must read exactly that many — no more, no less.
        # ------------------------------------------------------------------
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length) if content_length > 0 else b""

        # ------------------------------------------------------------------
        # Step 1b: Signature verification (when TIGHT_SECURITY is enabled)
        #
        # Extensiv signs every webhook payload with an RSA private key and
        # sends the base64-encoded signature in the "Signature" HTTP header.
        # When TIGHT_SECURITY is on, we reject unsigned or tampered requests
        # with HTTP 403 BEFORE replying 200.
        # ------------------------------------------------------------------
        if self.server.tight_security:
            sig_header = self.headers.get("Signature", "")
            if not sig_header:
                logger.warning(
                    "TIGHT_SECURITY: rejected request from %s — missing Signature header",
                    self.client_address[0],
                )
                self.send_response(403)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Forbidden: missing Extensiv signature\n")
                return

            if self.server.extensiv_public_key:
                try:
                    signature_bytes = base64.b64decode(sig_header)
                    self.server.extensiv_public_key.verify(
                        signature_bytes, raw_body, padding.PKCS1v15(), hashes.SHA256()
                    )
                    logger.debug("Extensiv RSA signature verified successfully")
                except Exception as e:
                    logger.warning(
                        "TIGHT_SECURITY: rejected request from %s — invalid signature: %s",
                        self.client_address[0],
                        e,
                    )
                    self.send_response(403)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"Forbidden: invalid Extensiv signature\n")
                    return
            else:
                logger.debug(
                    "Signature header present but verification key is unavailable"
                )

        # ------------------------------------------------------------------
        # Step 2: Reply with HTTP 200 immediately
        #
        # Extensiv waits a maximum of 3 seconds for a response.  If we don't
        # reply in time, they mark the delivery as failed and retry later.
        # So we reply FIRST, then process.
        # ------------------------------------------------------------------
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK\n")

        # ------------------------------------------------------------------
        # Step 3: Log the incoming request details
        # ------------------------------------------------------------------
        logger.info(
            "Received POST %s from %s:%s",
            self.path,
            self.client_address[0],
            self.client_address[1],
        )

        # Log all HTTP headers (useful for debugging)
        for name, value in self.headers.items():
            logger.debug("  Header: %s: %s", name, value)

        # If no body was sent, there's nothing to parse
        if not raw_body:
            logger.warning("Received POST with empty body")
            return

        # ------------------------------------------------------------------
        # Step 4: Parse the JSON payload
        #
        # Extensiv always sends JSON with Content-Type: application/json.
        # The payload is UTF-8 encoded.
        # ------------------------------------------------------------------
        decoded = raw_body.decode("utf-8", errors="replace")

        try:
            payload = json.loads(decoded)
        except (json.JSONDecodeError, TypeError) as e:
            logger.error("Failed to parse JSON: %s", e)
            logger.debug("Raw body: %s", decoded[:500])  # log first 500 chars
            return

        # Log the event type so we can see what kind of webhook this is
        event_type = payload.get("eventType", "unknown")
        logger.info("Event type: %s", event_type)

        # ------------------------------------------------------------------
        # Step 5: Extract Order ID and picks from the payload
        #
        # parse_picks_from_payload() does the heavy lifting of navigating
        # the nested JSON structure.  See that function's docstring for
        # details on what it returns.
        # ------------------------------------------------------------------
        order_id, picks = parse_picks_from_payload(payload)

        if order_id is None:
            # Not an order event, or couldn't find the order ID
            logger.info("Payload is not a recognized order event (no Order ID found)")
            logger.debug("Full payload:\n%s", json.dumps(payload, indent=2))
            return

        # ------------------------------------------------------------------
        # Step 6: Print the Order ID and picks to the console
        #
        # This is where you see the results!  Each pick is a dictionary with:
        #   qty      — how many units to pick
        #   sku      — the product SKU
        #   location — warehouse location name
        #   lot      — lot number (or None if not lot-tracked)
        # ------------------------------------------------------------------
        print("=" * 60)
        print(f"ORDER ID: {order_id}")
        print(f"EVENT:    {event_type}")
        print(f"PICKS:    {len(picks)} allocation(s)")
        print("-" * 60)

        for i, pick in enumerate(picks, start=1):
            print(f"  Pick {i}:")
            print(f"    SKU      : {pick['sku']}")
            print(f"    Quantity : {pick['qty']}")
            print(f"    Location : {pick['location']}")
            if pick["lot"]:
                print(f"    Lot      : {pick['lot']}")
            else:
                print("    Lot      : (none)")

        print("=" * 60)
        print()

        # Also log the picks so they appear in the log file
        logger.info("Order %s: %d pick(s) extracted", order_id, len(picks))
        for i, pick in enumerate(picks, start=1):
            logger.info(
                "  Pick %d: qty=%d  sku=%s  location=%s  lot=%s",
                i,
                pick["qty"],
                pick["sku"],
                pick["location"],
                pick["lot"] or "(none)",
            )

        # ------------------------------------------------------------------
        # Step 7: Forward to the Voodoo Robotics API
        #
        # Now that we have the order ID and picks, we send the order to
        # Voodoo so the robot picking system knows what to do.
        #
        # API documentation: https://developer.voodoorobotics.com/api/orders
        # OpenAPI spec:      https://bblock-demo.voodoorobotics.com/orders/openapi.json
        #
        # The endpoint and API key come from the .env file so they are never
        # hard-coded in source code (which could be checked into version control).
        #
        # IMPORTANT: do_POST() runs in a background thread — one per incoming
        # connection.  If you ever add shared state here (e.g. a counter or a
        # database connection pool), make sure access to it is thread-safe.
        # ------------------------------------------------------------------
        voodoo_api_endpoint = os.environ.get("VOODOO_API_ENDPOINT", "").strip()
        voodoo_api_key = os.environ.get("VOODOO_API_KEY", "").strip()

        if not voodoo_api_endpoint or not voodoo_api_key:
            logger.warning("VOODOO_API_ENDPOINT or VOODOO_API_KEY not set in .env file")
            return

        # Build the endpoint URLs for this specific order:
        #   order_endpoint  — base URL; POST new orders here
        #   delete_endpoint — append the order ID to target a specific order
        #   launch_endpoint — launch the order on Voodoo
        #   abort_endpoint  — abort the order on Voodoo
        order_endpoint = f"{voodoo_api_endpoint}/orders/"
        delete_endpoint = f"{order_endpoint}{order_id}/"
        launch_endpoint = f"{order_endpoint}{order_id}/launch/"
        abort_endpoint = f"{order_endpoint}{order_id}/abort/"

        # The API-Key header is Voodoo's authentication mechanism.
        # Content-Type tells Voodoo we are sending JSON in the request body.
        headers = {"API-Key": voodoo_api_key, "Content-Type": "application/json"}

        # ------------------------------------------------------------------
        # Look up the task list for this event type from the task config.
        #
        # The recommended approach is TASKS_FILE, a path to a JSON file that
        # maps event types to ordered lists of actions.  TASKS remains as a
        # legacy fallback for small setups.
        #
        # Supported actions:
        #   DELETE — remove the order from Voodoo (errors are non-fatal)
        #   ADD    — POST the order to Voodoo
        #   LAUNCH — POST to api/order/<orderid>/launch/ on Voodoo
        #   ABORT  — POST to api/order/<orderid>/abort/ on Voodoo
        # ------------------------------------------------------------------
        tasks = self.server.tasks_config
        if tasks is None:
            return

        actions = tasks.get(event_type)
        if not actions:
            logger.info("No tasks configured for event type: %s", event_type)
            return

        # Build the order payload (used by the ADD action)
        new_order = {"order_number": order_id, "items": []}
        for pick in picks:
            item = {
                "SKU": pick["sku"],
                "ordered_quantity": pick["qty"],
                "warehouse_location": pick["location"],
            }
            # Only add "description" when a lot number is present.
            if pick["lot"]:
                item["description"] = pick["lot"]
            new_order["items"].append(item)

        # Execute each action in order
        for action in actions:
            action = action.upper().strip()

            if action == "DELETE":
                try:
                    response = requests.delete(delete_endpoint, headers=headers)
                    response.raise_for_status()
                    logger.info(
                        "Deleted order from Voodoo (status %s)", response.status_code
                    )
                except requests.RequestException as e:
                    logger.warning("Delete failed (order may not exist yet): %s", e)

            elif action == "ADD":
                try:
                    response = requests.post(
                        order_endpoint, headers=headers, json=new_order
                    )
                    response.raise_for_status()
                    logger.info("Created order in Voodoo: %s", response.json())
                except requests.RequestException as e:
                    logger.error("Failed to create order in Voodoo: %s", e)
                    logger.debug("Request payload: %s", json.dumps(new_order, indent=2))

            elif action == "LAUNCH":
                try:
                    response = requests.post(launch_endpoint, headers=headers)
                    response.raise_for_status()
                    logger.info(
                        "Launched order %s in Voodoo (status %s)",
                        order_id,
                        response.status_code,
                    )
                except requests.RequestException as e:
                    logger.error("Failed to launch order %s in Voodoo: %s", order_id, e)

            elif action == "ABORT":
                try:
                    response = requests.post(abort_endpoint, headers=headers)
                    response.raise_for_status()
                    logger.info(
                        "Aborted order %s in Voodoo (status %s)",
                        order_id,
                        response.status_code,
                    )
                except requests.RequestException as e:
                    logger.error("Failed to abort order %s in Voodoo: %s", order_id, e)

            else:
                logger.warning(
                    "Unknown task action '%s' for event '%s'", action, event_type
                )

    # ------------------------------------------------------------------
    # do_GET — simple health check
    #
    # Not used by Extensiv, but convenient for checking the server is
    # running by visiting the URL in a browser.
    # ------------------------------------------------------------------
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Webhook receiver is running.\n")


# ---------------------------------------------------------------------------
# main()
#
# Reads configuration from the .env file, sets up logging, optionally
# enables TLS, and starts the server.
# ---------------------------------------------------------------------------
def main():
    # load_dotenv() reads the .env file and copies each KEY=VALUE pair into
    # os.environ.  Values already in the environment take precedence.
    load_dotenv()

    # ------------------------------------------------------------------
    # Read configuration from environment variables
    # ------------------------------------------------------------------

    # PORT — which TCP port to listen on (default 8443)
    port = int(os.environ.get("SERVER_PORT", "8443"))

    # TLS certificate paths — both must be set to enable HTTPS
    # Use fullchain.pem from Let's Encrypt, NOT cert.pem!
    cert_file = os.environ.get("TLS_CERT_FILE", "").strip()
    key_file = os.environ.get("TLS_KEY_FILE", "").strip()
    use_tls = bool(cert_file and key_file)

    # LOG_LEVEL — logging threshold for console and file output.
    log_level = os.environ.get("LOG_LEVEL", "INFO")

    # LOG_FILE — path to the log file.  Created if it doesn't exist.
    log_file = os.environ.get("LOG_FILE", "webhook.log").strip()

    # ------------------------------------------------------------------
    # Set up logging (must happen before we use the logger)
    # ------------------------------------------------------------------
    global logger
    logger = setup_logging(log_file, log_level)
    logger.info("Log level: %s", parse_log_level(log_level)[1])
    logger.info("Log file: %s", os.path.abspath(log_file))

    tasks_config = load_tasks_config()
    if tasks_config is None:
        logger.error("No valid task configuration available. Exiting.")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Create the server
    #
    # "0.0.0.0" = listen on all network interfaces.
    # Change to "127.0.0.1" to accept only local connections.
    # ------------------------------------------------------------------
    server = DebugHTTPServer(("0.0.0.0", port), WebhookHandler)
    server.tasks_config = tasks_config

    # ------------------------------------------------------------------
    # TIGHT_SECURITY — require HTTPS and verify Extensiv signatures
    # ------------------------------------------------------------------
    tight_security = os.environ.get("TIGHT_SECURITY", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )

    if tight_security:
        if not use_tls:
            logger.error(
                "TIGHT_SECURITY is enabled but TLS_CERT_FILE / TLS_KEY_FILE are not set. "
                "HTTPS is required when TIGHT_SECURITY is on."
            )
            sys.exit(1)

        pub_key_cache_file = os.environ.get(
            "EXTENSIV_PUBLIC_KEY_CACHE_FILE",
            "extensiv_public_key_cache.json",
        ).strip()
        public_key_pem = refresh_extensiv_public_key(pub_key_cache_file)
        if not public_key_pem:
            logger.error(
                "TIGHT_SECURITY is enabled but no Extensiv public key is available. Exiting."
            )
            sys.exit(1)

        try:
            server.extensiv_public_key = serialization.load_pem_public_key(
                public_key_pem.encode("utf-8")
            )
        except ValueError as e:
            logger.error("Failed to parse Extensiv public key: %s", e)
            sys.exit(1)

        logger.info("Extensiv signature verification is enabled")

        server.tight_security = True
        logger.info("TIGHT_SECURITY is enabled")

    # ------------------------------------------------------------------
    # TLS setup (optional but required for Extensiv)
    # ------------------------------------------------------------------
    if use_tls:
        if not os.path.isfile(cert_file):
            logger.error("Certificate file not found: %s", cert_file)
            sys.exit(1)
        if not os.path.isfile(key_file):
            logger.error("Key file not found: %s", key_file)
            sys.exit(1)

        # Create a TLS context with secure defaults
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2  # no TLS 1.0/1.1
        ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)

        # Wrap the server socket in TLS
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    else:
        scheme = "http"
        logger.info("TLS_CERT_FILE / TLS_KEY_FILE not set — running plain HTTP")

    logger.info("Listening on %s://0.0.0.0:%s", scheme, port)

    # ------------------------------------------------------------------
    # Run the server until Ctrl+C
    # ------------------------------------------------------------------
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down.")
        server.server_close()


# ---------------------------------------------------------------------------
# Entry point — only runs when this script is executed directly
# (not when imported as a module by other code)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    main()
