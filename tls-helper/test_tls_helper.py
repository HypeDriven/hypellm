#!/usr/bin/env python3
"""Tests for the reference outbound TLS helper.

Run with `python3 tls-helper/test_tls_helper.py`.

Not part of `cargo test --workspace`: the helper is deliberately outside the
Rust workspace (specification 4), so nothing in the build could run it.

Offline by construction. Every TLS server is in this process on 127.0.0.1,
and its certificates are minted for the run by the `openssl` command-line
tool into a temporary directory, under a CA that exists only for that run.
A checked-in CA would be a long-lived private key in the repository that
anything reading it could sign with; a generated one is gone when the test
ends. The helper is pointed at that CA with `ca_file`, which replaces the
system store, so no test trusts a real certificate authority either.

Each test asserts what the helper must refuse or preserve, not merely that it
answered: a refusal must also mean no connection was opened, and a relay must
be byte-exact in both directions at once.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import io
import json
import os
import selectors
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "hypellm-tls-helper"
_SPEC = importlib.util.spec_from_loader(
    "tls_helper", importlib.machinery.SourceFileLoader("tls_helper", str(SCRIPT))
)
assert _SPEC is not None and _SPEC.loader is not None
helper_module = importlib.util.module_from_spec(_SPEC)
# Registered before execution: `@dataclass` resolves its module through
# `sys.modules`.
sys.modules["tls_helper"] = helper_module
sys.dont_write_bytecode = True
_SPEC.loader.exec_module(helper_module)


def openssl(*args: str, cwd: str) -> None:
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


def mint(directory: str, name: str, ca: str, sans: str) -> tuple[str, str]:
    """A leaf certificate for `sans`, signed by the CA files named `ca`."""
    ext = Path(directory, f"{name}.ext")
    ext.write_text(
        f"subjectAltName={sans}\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid\n"
    )
    openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", f"/CN={name}", cwd=directory)
    openssl("x509", "-req", "-in", f"{name}.csr", "-CA", f"{ca}.pem", "-CAkey", f"{ca}.key",
            "-set_serial", str(abs(hash(name)) % 1_000_000 + 1), "-days", "2",
            "-out", f"{name}.pem", "-extfile", str(ext), cwd=directory)
    return str(Path(directory, f"{name}.pem")), str(Path(directory, f"{name}.key"))


def make_ca(directory: str, name: str) -> str:
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", f"{name}.key", "-out", f"{name}.pem", "-days", "2",
            "-subj", f"/CN={name}",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash", cwd=directory)
    return str(Path(directory, f"{name}.pem"))


class TlsServer:
    """A TLS server on 127.0.0.1 running `handler(conn)` per connection."""

    def __init__(self, cert: str, key: str, handler) -> None:
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.handler = handler
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.accepted = 0
        self.errors: list[str] = []
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def loop(self) -> None:
        while True:
            try:
                raw, _ = self.listener.accept()
            except OSError:
                return
            self.accepted += 1
            threading.Thread(target=self.serve, args=(raw,), daemon=True).start()

    def serve(self, raw: socket.socket) -> None:
        try:
            with self.context.wrap_socket(raw, server_side=True) as conn:
                self.handler(conn)
        except (ssl.SSLError, OSError) as error:
            self.errors.append(type(error).__name__)

    def close(self) -> None:
        self.listener.close()


def hold(conn: ssl.SSLSocket) -> None:
    """Keep a session open, silently, until the peer goes away."""
    conn.settimeout(10)
    try:
        while conn.recv(4096):
            pass
    except OSError:
        pass


class HelperCase(unittest.TestCase):
    sequence = 0

    @classmethod
    def setUpClass(cls) -> None:
        cls.dir = tempfile.TemporaryDirectory()
        d = cls.dir.name
        cls.ca = make_ca(d, "trusted-ca")
        make_ca(d, "stranger-ca")
        cls.cert, cls.key = mint(d, "api.test", "trusted-ca", "DNS:api.test,DNS:localhost")
        cls.stranger_cert, cls.stranger_key = mint(d, "stranger", "stranger-ca", "DNS:api.test")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.dir.cleanup()

    def setUp(self) -> None:
        self.servers: list[TlsServer] = []
        self.helpers: list = []

    def tearDown(self) -> None:
        for helper in self.helpers:
            helper.stop()
        for server in self.servers:
            server.close()

    # -- fixtures ------------------------------------------------------------

    def server(self, handler=hold, cert=None, key=None) -> TlsServer:
        server = TlsServer(cert or self.cert, key or self.key, handler)
        self.servers.append(server)
        return server

    def start(self, destinations: list[dict], **overrides) -> tuple[str, io.StringIO]:
        HelperCase.sequence += 1
        path = os.path.join(self.dir.name, f"helper-{HelperCase.sequence}.sock")
        document = {"socket": path, "destinations": destinations, "ca_file": self.ca, "log_level": "debug"}
        document.update(overrides)
        config_path = Path(self.dir.name, f"config-{HelperCase.sequence}.json")
        config_path.write_text(json.dumps(document))
        config = helper_module.load_config(str(config_path))
        stream = io.StringIO()
        helper = helper_module.Helper(config, helper_module.Log("debug", stream))
        helper.bind()
        threading.Thread(target=helper.serve_forever, daemon=True).start()
        self.helpers.append(helper)
        return path, stream

    @staticmethod
    def connect(path: str, line: bytes) -> tuple[socket.socket, bytes]:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(10)
        client.connect(path)
        try:
            client.sendall(line)
        except (BrokenPipeError, ConnectionResetError):
            # A refusal can close the socket before the line is written; the
            # status is still waiting to be read.
            pass
        status = bytearray()
        while not status.endswith(b"\n"):
            try:
                byte = client.recv(1)
            except ConnectionResetError:
                break
            if not byte:
                break
            status += byte
        return client, bytes(status)

    def refused(self, path: str, line: bytes) -> str:
        client, status = self.connect(path, line)
        client.close()
        self.assertTrue(status.startswith(b"ERR "), status)
        return status[4:].strip().decode()

    # -- the relay -----------------------------------------------------------

    def test_a_relay_is_byte_exact_in_both_directions_at_once(self) -> None:
        marker = b"SECRET-PLAINTEXT-MARKER"
        upward = marker + os.urandom(1024 * 1024) + bytes(range(256))
        downward = os.urandom(1536 * 1024) + marker
        received = bytearray()
        finished = threading.Event()

        def exchange(conn: ssl.SSLSocket) -> None:
            # Send while still receiving: a relay that only moved one
            # direction at a time would deadlock here once buffers filled.
            # One thread, non-blocking, because an OpenSSL connection must
            # not be read and written from two threads at once.
            conn.setblocking(False)
            pending = memoryview(downward)
            deadline = time.monotonic() + 20
            with selectors.DefaultSelector() as selector:
                selector.register(conn, selectors.EVENT_READ | selectors.EVENT_WRITE)
                while (len(received) < len(upward) or pending) and time.monotonic() < deadline:
                    if not conn.pending():
                        selector.select(timeout=0.5)
                    try:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        received.extend(chunk)
                    except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                        pass
                    if pending:
                        try:
                            pending = pending[conn.send(pending[:16384]):]
                        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                            pass
            finished.set()

        server = self.server(exchange)
        path, log = self.start([{"sni": "api.test", "port": server.port, "local": True}])
        client, status = self.connect(path, f"CONNECT 127.0.0.1 {server.port} api.test\n".encode())
        self.assertEqual(status, b"OK\n")
        got = bytearray()

        def read_all() -> None:
            while len(got) < len(downward):
                chunk = client.recv(65536)
                if not chunk:
                    break
                got.extend(chunk)

        reader = threading.Thread(target=read_all)
        reader.start()
        client.sendall(upward)
        reader.join(20)
        self.assertTrue(finished.wait(20), "the provider never received the whole upload")
        client.close()
        self.assertEqual(bytes(received), upward, "the provider must receive exactly what the router sent")
        self.assertEqual(bytes(got), downward, "the router must receive exactly what the provider sent")
        time.sleep(0.2)
        self.assertNotIn("SECRET-PLAINTEXT-MARKER", log.getvalue(), "plaintext must never reach the log")
        self.assertIn('"event":"session.closed"', log.getvalue())

    def test_a_name_is_accepted_only_when_it_is_the_sni(self) -> None:
        server = self.server(lambda conn: conn.sendall(b"hello"))
        path, _ = self.start([{"sni": "localhost", "port": server.port, "local": True}])
        client, status = self.connect(path, f"CONNECT localhost {server.port} localhost\n".encode())
        self.assertEqual(status, b"OK\n")
        self.assertEqual(client.recv(5), b"hello")
        client.close()
        self.assertEqual(
            self.refused(path, f"CONNECT evil.example {server.port} localhost\n".encode()),
            "host_mismatch",
        )

    # -- what is refused, and that a refusal opens nothing --------------------

    def test_a_destination_not_on_the_allowlist_is_refused_before_any_connection(self) -> None:
        server = self.server()
        path, _ = self.start([{"sni": "api.test", "port": server.port, "local": True}])
        self.assertEqual(
            self.refused(path, f"CONNECT 127.0.0.1 {server.port} elsewhere.test\n".encode()),
            "destination_not_allowlisted",
        )
        # Same name, another port: the row is the pair, not the name.
        self.assertEqual(
            self.refused(path, f"CONNECT 127.0.0.1 {server.port + 1} api.test\n".encode()),
            "destination_not_allowlisted",
        )
        time.sleep(0.1)
        self.assertEqual(server.accepted, 0)

    def test_a_certificate_for_another_name_is_refused(self) -> None:
        server = self.server()
        path, _ = self.start([{"sni": "other.test", "port": server.port, "local": True}])
        self.assertEqual(
            self.refused(path, f"CONNECT 127.0.0.1 {server.port} other.test\n".encode()),
            "certificate_invalid",
        )

    def test_a_certificate_from_an_untrusted_issuer_is_refused(self) -> None:
        server = self.server(cert=self.stranger_cert, key=self.stranger_key)
        path, _ = self.start([{"sni": "api.test", "port": server.port, "local": True}])
        self.assertEqual(
            self.refused(path, f"CONNECT 127.0.0.1 {server.port} api.test\n".encode()),
            "certificate_invalid",
        )

    def test_a_non_global_address_is_refused_unless_the_row_says_local(self) -> None:
        server = self.server()
        path, _ = self.start([
            {"sni": "api.test", "port": server.port},
            {"sni": "api.test", "port": 443},
        ])
        for address in (
            "127.0.0.1",          # loopback
            "10.0.0.1",           # private
            "169.254.169.254",    # link-local: the cloud metadata service
            "100.64.0.1",         # shared address space (carrier-grade NAT)
            "::ffff:127.0.0.1",   # loopback, spelled as IPv6
            "::1",
            "0.0.0.0",
            "224.0.0.1",
        ):
            port = server.port if address == "127.0.0.1" else 443
            with self.subTest(address=address):
                self.assertEqual(
                    self.refused(path, f"CONNECT {address} {port} api.test\n".encode()),
                    "address_not_permitted",
                )
        time.sleep(0.1)
        self.assertEqual(server.accepted, 0, "a refused address must not be dialled")

    def test_a_row_with_prefixes_admits_only_addresses_inside_them(self) -> None:
        server = self.server()
        path, _ = self.start([
            {"sni": "api.test", "port": server.port, "local": True, "prefixes": ["192.0.2.0/24"]},
        ])
        self.assertEqual(
            self.refused(path, f"CONNECT 127.0.0.1 {server.port} api.test\n".encode()),
            "address_not_permitted",
        )

    def test_malformed_requests_are_refused_with_a_reason(self) -> None:
        path, _ = self.start([{"sni": "api.test", "port": 443}])
        cases = {
            b"HELLO\n": "malformed_request",
            b"CONNECT 1.2.3.4 443\n": "malformed_request",
            b"CONNECT  1.2.3.4 443 api.test\n": "malformed_request",
            b"connect 1.2.3.4 443 api.test\n": "malformed_request",
            b"CONNECT 1.2.3.4 http api.test\n": "invalid_port",
            b"CONNECT 1.2.3.4 0443 api.test\n": "invalid_port",
            b"CONNECT 1.2.3.4 70000 api.test\n": "invalid_port",
            # helper.rs sends an empty SNI when a destination has none.
            b"CONNECT 1.2.3.4 443 \n": "invalid_sni",
            b"CONNECT 1.2.3.4 443 1.2.3.4\n": "invalid_sni",
            b"CONNECT 1.2.3.4 443 bad_name.test\n": "invalid_sni",
            b"CONNECT 1.2.3.4 443 api.test\xff\n": "malformed_request",
        }
        for line, code in cases.items():
            with self.subTest(line=line):
                self.assertEqual(self.refused(path, line), code)

    def test_an_oversized_line_is_refused_without_waiting_for_its_end(self) -> None:
        path, _ = self.start([{"sni": "api.test", "port": 443}])
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect(path)
        client.sendall(b"CONNECT " + b"a" * 4096)  # never a newline
        self.assertEqual(client.recv(64), b"ERR line_too_long\n")
        client.close()

    def test_a_silent_client_is_refused_at_the_line_deadline(self) -> None:
        path, _ = self.start([{"sni": "api.test", "port": 443}], line_timeout_ms=200)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect(path)
        started = time.monotonic()
        self.assertEqual(client.recv(64), b"ERR line_timeout\n")
        self.assertLess(time.monotonic() - started, 2.0)
        client.close()

    # -- bounds ----------------------------------------------------------------

    def test_sessions_past_the_cap_are_refused_and_a_closed_one_frees_its_slot(self) -> None:
        server = self.server()
        path, _ = self.start([{"sni": "api.test", "port": server.port, "local": True}], max_sessions=2)
        line = f"CONNECT 127.0.0.1 {server.port} api.test\n".encode()
        first, status = self.connect(path, line)
        self.assertEqual(status, b"OK\n")
        second, status = self.connect(path, line)
        self.assertEqual(status, b"OK\n")
        self.assertEqual(self.refused(path, line), "busy")
        first.close()
        deadline = time.monotonic() + 5
        while True:
            client, status = self.connect(path, line)
            if status == b"OK\n" or time.monotonic() > deadline:
                break
            client.close()
            time.sleep(0.05)
        self.assertEqual(status, b"OK\n", "a closed session must release its slot")
        client.close()
        second.close()

    def test_an_idle_session_is_closed(self) -> None:
        server = self.server()
        path, log = self.start(
            [{"sni": "api.test", "port": server.port, "local": True}], idle_timeout_ms=300
        )
        client, status = self.connect(path, f"CONNECT 127.0.0.1 {server.port} api.test\n".encode())
        self.assertEqual(status, b"OK\n")
        started = time.monotonic()
        self.assertEqual(client.recv(1), b"", "the helper must end a session nothing uses")
        self.assertLess(time.monotonic() - started, 3.0)
        client.close()
        time.sleep(0.1)
        self.assertIn('"ended":"idle_timeout"', log.getvalue())

    # -- configuration ---------------------------------------------------------

    def test_a_configuration_with_an_unknown_key_or_a_repeated_row_is_refused(self) -> None:
        cases = [
            {"socket": "/tmp/x.sock", "destinations": [], "max_sesions": 4},
            {"socket": "/tmp/x.sock", "destinations": [{"sni": "a.test", "port": 443}, {"sni": "A.test", "port": 443}]},
            {"socket": "/tmp/x.sock", "destinations": [{"sni": "1.2.3.4", "port": 443}]},
            {"socket": "/tmp/x.sock", "destinations": [{"sni": "a.test", "port": 443, "allow": True}]},
            {"socket": "/tmp/x.sock", "destinations": [], "max_sessions": 100000},
            {"socket": "relative.sock", "destinations": []},
        ]
        for index, document in enumerate(cases):
            with self.subTest(index=index):
                path = Path(self.dir.name, f"bad-{index}.json")
                path.write_text(json.dumps(document))
                with self.assertRaises(ValueError):
                    helper_module.load_config(str(path))

    def test_proxy_variables_are_ignored_and_reported(self) -> None:
        # The helper as its own process, with every proxy variable pointing at
        # a port nothing listens on. A relay that honoured one would fail.
        if os.geteuid() == 0:
            self.skipTest("the helper refuses to run as root, so its process cannot start here")
        server = self.server(lambda conn: conn.sendall(b"direct"))
        socket_path = os.path.join(self.dir.name, "proxy-test.sock")
        config = Path(self.dir.name, "proxy-test.json")
        config.write_text(json.dumps({
            "socket": socket_path, "ca_file": self.ca,
            "destinations": [{"sni": "api.test", "port": server.port, "local": True}],
        }))
        env = dict(os.environ)
        for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY"):
            env[name] = "http://127.0.0.1:9"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        process = subprocess.Popen(
            [sys.executable, str(SCRIPT), "--config", str(config)],
            env=env, stderr=subprocess.PIPE, text=True,
        )
        try:
            deadline = time.monotonic() + 10
            while not os.path.exists(socket_path) and time.monotonic() < deadline:
                time.sleep(0.05)
            client, status = self.connect(socket_path, f"CONNECT 127.0.0.1 {server.port} api.test\n".encode())
            self.assertEqual(status, b"OK\n")
            self.assertEqual(client.recv(6), b"direct")
            client.close()
        finally:
            process.terminate()
            _, stderr = process.communicate(timeout=10)
        self.assertIn("helper.proxy_environment_ignored", stderr)
        self.assertNotIn("127.0.0.1:9", stderr, "the variables' values are not logged")

    def test_the_helper_refuses_to_run_as_root(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("only observable when the test itself runs as root")
        config = Path(self.dir.name, "root-test.json")
        config.write_text(json.dumps({"socket": os.path.join(self.dir.name, "root.sock"), "destinations": []}))
        result = subprocess.run([sys.executable, str(SCRIPT), "--config", str(config)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn("refusing to run as root", result.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.dir.name, "root.sock")))

    def test_the_shipped_configuration_is_valid_and_public_only(self) -> None:
        config = helper_module.load_config(str(HERE / "tls-helper.json"))
        self.assertTrue(config.destinations)
        for row in config.destinations.values():
            self.assertFalse(row.local, f"{row.sni} must not be reachable at a private address")
            self.assertEqual(row.port, 443)


if __name__ == "__main__":
    unittest.main(verbosity=1)
