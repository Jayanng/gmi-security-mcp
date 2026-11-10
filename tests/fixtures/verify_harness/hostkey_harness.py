"""Local SSH host key test harness for the verify_finding oracle.

Local only, paramiko only (installed in the project venv for
Phase A1). start_test_server runs a tiny SSH server on
127.0.0.1 with a fresh host key and password auth that accepts
any password. connect_no_verify connects with a raw Transport
and no host key check at all, which is what an SSH client with
no hostVerifier and no known_hosts check does: the connection
succeeds even when the server presents a wrong host key. The
fixed form, connect_strict, uses an SSHClient with a known_hosts
file and RejectPolicy, so a wrong host key fails. This mirrors
the ssh-mcp-server finding: buildClientConfig had no
hostVerifier and known_hosts was never consulted.
"""

import socket
import threading

import paramiko


class _Server(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        return "password"


def _fingerprint(key):
    return ":".join("%02x" % b for b in key.get_fingerprint())


def start_test_server():
    """Start the test SSH server. Returns (port, host_key, stop_fn).

    host_key is the paramiko key the server presents. stop_fn
    closes the listening socket; the transport ends when the
    client disconnects.
    """
    host_key = paramiko.RSAKey.generate(2048)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    port = sock.getsockname()[1]
    state = {"transport": None, "stop": False}

    def serve():
        while not state["stop"]:
            try:
                sock.settimeout(5)
                conn, _addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            transport = paramiko.Transport(conn)
            state["transport"] = transport
            transport.add_server_key(host_key)
            try:
                transport.start_server(server=_Server())
                channel = transport.accept(timeout=5)
                if channel is not None:
                    channel.close()
            except Exception:
                pass
            finally:
                try:
                    transport.close()
                except Exception:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    def stop():
        state["stop"] = True
        try:
            sock.close()
        except OSError:
            pass

    return port, host_key, stop


def connect_no_verify(port):
    """Connect with no host key verification. Returns (ok, fingerprint).

    Uses a raw Transport, which performs no host key check: the
    connection succeeds whatever key the server presents.
    """
    transport = paramiko.Transport(("127.0.0.1", port))
    try:
        transport.connect(username="tester", password="tester")
        key = transport.get_remote_server_key()
        return True, _fingerprint(key)
    finally:
        transport.close()


def connect_strict(port, known_hosts_path):
    """Connect with known_hosts and RejectPolicy. Returns ok bool.

    A server presenting a key that differs from known_hosts fails
    with BadHostKeyException. That is the fixed behaviour.
    """
    client = paramiko.SSHClient()
    client.load_host_keys(known_hosts_path)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(
            "127.0.0.1",
            port=port,
            username="tester",
            password="tester",
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )
        return True
    except Exception:
        return False
    finally:
        client.close()
