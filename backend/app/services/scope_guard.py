"""Scope Guard - strict runtime boundary enforcement for scanning.

This is the primary ethical and safety control mechanism.
Every outgoing request is validated before transmission.
"""
import ipaddress
import socket
from urllib.parse import urlparse
from typing import Optional

from ..config import ALLOWED_SCHEMES, LOOPBACK_ADDRESSES, LOOPBACK_HOSTNAMES


class ScopeViolation(Exception):
    """Raised when an outgoing HTTP request attempts to exceed configured test scope."""
    pass


class ScopeGuard:
    """Enforces target hosts, ports, path prefixes, methods, and loopback boundaries."""

    def __init__(
        self,
        allowed_hosts: list[str],
        allowed_ports: list[int],
        allowed_paths: list[str],
        allowed_methods: list[str],
        require_loopback: bool = True,
        is_authorized: bool = True,
    ):
        self.allowed_hosts = set(allowed_hosts)
        self.allowed_ports = set(allowed_ports)
        self.allowed_paths = allowed_paths or ["/api/"]
        self.allowed_methods = set(m.upper() for m in allowed_methods)
        self.require_loopback = require_loopback
        self.is_authorized = is_authorized
        self._request_count = 0
        self._max_requests = 200

    def set_max_requests(self, max_req: int) -> None:
        """Configure maximum request quota."""
        self._max_requests = max_req

    def validate_url(self, url: str) -> None:
        """Validate an HTTP target URL against security and boundary policies."""
        if not self.is_authorized:
            raise ScopeViolation("Target is not explicitly authorized for security testing.")

        parsed = urlparse(url)

        # Check scheme
        if parsed.scheme not in ALLOWED_SCHEMES:
            raise ScopeViolation(
                f"Scheme '{parsed.scheme}' is disallowed. Allowed schemes: {sorted(ALLOWED_SCHEMES)}"
            )

        # Disallow embedded credentials in URL
        if parsed.username or parsed.password:
            raise ScopeViolation("URL credentials (user:pass@host) are forbidden.")

        hostname = parsed.hostname
        if not hostname:
            raise ScopeViolation("Missing valid hostname in target URL.")

        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80

        # Check allowed hosts
        if hostname not in self.allowed_hosts:
            raise ScopeViolation(
                f"Host '{hostname}' is out-of-scope. Permitted hosts: {sorted(self.allowed_hosts)}"
            )

        # Check allowed ports
        if port not in self.allowed_ports:
            raise ScopeViolation(
                f"Port {port} is out-of-scope. Permitted ports: {sorted(self.allowed_ports)}"
            )

        # Check loopback restriction if active
        if self.require_loopback:
            self._verify_loopback(hostname)

        # Check path prefix
        path = parsed.path or "/"
        if not any(path.startswith(p) for p in self.allowed_paths):
            raise ScopeViolation(
                f"Path '{path}' is outside permitted path prefixes: {self.allowed_paths}"
            )

    def validate_method(self, method: str) -> None:
        """Validate that HTTP method is within allowed scope."""
        if method.upper() not in self.allowed_methods:
            raise ScopeViolation(
                f"HTTP method '{method}' is disallowed. Allowed: {sorted(self.allowed_methods)}"
            )

    def validate_request(self, method: str, url: str) -> None:
        """Validate both method, URL, and overall request volume before sending."""
        self._request_count += 1
        if self._request_count > self._max_requests:
            raise ScopeViolation(
                f"Scan request budget exceeded ({self._max_requests} max requests allowed per run)."
            )
        self.validate_url(url)
        self.validate_method(method)

    def validate_redirect(self, original_url: str, redirect_url: str) -> None:
        """Prevent scanner from being redirected out of scope by target API."""
        self.validate_url(redirect_url)

    def _verify_loopback(self, hostname: str) -> None:
        """Confirm that hostname resolves solely to a loopback address."""
        if hostname in LOOPBACK_ADDRESSES:
            return
        if hostname in LOOPBACK_HOSTNAMES:
            try:
                addr_infos = socket.getaddrinfo(hostname, None)
                for addr_info in addr_infos:
                    ip_str = addr_info[4][0]
                    ip = ipaddress.ip_address(ip_str)
                    if not ip.is_loopback:
                        raise ScopeViolation(
                            f"Hostname '{hostname}' resolved to non-loopback IP '{ip_str}'."
                        )
                return
            except socket.gaierror as e:
                raise ScopeViolation(f"Unable to resolve hostname '{hostname}': {e}")

        # Attempt address resolution check
        try:
            addr_infos = socket.getaddrinfo(hostname, None)
            for addr_info in addr_infos:
                ip_str = addr_info[4][0]
                ip = ipaddress.ip_address(ip_str)
                if not ip.is_loopback:
                    raise ScopeViolation(
                        f"Resolved address '{ip_str}' for host '{hostname}' is not a loopback address. "
                        "Academic prototype allows only loopback testing by default."
                    )
        except socket.gaierror as e:
            raise ScopeViolation(f"Resolution failure for '{hostname}': {e}")

    @property
    def request_count(self) -> int:
        return self._request_count

