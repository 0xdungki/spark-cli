from __future__ import annotations

import ipaddress
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
}

UNSAFE_BIND_HOSTS = {
    "0.0.0.0",
    "::",
}

LOCAL_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
}


@dataclass(frozen=True)
class UrlPolicy:
    allow_local: bool = True
    allow_private_networks: bool = False
    require_https_for_remote: bool = True


def _parse_url(raw_url: str) -> urllib.parse.ParseResult:
    value = raw_url.strip()
    if "://" not in value:
        value = f"http://{value}"
    return urllib.parse.urlparse(value)


def _host_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def validate_url_safety(raw_url: str, *, label: str = "URL", policy: UrlPolicy | None = None) -> list[str]:
    """Static, network-free policy check on a single URL string.

    Used at config-validation time (e.g. ``spark doctor``) to flag obviously
    unsafe endpoint values before any request is ever made. Performs *no* I/O,
    so it cannot itself become an SSRF surface.

    Runtime defenders that follow redirects must use :func:`safe_urlopen`, which
    re-applies this policy at every hop.
    """
    active_policy = policy or UrlPolicy()
    value = str(raw_url or "").strip()
    if not value or value.startswith("${"):
        return []

    errors: list[str] = []
    parsed = _parse_url(value)
    if parsed.scheme not in {"http", "https"}:
        return [f"{label} uses unsupported URL scheme `{parsed.scheme}`."]

    host = (parsed.hostname or "").strip().lower()
    if not host:
        return [f"{label} has a URL without a hostname."]
    if host in METADATA_HOSTS:
        errors.append(f"{label} points at cloud metadata service `{host}`.")
    if host in UNSAFE_BIND_HOSTS:
        errors.append(f"{label} points at unsafe bind host `{host}`.")

    ip = _host_ip(host)
    is_local = host in LOCAL_HOSTS or bool(ip and ip.is_loopback)
    if is_local and not active_policy.allow_local:
        errors.append(f"{label} points at local-only host `{host}`.")
    if ip is not None:
        if ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            errors.append(f"{label} points at unsafe network address `{host}`.")
        elif ip.is_private and not ip.is_loopback and not active_policy.allow_private_networks:
            errors.append(f"{label} points at private network address `{host}`.")
    if active_policy.require_https_for_remote and not is_local and parsed.scheme != "https":
        errors.append(f"{label} uses non-HTTPS remote endpoint `{value}`.")
    return errors


class _PolicyEnforcingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirect hops that fail the configured :class:`UrlPolicy`.

    The default ``HTTPRedirectHandler`` blindly follows every ``Location:`` it
    is handed, which is exactly the SSRF primitive we need to close: an
    attacker-controlled origin replies ``302 -> http://169.254.169.254/...`` or
    ``-> http://127.0.0.1:11434/...`` and the validator sees a benign first-hop
    URL while the runtime fetcher silently lands on a cloud metadata or local
    admin endpoint.

    This subclass re-runs :func:`validate_url_safety` on every redirect target
    *before* delegating to the base implementation, so any policy violation
    short-circuits the chain with a clean ``URLError`` instead of completing
    the unsafe fetch.
    """

    def __init__(self, *, label: str, policy: UrlPolicy):
        super().__init__()
        self._label = label
        self._policy = policy

    def redirect_request(  # type: ignore[override]
        self,
        req: urllib.request.Request,
        fp,
        code: int,
        msg: str,
        headers,
        newurl: str,
    ):
        errors = validate_url_safety(newurl, label=self._label, policy=self._policy)
        if errors:
            raise urllib.error.URLError(
                f"redirect blocked by URL policy: {errors[0]}"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def safe_urlopen(
    url_or_request: str | urllib.request.Request,
    *,
    label: str = "URL",
    policy: UrlPolicy | None = None,
    timeout: float | None = None,
):
    """Open a URL with redirect hops constrained by :class:`UrlPolicy`.

    This is the runtime SSRF gate. The initial URL is validated up front, then
    every ``3xx`` redirect target is re-validated by
    :class:`_PolicyEnforcingRedirectHandler` before the next request is issued.

    A redirect to a cloud metadata host, an unsafe bind host, or (depending on
    policy) a private/local network raises :class:`urllib.error.URLError`
    instead of being silently followed. Callers should catch ``URLError``
    exactly like they would for a network failure.
    """
    active_policy = policy or UrlPolicy()
    if isinstance(url_or_request, urllib.request.Request):
        initial_url = url_or_request.full_url
    else:
        initial_url = url_or_request

    initial_errors = validate_url_safety(initial_url, label=label, policy=active_policy)
    if initial_errors:
        raise urllib.error.URLError(
            f"URL blocked by policy: {initial_errors[0]}"
        )

    opener = urllib.request.build_opener(
        _PolicyEnforcingRedirectHandler(label=label, policy=active_policy)
    )
    if timeout is None:
        return opener.open(url_or_request)
    return opener.open(url_or_request, timeout=timeout)
