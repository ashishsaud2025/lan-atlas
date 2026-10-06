"""Run desktop room chat and DMs using raw UDP discovery and framed TCP."""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path
import sys
from uuid import uuid4

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication

from core.chat import ChatService
from core.discovery import IPV6_CAPABILITY, Hello, ipv6_supported
from core.identity import DeviceIdentity
from core.secure_transport import SECURE_PORT, SecureTransport
from core.services import LocalServiceDirectory, RemoteDirectoryCache
from core.storage import JsonLinesPostStore
from core.trust import TrustStore
from gui.main_window import MainWindow
from m1_discovery import load_identity, port_number


def _saved_discovery_selection() -> tuple[tuple[str, ...] | None, bool]:
    """Return persisted announcement egress without starting Qt networking."""
    from ipaddress import ip_address as _ip_address
    try:
        settings = QSettings("LAN Manager", "LAN Atlas")
        saved_address = settings.value("network/discovery_address", "auto")
        saved_fallback = settings.value("network/discovery_include_fallback", True)
    except (ValueError, OSError, RuntimeError):
        return None, True
    fallback = saved_fallback is not False and str(saved_fallback).lower() not in {
        "false", "0", "no"}
    if not isinstance(saved_address, str) or saved_address.strip().lower() == "auto":
        return None, fallback
    parts = [part.strip() for part in saved_address.split(",")]
    addresses: list[str] = []
    for part in parts:
        if not part:
            continue
        try:
            _ip_address(part.partition("%")[0])
        except ValueError:
            return None, fallback
        addresses.append(part)
    if not addresses:
        return None, fallback
    return tuple(addresses), fallback


def main() -> int:
    """Start the desktop client and release workers after the window closes."""
    root = (Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) if os.name == "nt"
            else Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share"))))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--port", type=port_number, default=50000)
    parser.add_argument("--tcp-port", type=port_number, default=50001)
    parser.add_argument("--secure-port", type=port_number, default=SECURE_PORT)
    parser.add_argument("--broadcast", default="255.255.255.255")
    parser.add_argument("--reuse-address", action="store_true")
    parser.add_argument("--source-address", action="append", default=None,
                        help="also announce from one local IP address, with %%scope "
                             "for IPv6 link local; repeatable unless --no-fallback")
    parser.add_argument("--no-fallback", action="store_true",
                        help="do not also announce through the OS default route")
    parser.add_argument("--discovery-auto", action="store_true",
                        help="ignore persisted egress selection for this launch")
    parser.add_argument("--identity-file", type=Path, default=root / "lan-manager/peer-id")
    parser.add_argument("--security-identity-file", type=Path,
                        default=root / "lan-manager/identity.pem")
    parser.add_argument("--trust-file", type=Path,
                        default=root / "lan-manager/trust.json")
    parser.add_argument("--addressbook-file", type=Path,
                        default=root / "lan-manager/addressbook.json")
    parser.add_argument("--post-file", type=Path, default=root / "lan-manager/posts.jsonl")
    parser.add_argument("--catalog-file", type=Path,
                        default=root / "lan-manager/remote-catalog.json")
    args = parser.parse_args()
    if args.discovery_auto and args.source_address:
        parser.error("--discovery-auto cannot be combined with --source-address")
    logging.basicConfig(level=logging.INFO)
    try:
        peer_id = load_identity(args.identity_file)
        identity = DeviceIdentity.load_or_create(
            args.security_identity_file, peer_id)
        capabilities = ["chat_v1", "file_v1", "posts_v1",
                          "secure_transport_v1", "directory_v1"]
        if ipv6_supported():
            capabilities.append(IPV6_CAPABILITY)
        hello = Hello(
            peer_id, str(uuid4()), args.name, args.tcp_port,
            tuple(capabilities), args.secure_port, identity.fingerprint)
        secure_transport = SecureTransport(
            identity, TrustStore(args.trust_file), hello)
        if args.discovery_auto:
            sources: tuple[str, ...] | None = None
            fallback = not args.no_fallback
        elif args.source_address is not None:
            sources = tuple(args.source_address)
            fallback = not args.no_fallback
        else:
            saved_sources, saved_fallback = _saved_discovery_selection()
            sources = saved_sources
            fallback = False if args.no_fallback else saved_fallback
        service = ChatService(hello, args.port, args.broadcast, args.reuse_address,
                              JsonLinesPostStore(args.post_file),
                              secure_transport=secure_transport,
                              discovery_source_addresses=sources,
                              discovery_include_fallback=fallback,
                              directory=LocalServiceDirectory(hello),
                              address_book=args.addressbook_file,
                              remote_catalog=RemoteDirectoryCache(
                                  args.catalog_file))
    except (ValueError, OSError) as error:
        logging.error("Startup failed: %s", error)
        return 1
    app = QApplication(sys.argv[:1])
    window = MainWindow(service)
    window.show()
    service.start()
    try:
        return app.exec()
    finally:
        window.portal.stop()
        if not window.portal.join():
            logging.error("Portal worker did not finish within shutdown deadline")
        window.forwarder.stop()
        if not window.forwarder.join():
            logging.error("Forward worker did not finish within shutdown deadline")
        service.stop()
        if not service.join():
            logging.error("Network workers did not finish within shutdown deadline")


if __name__ == "__main__":
    raise SystemExit(main())
