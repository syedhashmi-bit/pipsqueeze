import os
import re
import routeros_api
from dotenv import load_dotenv

load_dotenv()


class MikroTikAPI:
    def __init__(self, interface=None):
        self.host = os.getenv("MT_HOST")
        self.username = os.getenv("MT_USERNAME")
        self.password = os.getenv("MT_PASSWORD")
        self.port = int(os.getenv("MT_PORT", "8728"))
        # Allow caller to override interface, fallback to env
        self.wireguard_interface = interface or os.getenv("MT_WIREGUARD_INTERFACE", "Test-Wireguard")

        self.connection = None
        self.api = None

    def connect(self):
        self.connection = routeros_api.RouterOsApiPool(
            host=self.host,
            username=self.username,
            password=self.password,
            port=self.port,
            plaintext_login=True
        )
        self.api = self.connection.get_api()

    def disconnect(self):
        if self.connection:
            self.connection.disconnect()

    def get_peer_id(self, peer):
        return (
            peer.get("id")
            or peer.get(".id")
            or peer.get("numbers")
            or peer.get("name")
        )

    def get_all_wireguard_interfaces(self):
        """Return list of all WireGuard interface names on the router."""
        try:
            ifaces = self.api.get_resource("/interface/wireguard").get()
            return [i.get("name") for i in ifaces if i.get("name")]
        except Exception:
            return [self.wireguard_interface]

    def get_peers(self):
        peers_resource = self.api.get_resource("/interface/wireguard/peers")
        all_peers = peers_resource.get()

        filtered_peers = []

        for peer in all_peers:
            if peer.get("interface") != self.wireguard_interface:
                continue

            peer_id = self.get_peer_id(peer)
            peer["peer_id"] = peer_id

            # Read raw handshake field (hyphen key from MikroTik)
            raw_hs = peer.get("last-handshake", "")
            peer["last_handshake"] = raw_hs if raw_hs else "Never"
            peer["rx"] = peer.get("rx", "0")
            peer["tx"] = peer.get("tx", "0")

            # Parse handshake duration properly (e.g. "1h2m30s", "45s")
            if raw_hs:
                try:
                    seconds = 0
                    h = re.search(r"(\d+)h", raw_hs)
                    m = re.search(r"(\d+)m", raw_hs)
                    s = re.search(r"(\d+)s", raw_hs)
                    if h: seconds += int(h.group(1)) * 3600
                    if m: seconds += int(m.group(1)) * 60
                    if s: seconds += int(s.group(1))
                    if seconds == 0 and not any([h, m, s]):
                        seconds = int(raw_hs)
                    peer["status"] = "Online" if seconds < 120 else "Offline"
                    peer["handshake_seconds"] = seconds
                except Exception:
                    peer["status"] = "Unknown"
                    peer["handshake_seconds"] = -1
            else:
                peer["status"] = "Offline"
                peer["handshake_seconds"] = -1

            filtered_peers.append(peer)

        return filtered_peers

    def enable_peer(self, peer_id):
        peers = self.api.get_resource("/interface/wireguard/peers")
        peers.set(id=peer_id, disabled="false")

    def disable_peer(self, peer_id):
        peers = self.api.get_resource("/interface/wireguard/peers")
        peers.set(id=peer_id, disabled="true")

    def add_peer(self, public_key, allowed_address, name):
        peers = self.api.get_resource("/interface/wireguard/peers")
        peers.add(
            interface=self.wireguard_interface,
            public_key=public_key,
            allowed_address=allowed_address,
            comment=name
        )

    def rename_peer(self, old_name, new_name):
        """Rename a peer's comment field on MikroTik."""
        peers = self.api.get_resource("/interface/wireguard/peers")
        all_peers = peers.get()
        for peer in all_peers:
            if peer.get("interface") != self.wireguard_interface:
                continue
            if peer.get("comment", "").strip() == old_name.strip():
                peer_id = self.get_peer_id(peer)
                if peer_id:
                    peers.set(id=peer_id, comment=new_name)
                    return True
        return False

    def enable_peer_by_name(self, name):
        """Enable a peer by its comment/name."""
        peers = self.api.get_resource("/interface/wireguard/peers")
        all_peers = peers.get()
        for peer in all_peers:
            if peer.get("interface") != self.wireguard_interface:
                continue
            if peer.get("comment", "").strip() == name.strip():
                peer_id = self.get_peer_id(peer)
                if peer_id:
                    peers.set(id=peer_id, disabled="false")
                    return True
        return False

    def disable_peer_by_name(self, name):
        """Disable a peer by its comment/name."""
        peers = self.api.get_resource("/interface/wireguard/peers")
        all_peers = peers.get()
        for peer in all_peers:
            if peer.get("interface") != self.wireguard_interface:
                continue
            if peer.get("comment", "").strip() == name.strip():
                peer_id = self.get_peer_id(peer)
                if peer_id:
                    peers.set(id=peer_id, disabled="true")
                    return True
        return False

    def delete_peer_by_comment(self, name):
        """Delete a peer by its comment/name field."""
        peers = self.api.get_resource("/interface/wireguard/peers")
        all_peers = peers.get()
        for peer in all_peers:
            if peer.get("interface") != self.wireguard_interface:
                continue
            if peer.get("comment", "").strip() == name.strip():
                peer_id = self.get_peer_id(peer)
                if peer_id:
                    peers.remove(id=peer_id)
                    return True
        return False

    def delete_peer_by_allowed_address(self, allowed_address):
        peers = self.api.get_resource("/interface/wireguard/peers")
        all_peers = peers.get()
        for peer in all_peers:
            if peer.get("interface") != self.wireguard_interface:
                continue
            peer_addr = peer.get("allowed-address", "")
            peer_id = self.get_peer_id(peer)
            if allowed_address in peer_addr and peer_id:
                peers.remove(id=peer_id)
                return True
        return False

    def delete_dashboard_peers(self):
        peers = self.api.get_resource("/interface/wireguard/peers")
        all_peers = peers.get()
        deleted_count = 0
        for peer in all_peers:
            if peer.get("interface") != self.wireguard_interface:
                continue
            peer_id = self.get_peer_id(peer)
            if peer_id:
                peers.remove(id=peer_id)
                deleted_count += 1
        return deleted_count