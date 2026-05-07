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

    # ─── Firewall / Address-list helpers ───────────────────────────────────────

    _BLOCK_LIST    = "pipsqueeze-lan-block"
    _BLOCK_COMMENT = "pipsqueeze"

    def ensure_lan_block_rule(self):
        """Create a forward-DROP rule for the pipsqueeze-lan-block list if absent."""
        try:
            fw    = self.api.get_resource("/ip/firewall/filter")
            rules = fw.get()
            for r in rules:
                if self._BLOCK_LIST in r.get("comment", ""):
                    return
            lan_subnet = os.getenv("LAN_SUBNET", "192.168.88.0/24")
            fw.add(**{
                "chain":            "forward",
                "src-address-list": self._BLOCK_LIST,
                "dst-address":      lan_subnet,
                "action":           "drop",
                "comment":          self._BLOCK_LIST,
            })
        except Exception as e:
            print(f"[firewall] ensure_lan_block_rule: {e}")

    def _get_block_entries(self):
        al      = self.api.get_resource("/ip/firewall/address-list")
        entries = al.get()
        return [e for e in entries if e.get("list") == self._BLOCK_LIST]

    def add_to_lan_block(self, ip):
        """Add a VPN client IP to the LAN block address-list."""
        try:
            addr    = ip if "/" in ip else ip + "/32"
            entries = self._get_block_entries()
            for e in entries:
                if e.get("address", "").split("/")[0] == ip.split("/")[0]:
                    return
            al = self.api.get_resource("/ip/firewall/address-list")
            al.add(**{"list": self._BLOCK_LIST, "address": addr, "comment": self._BLOCK_COMMENT})
        except Exception as e:
            print(f"[firewall] add_to_lan_block({ip}): {e}")

    def remove_from_lan_block(self, ip):
        """Remove a VPN client IP from the LAN block address-list."""
        try:
            ip_bare = ip.split("/")[0]
            entries = self._get_block_entries()
            al      = self.api.get_resource("/ip/firewall/address-list")
            for e in entries:
                if e.get("address", "").split("/")[0] == ip_bare:
                    eid = e.get("id") or e.get(".id")
                    if eid:
                        al.remove(id=eid)
        except Exception as e:
            print(f"[firewall] remove_from_lan_block({ip}): {e}")

    def get_lan_block_ips(self):
        """Return set of bare IPs currently in the block list."""
        try:
            return {e.get("address", "").split("/")[0] for e in self._get_block_entries()}
        except Exception:
            return set()

    def sync_firewall_rules(self, clients):
        """Reconcile address-list with DB state. clients: list of dicts with ip & access_mode."""
        self.ensure_lan_block_rule()
        current     = self.get_lan_block_ips()
        should_block = {c["ip"] for c in clients if c.get("access_mode", "internet") == "internet"}
        for ip in should_block - current:
            self.add_to_lan_block(ip)
        for ip in current - should_block:
            self.remove_from_lan_block(ip)
        return len(should_block)

    def get_firewall_rule_count(self):
        try:
            fw = self.api.get_resource("/ip/firewall/filter")
            return len(fw.get())
        except Exception:
            return -1

    # ───────────────────────────────────────────────────────────────────────────

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