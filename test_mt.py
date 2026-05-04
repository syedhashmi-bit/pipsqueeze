from mikrotik_api import MikroTikAPI

mt = MikroTikAPI()
mt.connect()

peers = mt.get_peers()

for p in peers:
    print(p)

mt.disconnect()
