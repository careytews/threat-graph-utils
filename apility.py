
import requests
import json

class Apility:
    def __init__(self, uuid):
        self.uuid = uuid
        self.base = "https://api.apility.net"

    def get_ip_reputation(self, ips):
        ips = ",".join(ips)

        url="%s/badip_batch/%s" % (self.base, ips)

        headers = { "X-Auth-Token": self.uuid }

        r = requests.get(url, headers=headers)
        return r.json()["response"]

    def get_domain_reputation(self, i):
        i = ",".join(i)

        url="%s/baddomain_batch/%s" % (self.base, i)

        headers = { "X-Auth-Token": self.uuid }

        r = requests.get(url, headers=headers)
        return r.json()["response"]

