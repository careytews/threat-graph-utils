
import requests
import json

class RateLimit(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class ApiError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class Apility:
    def __init__(self, uuid):
        self.uuid = uuid
        self.base = "https://api.apility.net"

    def get_ip_reputation(self, ips):
        ips = ",".join(ips)

        url="%s/badip_batch/%s" % (self.base, ips)

        headers = { "X-Auth-Token": self.uuid }

        r = requests.get(url, headers=headers)

        if r.status_code == 429:
            raise RateLimit("Rate limit exceeded")

        if r.status_code != 200:
            raise ApiError(r.text)

        return r.json()["response"]

    def get_domain_reputation(self, i):
        i = ",".join(i)

        url="%s/baddomain_batch/%s" % (self.base, i)

        headers = { "X-Auth-Token": self.uuid }

        r = requests.get(url, headers=headers)

        if r.status_code == 429:
            raise RateLimit("Rate limit exceeded")

        if r.status_code != 200:
            raise ApiError(r.text)
            
        return r.json()["response"]

    def get_probability(self, bl):
        return {
            "ALIENVAULT-REPUTATION": 0.3,
            "BBCAN177-MS1": 0.3,
            "BBCAN177-MS3": 0.3,
            "BLOCKLISTNET-UA": 0.3,
            "BRUTEFORCEBLOCKER": 0.3,
            "ETHERSCAMDB-DOMAINS": 0.05,
            "FAIL2BAN-APACHE": 0.3,
            "FAIL2BAN-BOTS": 0.3,
            "FAIL2BAN-IMAP": 0.3,
            "FAIL2BAN-MAIL": 0.3,
            "FAIL2BAN-SSH": 0.3,
            "FAIL2BAN-STRONGIPS": 0.3,
            "FREEMAIL": 0.05,
            "IANA-BOGONS": 0.3,
            "NIXSPAM-IP": 0.3,
            "SQUIDBLACKLIST-MALICIOUS-DOMAINS": 0.1,
            "STOPFORUMSPAM-180": 0.3,
            "STOPFORUMSPAM-30": 0.3,
            "STOPFORUMSPAM-365": 0.3,
            "STOPFORUMSPAM-90": 0.3,
            "TEAMCYMRU-BOGONS": 0.0,
            "TOP100-1D-IP": 0.3,
            "UCEPROTECT-BACKSCATTERER": 0.3,
            "UCEPROTECT-LEVEL1": 0.3,
            "UDGER-TOR": 0.3
        }.get(bl, 0.1)

