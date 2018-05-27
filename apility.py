
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

