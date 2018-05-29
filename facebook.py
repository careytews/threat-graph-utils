
import requests
import json
import urllib

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

class Facebook:
    def __init__(self, id, secret):
        self.id = id
        self.secret = secret
        self.base = "https://graph.facebook.com/"

    def get_ip_report(self, ip):
        
        query_params = urllib.urlencode({
            'access_token': self.id + '|' + self.secret,
            'type': "IP_ADDRESS",
            'text': ip,
            'strict_text' : True
        })

        url = "%s/v2.4/threat_descriptors?" % self.base + query_params

        r = requests.get(url)
        
        if r.status_code != 200:
            print "ERROR"
            raise ApiError(r.text)

        return r.json()

    def get_domain_report(self, domain):
        
        query_params = urllib.urlencode({
            'access_token': self.id + '|' + self.secret,
            'type': "DOMAIN",
            'text': domain,
            'strict_text': True
        })

        url = "%s/v2.4/threat_descriptors?" % self.base + query_params

        r = requests.get(url)
        
        if r.status_code != 200:
            print "ERROR"
            raise ApiError(r.text)

        return r.json()

    def sev_prob(self, x):
        return {
            "UNKNOWN": 0.0,
            "INFO": 0.0,
            "WARNING": 0.2,
            "SUSPICIOUS": 0.3,
            "SEVERE": 0.7,
            "APOCALYPSE": 1.0
        }.get(x, 0.0)

    def status_prob(self, x):
        return {
            "UNKNOWN": 0.0,
            "NON_MALICIOUS": 0.0,
            "SUSPICIOUS": 0.7,
            "MALICIOUS": 0.9
        }.get(x, 0.0)
