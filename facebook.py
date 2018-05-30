
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
            "UNKNOWN": 0.1,
            "INFO": 0.3,
            "WARNING": 0.5,
            "SUSPICIOUS": 0.7,
            "SEVERE": 0.9,
            "APOCALYPSE": 1.0
        }.get(x, 0.0)

    def status_prob(self, x):
        return {
            "UNKNOWN": 0.1,
            "NON_MALICIOUS": 0.0,
            "SUSPICIOUS": 0.7,
            "MALICIOUS": 1.0
        }.get(x, 0.0)

    def parse_threat(self, threat):

        severity = threat["severity"]
        status=threat["status"]
        owner_id = threat["owner"]["id"]
        pub = threat["owner"]["name"]
        conf = threat["confidence"]

        # Convoluted way to make a blacklist name out of severity status,
        # confidence
        tag = severity[0] + status[0] + str(int(conf / 10))
        blacklist = "%s.%s.%s" % ("facebook", owner_id, tag)

        id = threat["id"]

        if threat.has_key("description"):
            desc = threat["description"]
        else:
            desc = ""

        # Make confidence a value in 0..1 to one decimal place.
        conf = int(conf / 10)/10.0

        print self.status_prob(status), self.sev_prob(severity), conf
        prob = self.status_prob(status) * self.sev_prob(severity) * conf
        pub = threat["owner"]["name"]

        return blacklist, prob, id, desc, status, severity, pub

