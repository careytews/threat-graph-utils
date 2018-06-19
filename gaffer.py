
import os
import requests
import json

class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class GafferError(Error):
    """Exception raised for errors in the input.

    Attributes:
        message -- explanation of the error
    """
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message

class Gaffer:

    def __init__(self, url=None):
        if url == None:
            url = os.getenv("GAFFER")
        if url == None:
            url = "https://analytics.trustnetworks.com/gaffer"
        self.url = url
        self.session = requests.Session()

    def use_cert(self, key=None, cert=None, ca=None, private=None):
        if private == None:
            private = os.getenv("PRIVATE")
        if private == None:
            private = os.getenv("HOME") + "/private"
        if key == None:
            key = private + "/key.me"
        if cert == None:
            cert = private + "/cert.me"
        if ca == None:
            ca = private + "/cert.ca"

        self.session.cert = (cert, key)
        self.session.verify = (ca)

    def get_all(self, entities=[], edges=[]):
        return {
            "class" : "uk.gov.gchq.gaffer.operation.impl.get.GetAllElements",
            "view": {
                "entities": {
                    group: {} for group in entities
                },
                "edges": {
                    group: {} for group in edges
                }
            }
        }

    def limit(self, lim):
        return {
            "class" : "uk.gov.gchq.gaffer.operation.impl.Limit",
            "resultLimit" : lim
        }

    def operation_list(self, lst):
        return {
            "class": "uk.gov.gchq.gaffer.operation.OperationChain",
            "operations": lst
        }

    def execute(self, ops):
        url = self.url + "/rest/v2/graph/operations/execute"

        headers = { "Content-Type": "application/json" }
        res = self.session.post(url,
                                 data=json.dumps(ops),
                                 headers=headers)

        if res.status_code != 200:
            raise GafferError("Status %d" % res.status_code)
        
        return res.json()

    def post(self, path, data=None, stream=False):
        
        headers = { "Content-Type": "application/json" }
        url = self.url + path
  
        res = self.session.post(url,
                                data=data,
                                headers=headers,
                                stream=stream)


        if res.status_code != 200:
            raise GafferError("Status %d" % res.status_code)
        
        return res

    def get(self, path, stream=False):
        
        headers = { "Content-Type": "application/json" }
        url = self.url + path
  
        res = self.session.get(url, stream=stream)

        if res.status_code != 200:
            raise GafferError("Status %d" % res.status_code)
        
        return res

