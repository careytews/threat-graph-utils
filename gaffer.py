
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

class ViewGroup:
    def __init__(self, name, exclude=None):
        self.name=name
        self.exclude=exclude

    def encode(self):
        obj = {self.name: {}}
        if obj != None:
            obj[self.name]["excludeProperties"] = self.exclude
        return obj

            
class GetAllElements:

    ALL=[]
    NONE=None
    
    def __init__(self, entities=ALL, edges=ALL):
        self.entities = entities
        self.edges = edges

    def encode_group(self, g):
        if type(g) == str:
            return {g: {}}
#         if type(g) == unicode:
#             return {g: {}}
        if isinstance(g, ViewGroup):
            return g.encode()
        raise TypeError("Needs to be string, unicode or GroupView")
        
    def encode(self):
        op = {
            "class" : "uk.gov.gchq.gaffer.operation.impl.get.GetAllElements",
            "view": {
            }
        }
        if self.entities != None:
            op["view"]["entities"] = {}
            for group in self.entities:
                op["view"]["entities"] = dict(op["view"]["entities"], **self.encode_group(group))
        if self.edges != None:
            op["view"]["edges"] = {}
            for group in self.edges:
                op["view"]["edges"] = dict(op["view"]["edges"], **self.encode_group(group))
        return op
    
    def set_entities(self, entities=ALL):
        self.entities=entities
    
    def set_edges(self, edges=ALL):
        self.edges=edges

class GetElements:

    ALL=[]
    NONE=None
    
    def __init__(self, entities=ALL, edges=ALL, include="EITHER"):
        self.entities = entities
        self.edges = edges
        self.include = include

    def encode_group(self, g):
        if type(g) == str:
            return {g: {}}
#         if type(g) == unicode:
#             return {g: {}}
        if isinstance(g, ViewGroup):
            return g.encode()
        raise TypeError("Needs to be string, unicode or GroupView")
    
    def encode(self):
        op = {
            "class" : "uk.gov.gchq.gaffer.operation.impl.get.GetElements",
            "view": {
            },
            "includeIncomingOutGoing": self.include
        }
        if self.entities != None:
            op["view"]["entities"] = {}
            for group in self.entities:
                op["view"]["entities"] = dict(op["view"]["entities"], **self.encode_group(group))
        if self.edges != None:
            op["view"]["edges"] = {}
            for group in self.edges:
                op["view"]["edges"] = dict(op["view"]["edges"], **self.encode_group(group))
        return op
    
    def set_entities(self, entities=ALL):
        self.entities=entities
    
    def set_edges(self, edges=ALL):
        self.edges=edges

class OperationChain:

    def __init__(self, operations=[]):
        self.operations = operations

    def encode(self):
        return {
            "class": "uk.gov.gchq.gaffer.operation.OperationChain",
            "operations": [ op.encode() for op in self.operations ]
        }
    
    def add(self, op):
        self.operations.append(op)

class GetWalks:

    def __init__(self, operations=[], limit=None):
        self.operations = operations
        self.limit = limit

    def encode(self):
        op = {
            "class": "uk.gov.gchq.gaffer.operation.impl.GetWalks",
            "operations": [v.encode() for v in self.operations]
        }
        if self.limit != None:
            op["resultsLimit"] = self.limit
        return op
    
    def add(self, op):
        self.operations.append(op)

    def set_limit(self, limit):
        self.limit = limit

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
        return GetAll(entities, edges)

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

        if type(ops) == dict:
            data = json.dumps(ops)
        else:
            data=json.dumps(ops.encode())
                            
        url = self.url + "/rest/v2/graph/operations/execute"

        headers = { "Content-Type": "application/json" }
        res = self.session.post(url, data, headers=headers)

        if res.status_code != 200:
            raise GafferError("Status %d: %s" % (res.status_code, res.text))
        
        return res.json()

    def execute_chunked(self, ops):

        if type(ops) == dict:
            data = json.dumps(ops)
        else:
            data=json.dumps(ops.encode())

        url = self.url + "/rest/v2/graph/operations/execute/chunked"

        headers = { "Content-Type": "application/json" }

        res = self.session.post(url, data, headers=headers, stream=True)

        if res.status_code != 200:
            raise GafferError("Status %d: %s" % (res.status_code, res.text))

        return res.iter_lines()

    def post(self, path, data=None, stream=False):
        
        headers = { "Content-Type": "application/json" }
        url = self.url + path
  
        res = self.session.post(url,
                                data=data,
                                headers=headers,
                                stream=stream)

        if res.status_code != 200:
            raise GafferError("Status %d: %s" % (res.status_code, res.text))
        
        return res

    def get(self, path, stream=False):
        
        headers = { "Content-Type": "application/json" }
        url = self.url + path
  
        res = self.session.get(url, stream=stream)

        if res.status_code != 200:
            raise GafferError("Status %d: %s" % (res.status_code, res.text))
        
        return res

