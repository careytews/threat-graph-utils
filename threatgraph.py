
import gaffer
import sets
import ipaddress
import time

class Gaffer(gaffer.Gaffer):
    def __init__(self):
        url = "https://analytics.trustnetworks.com/gaffer-threat"
        gaffer.Gaffer.__init__(self, url)
        self.use_cert()

    def get_all_ips(self):
        query = {
            "class": "uk.gov.gchq.gaffer.operation.OperationChain",
            "operations": [
                {
                    "class": "uk.gov.gchq.gaffer.operation.impl.get.GetAllElements",
                    "view": {
                        "entities": {
                            "ip": {
                            }
                        }
                    }
                }
            ]
        }

        res = self.execute(query)
        ips = sets.Set([v["vertex"] for v in res])

        return ips

    def get_all_domains(self):
        query = {
            "class": "uk.gov.gchq.gaffer.operation.OperationChain",
            "operations": [
                {
                    "class": "uk.gov.gchq.gaffer.operation.impl.get.GetAllElements",
                    "view": {
                        "entities": {
                            "domain": {
                            }
                        }
                    }
                }
            ]
        }

        res = self.execute(query)
        domains = sets.Set([v["vertex"] for v in res])

        return domains

    def get_probed_ips(self, probe):

        query = {
            "class": "uk.gov.gchq.gaffer.operation.OperationChain",
            "operations": [
                {
                    "class": "uk.gov.gchq.gaffer.operation.impl.get.GetAllElements",
                    "view": {
                        "entities": {
                            "ip": {
                            }
                        }
                    }
                    
                },
                {
                    "class" : "uk.gov.gchq.gaffer.operation.impl.GetWalks",
                    "operations" : [
                        {
                            "class" : "uk.gov.gchq.gaffer.operation.OperationChain",
                            "operations" : [
                                {
                                    "class" : "uk.gov.gchq.gaffer.operation.impl.get.GetElements",
                                    "includeIncomingOutGoing" : "OUTGOING",
                                    "view": {
                                        "edges": {
                                            "probed": {
                                                "preAggregationFilterFunctions" : [
                                                    {
                                                        "selection" : [ "probe" ],
                                                        "predicate" : {
                                                            "class" : "uk.gov.gchq.koryphe.impl.predicate.IsEqual",
                                                            "value" : probe
                                                        }
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        res = self.execute(query)

        seen_ips = sets.Set([v["entities"][0].keys()[0] for v in res])

        return seen_ips

    def get_probed_domains(self, probe):

        query = {
            "class": "uk.gov.gchq.gaffer.operation.OperationChain",
            "operations": [
                {
                    "class": "uk.gov.gchq.gaffer.operation.impl.get.GetAllElements",
                    "view": {
                        "entities": {
                            "domain": {
                            }
                        }
                    }
                    
                },
                {
                    "class" : "uk.gov.gchq.gaffer.operation.impl.GetWalks",
                    "operations" : [
                        {
                            "class" : "uk.gov.gchq.gaffer.operation.OperationChain",
                            "operations" : [
                                {
                                    "class" : "uk.gov.gchq.gaffer.operation.impl.get.GetElements",
                                    "includeIncomingOutGoing" : "OUTGOING",
                                    "view": {
                                        "edges": {
                                            "probed": {
                                                "preAggregationFilterFunctions" : [
                                                    {
                                                        "selection" : [ "probe" ],
                                                        "predicate" : {
                                                            "class" : "uk.gov.gchq.koryphe.impl.predicate.IsEqual",
                                                            "value" : probe
                                                        }
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        res = self.execute(query)

        seen_domains = sets.Set([v["entities"][0].keys()[0] for v in res])

        return seen_domains

    def remove_private_ips(self, ips):

        # Remove private addresses
        private = sets.Set()
        for v in ips:
            if ipaddress.ip_address(v).is_private:
                private.add(v)
        return ips - private

    def make_match_edge(self, ip, blacklist, id="", description="",
                        status="", severity=""):

        elt = {
 	    "class": "uk.gov.gchq.gaffer.data.element.Edge",
 	    "properties": {
                "time": {
                    "uk.gov.gchq.gaffer.time.RBMBackedTimestampSet": {
                        "timeBucket": "HOUR",
                        "timestamps": [time.time()]
                    }
                }
            },
 	    "group": "matches",
 	    "source": ip,
 	    "destination": blacklist,
 	    "directed": True
        }

        if id != "": elt["properties"]["id"] = id
        if description != "": elt["properties"]["description"] = description
        if status != "": elt["properties"]["status"] = status
        if severity != "": elt["properties"]["severity"] = severity

        return elt

    def make_blacklist_entity(self, blacklist, prob=0.3, tp="", source="",
                              pub="", name="", ):

        elt = {
 	    "class": "uk.gov.gchq.gaffer.data.element.Entity",
            "properties": {
                "update": {
                    "uk.gov.gchq.gaffer.time.RBMBackedTimestampSet": {
                        "timeBucket": "HOUR",
                        "timestamps": [time.time()]
                        }
                },
                "probability": prob
            },
            "group": "blacklist",
            "vertex": blacklist
        }

        if tp != "": elt["properties"]["type"] = tp
        if source != "": elt["properties"]["source"] = source
        if pub != "": elt["properties"]["publisher"] = pub

        return elt

    def make_probed_edge(self, thing, prober, probe, time):
        return {
 	    "class": "uk.gov.gchq.gaffer.data.element.Edge",
            "source": thing,
            "destination": prober,
            "properties": {
                "probe": probe,
                "probetime": time
            },
            "group": "probed"
        }
