
import gaffer
import ipaddress
import time

class Gaffer(gaffer.Gaffer):
    def __init__(self):
        url = "https://analytics.trustnetworks.com/gaffer-threat"
        gaffer.Gaffer.__init__(self, url)
        self.use_cert()

    def get_all_ips(self):
        op = gaffer.GetAllElements(entities=["ip"], edges=None)
        res = self.execute(op)
        ips = set([v["vertex"] for v in res])

        return ips

    def get_all_domains(self):

        op = gaffer.GetAllElements(entities=["domain"], edges=None)
        res = self.execute(op)
        domains = set([v["vertex"] for v in res])

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

        seen_ips = set([list(v["entities"][0].keys())[0] for v in res])

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

        seen_domains = set([list(v["entities"][0].keys())[0] for v in res])

        return seen_domains

    def remove_private_ips(self, ips):

        # Remove private addresses
        private = set()
        for v in ips:
            if ipaddress.ip_address(v).is_private:
                private.add(v)
        return ips - private

    def make_match_edge(self, ip, blacklist, id="", description="",
                        status="", severity="", time=time.time()):

        elt = {
 	    "class": "uk.gov.gchq.gaffer.data.element.Edge",
 	    "properties": {
                "time": {
                    "uk.gov.gchq.gaffer.time.RBMBackedTimestampSet": {
                        "timeBucket": "HOUR",
                        "timestamps": [time]
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
                              pub="", name="", time=time.time()):

        elt = {
 	    "class": "uk.gov.gchq.gaffer.data.element.Entity",
            "properties": {
                "update": {
                    "uk.gov.gchq.gaffer.time.RBMBackedTimestampSet": {
                        "timeBucket": "HOUR",
                        "timestamps": [time]
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

    def get_unprobed_domains(self, my_probe):

        # Get list of all domains which need to be updated.
        domains = self.get_all_domains()
        seen_domains = self.get_probed_domains(my_probe)
        domains = domains - seen_domains

        return domains

    def get_unprobed_ips(self, my_probe):

        # Get list of all IPs which need to be updated.
        ips = self.get_all_ips()
        seen_ips = self.get_probed_ips(my_probe)

        ips = ips - seen_ips
        ips = self.remove_private_ips(ips)

        return ips

