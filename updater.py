
import json
import facebook
import threatgraph
import time

class FacebookUpdater:

    @staticmethod
    def domain_updater():
        # Information about me, the prober
        probe="fb-dm-v0"
        probe_time=1
        probe_id = "facebook-domain"

        u = FacebookUpdater(probe=probe, probe_time=probe_time,
                            probe_id=probe_id)

        u.fetcher = FacebookUpdater.get_unprobed_domains

        return u

    @staticmethod
    def ip_updater():
        # Information about me, the prober
        probe="fb-ip-v0"
        probe_time=1
        probe_id = "facebook-ip"

        u = FacebookUpdater(probe=probe, probe_time=probe_time,
                            probe_id=probe_id)

        u.fetcher = FacebookUpdater.get_unprobed_ips

        return u

    def __init__(self, probe, probe_time, probe_id):
        self.g = threatgraph.Gaffer()

        # Blacklist source info
        self.src = "facebook.com"
        self.tp = "blacklist"

        self.probe = probe
        self.probe_time = probe_time
        self.probe_id = probe_id

        # Get Facebook creds
        creds = json.loads(open("facebook-creds").read())
        self.fb = facebook.Facebook(creds["id"], creds["secret"])

    def facebook_threats_to_elts(self, thing, threats):
    
        # Initialise graph elements
        elts = []

        # Iterate over threat data
        for threat in threats:

            ok = True
            for reac in threat.get("reactions", []):
                if reac["key"] == "NOT_HELPFUL":
                    ok = False

            if ok == False:
                print "Ignoring blacklist, marked NOT HELPFUL"
                continue

            if threat["review_status"] == "UNREVIEWED":
                print "Ignore unreviewed threat"
                continue

            # Blacklist name
            bl, prob, id, desc, status, severity, pub = self.fb.parse_threat(threat)

            # Create a blacklist match edge
            elt = self.g.make_match_edge(thing, bl, id=id, description=desc,
                                         status=status, severity=severity)
            elts.append(elt)

            print "Blacklist = ", bl
            print "Probability = ", prob
            print "Description = ", desc

            # Create a blacklist entity (probably exists already)
            elt = self.g.make_blacklist_entity(bl, prob, self.tp, self.src,
                                               pub)
            elts.append(elt)

        # Create a probed edge
        elt = self.g.make_probed_edge(thing, self.probe_id, self.probe,
                                      self.probe_time)
        elts.append(elt)

        # Turn element list into a Gaffer operation
        elts = {
            "class": "uk.gov.gchq.gaffer.operation.impl.add.AddElements",
            "validate": True,
            "skipInvalidElements": False,
            "input": elts
        }

        return elts

    def get_unprobed_domains(self):
        return self.g.get_unprobed_domains(self.probe)
    
    def get_unprobed_ips(self):
        return self.g.get_unprobed_ips(self.probe)
    
    def update(self):

        # Get list of all domains which need to be updated.
        things = self.fetcher(self)
        
        # Iterate over domains
        for thing in things:

            print thing
    
            if self.probe_id == "facebook-domain":
                res = self.fb.get_domain_report(thing)
            else:
                res = self.fb.get_ip_report(thing)

            elts = self.facebook_threats_to_elts(thing, res["data"])

            # Execute Gaffer insert
            url = "/rest/v2/graph/operations/execute"
            data = json.dumps(elts)
            response = self.g.post(url, data)

            # If status code is bad, fail
            if response.status_code != 200:
                print response.text

            time.sleep(0.01)

