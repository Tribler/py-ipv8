import json

from geoip import geolite2
from twisted.web import resource


class CrawlerGeoEndpoint(resource.Resource):
    """
    This endpoint is responsible for handing all requests regarding the crawler geo lookup.
    """

    def __init__(self, session):
        resource.Resource.__init__(self)
        self.session = session

    def render_GET(self, request):
        network = self.session.network
        peer_list = network.verified_peers[:]
        countries_dict = {}
        for p in peer_list:
            data = geolite2.lookup(p.address[0])
            if data:
                countries_dict[data.country] = 1 + countries_dict.get(data.country, 0)
            else:
                countries_dict['?'] = 1 + countries_dict.get('?', 0)
        return json.dumps(countries_dict)
