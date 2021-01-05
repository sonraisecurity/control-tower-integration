import logging

from sonrai.graphql import APIClient

logger = logging.getLogger()


class GraphQLClient(APIClient):
    def __init__(self, token):
        super().__init__()
        self._token = token
        self._url = token.get_graphql_url()

    def query(self, q, variables=None, raise_for_errors=True):
        params = {
            "query": q,
            "variables": variables
        }
        with self.request('post', self._url, self._token.get(), json=params) as r:
            r.raise_for_status()
            response_data = r.json()
            data = response_data.get('data')
            if raise_for_errors and (not data or response_data.get('errors')):
                raise IOError("Error in query response: {}".format(response_data))
            return data
