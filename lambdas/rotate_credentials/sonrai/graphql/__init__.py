import threading
import requests


class APIClient:
    def __init__(self):
        super().__init__()
        self._thread_local = threading.local()

    def request(self, method, url, token, **kwargs):
        session = self._session()
        headers = kwargs.pop('headers', {})
        if (not headers or 'Authorization' not in headers) and ('Authorization' not in session.headers):
            headers['Authorization'] = 'Bearer ' + token
        return session.request(method, url, headers=headers, **kwargs)

    def _session(self):
        if not hasattr(self._thread_local, 'session'):
            self._thread_local.session = requests.session()
        session = self._thread_local.session
        return session
