import jwt
import time
import logging

class GraphQLToken:
    _ENV_KEY = 'https://sonraisecurity.com/env'
    _ORG_KEY = 'https://sonraisecurity.com/org'
    _GRAPHQL_URL_FMT = 'https://{}{}.sonraisecurity.com/graphql'
    _EXPIRY_THRESHOLD_SEC = 0

    def __init__(self, token_str):
        self._value = None
        self._set(token_str)

    def expired(self):
        now = time.time()
        remaining = self._exp - now
        logging.info("Token expires in: {}".format(remaining))
        return remaining < self._EXPIRY_THRESHOLD_SEC

    def get_graphql_url(self):
        if self._value is None:
            self.get()
        env = self._env
        org = self._org
        if not env:
            raise ValueError("No env present in token")
        if not org:
            raise ValueError("No org present in token")
        if env.startswith("c"):
            env_sub = ''
        elif len(env) == 3:
            env_sub = '.' + env[:2]
        elif len(env) > 3:
            env_sub = '.' + env[:1]
        else:
            raise ValueError("Unsupported env: {}".format(env))
        return self._GRAPHQL_URL_FMT.format(org, env_sub)

    def _set(self, value):
        if not value:
            raise ValueError("No token specified")
        decoded = jwt.decode(value, verify=False)
        self._value = value
        self._org = decoded.get(self._ORG_KEY, None)
        self._env = decoded.get(self._ENV_KEY, None)
        self._exp = int(decoded.get('exp', 0))

    def get(self):
        return self._value

    def _refresh(self, force=False):
        raise NotImplementedError()




