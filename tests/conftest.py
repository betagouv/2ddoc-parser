import os

# Les tests ne doivent pas dépendre du réseau : on configure un cache vide
# pour que le resolver par défaut reste offline.
os.environ.setdefault("FR_2DDOC_KEY_CACHE", "/nonexistent/2ddoc-test-keys")
