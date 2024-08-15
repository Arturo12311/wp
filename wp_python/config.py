import datetime

PROXY_HOST = '192.168.2.145'
PROXY_PORT = 8888
TIMESTAMP = None

def initialize_timestamp():
    global TIMESTAMP
    TIMESTAMP = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

def get_timestamp():
    return TIMESTAMP