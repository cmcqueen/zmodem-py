
import logging
import logging.handlers
import os.path

# configurable file logger
class RotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Easier setup for RotatingFileHandler."""
    def __init__(self, filename, mode='a', maxBytes=0, backupCount=0, encoding=None, delay=False):
        """Args same as for RotatingFileHandler, but in filename '~' is expanded."""
        fn = os.path.expandvars(os.path.expanduser(filename))
        logging.handlers.RotatingFileHandler.__init__(self, fn, mode=mode, maxBytes=maxBytes, backupCount=backupCount, encoding=encoding, delay=delay)
