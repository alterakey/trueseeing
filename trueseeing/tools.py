import logging
log = logging.getLogger(__name__)

def noneif(x, defaulter):
    if x is not None:
        return x
    else:
        if callable(defaulter):
            return defaulter()
        else:
            return defaulter
