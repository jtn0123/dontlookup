"""
DVB-S2(X) IP packet encapsulation parser framework.

This package provides parsers for extracting IP packets from
raw DVB-S2 satellite captures.
"""

# Initialize custom logging levels on import
from parser.config import PAYLOAD_LEVEL_NUM, HEADER_LEVEL_NUM
import logging

# Define custom logging levels
logging.addLevelName(PAYLOAD_LEVEL_NUM, "PAYLOAD")
logging.addLevelName(HEADER_LEVEL_NUM, "HEADER")


def _add_logging_methods():
    """Add payload and header methods to Logger class."""
    def payload(self, message, *args, **kws):
        if self.isEnabledFor(PAYLOAD_LEVEL_NUM):
            self._log(PAYLOAD_LEVEL_NUM, message, args, **kws)

    def header(self, message, *args, **kws):
        if self.isEnabledFor(HEADER_LEVEL_NUM):
            self._log(HEADER_LEVEL_NUM, message, args, **kws)

    logging.Logger.payload = payload
    logging.Logger.header = header


_add_logging_methods()
