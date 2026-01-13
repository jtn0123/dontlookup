"""
Configuration settings for the DVB-S2 parser framework.

All directory paths can be overridden via environment variables:
    DVB_OUTPUT_DIR   - Output directory for parsed data (default: output/)
    DVB_LOGS_DIR     - Directory for log files (default: logs/)
    DVB_PLOTS_DIR    - Directory for generated plots (default: plots/)
    DVB_PROMISING_DIR - Directory for promising results (default: promising/)

Example:
    export DVB_OUTPUT_DIR=/path/to/custom/output
    python dontlookup.py capture.ts
"""

import os

# Directory paths - configurable via environment variables
write_dir = os.environ.get('DVB_OUTPUT_DIR', 'output/')
logs_dir = os.environ.get('DVB_LOGS_DIR', 'logs/')
plot_dir = os.environ.get('DVB_PLOTS_DIR', 'plots/')
promising_dir = os.environ.get('DVB_PROMISING_DIR', 'promising/')

# Ensure directories end with /
if not write_dir.endswith('/'):
    write_dir += '/'
if not logs_dir.endswith('/'):
    logs_dir += '/'
if not plot_dir.endswith('/'):
    plot_dir += '/'
if not promising_dir.endswith('/'):
    promising_dir += '/'

# DVB-S2 Base Band Header constants
BBHEADER_LEN = 10  # Base Band header length in bytes

# MPEG-TS constants
MPEG_TS_SYNC_BYTE = b'\x47'  # MPEG-TS synchronization byte
MPEG_FRAME_SIZE = 188  # Standard MPEG-TS packet size in bytes

# Parsing constants
ZERO_SKIP = b'\x00'  # Zero byte for padding detection
IP_HEADER_MIN_SIZE = 20  # Minimum IPv4 header size in bytes
GSE_HEADER_MIN_LEN = 2  # Minimum GSE header length in bytes

# Preview length for initial file analysis (in bytes)
PREVIEW_LENGTH = 1000000  # 1 MB

# Custom logging levels
# Standard levels: DEBUG=10, INFO=20, WARNING=30, ERROR=40, CRITICAL=50
PAYLOAD_LEVEL_NUM = 5   # Most verbose - shows payload data
HEADER_LEVEL_NUM = 15   # Shows header information (between DEBUG and INFO)
