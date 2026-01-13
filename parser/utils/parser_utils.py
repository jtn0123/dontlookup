import dpkt
import time
import socket
from kaitaistruct import KaitaiStream, BytesIO
import sys
from datetime import datetime
import random
import argparse
import os
import logging
import mmap
from tqdm import tqdm
from multiprocessing import get_context, Pool, freeze_support, current_process
from collections import defaultdict, Counter, deque
from parser.utils.pcaplib import Writer
from scapy.all import *
load_layer("tls")

# Optional cryptography import for TLS certificate parsing
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    x509 = None
    default_backend = None

from parser.config import PAYLOAD_LEVEL_NUM, HEADER_LEVEL_NUM
from parser.config import BBHEADER_LEN, MPEG_TS_SYNC_BYTE, IP_HEADER_MIN_SIZE, GSE_HEADER_MIN_LEN
from parser.config import write_dir, plot_dir, logs_dir


def get_log_level_from_verbosity(verbose_count: int) -> int:
    """
    Convert a verbosity count (from argparse -v flags) to a logging level.

    Args:
        verbose_count: Number of -v flags specified (0, 1, 2, 3+)

    Returns:
        Appropriate logging level integer

    Examples:
        0 -> logging.INFO (20)
        1 -> HEADER_LEVEL_NUM (15)
        2 -> logging.DEBUG (10)
        3+ -> PAYLOAD_LEVEL_NUM (5)
    """
    if verbose_count == 0:
        return logging.INFO
    elif verbose_count == 1:
        return HEADER_LEVEL_NUM
    elif verbose_count == 2:
        return logging.DEBUG
    else:
        return PAYLOAD_LEVEL_NUM


def ensure_directories_exist(*directories: str) -> None:
    """
    Ensure that the specified directories exist, creating them if necessary.

    Args:
        *directories: Variable number of directory paths to create
    """
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)

def initialize_custom_logging_levels():
    """
    Defines custom logging levels (PAYLOAD, HEADER) and adds convenience methods
    to the logging.Logger class. This function should be called ONCE at
    application startup to ensure custom levels are registered.
    """
    # Check if levels are already added to prevent re-adding warnings/errors
    # (though typically called once, this makes it robust)
    if not hasattr(logging, 'PAYLOAD'): # Check for convenience attribute
        logging.addLevelName(PAYLOAD_LEVEL_NUM, 'PAYLOAD')
        # Add convenience method for PAYLOAD level
        def payload(self, message, *args, **kws):
            if self.isEnabledFor(PAYLOAD_LEVEL_NUM):
                self._log(PAYLOAD_LEVEL_NUM, message, args, **kws)
        logging.Logger.payload = payload

    if not hasattr(logging, 'HEADER'): # Check for convenience attribute
        logging.addLevelName(HEADER_LEVEL_NUM, 'HEADER')
        # Add convenience method for HEADER level
        def header(self, message, *args, **kws):
            if self.isEnabledFor(HEADER_LEVEL_NUM):
                self._log(HEADER_LEVEL_NUM, message, args, **kws)
        logging.Logger.header = header


def parse_tls_cert(cert_bytes: bytes) -> None:
    """
    Parse and print details from a DER-encoded TLS certificate.

    Args:
        cert_bytes: DER-encoded certificate data

    Note:
        Requires cryptography. Install with: pip install dontlookup[crypto]
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        logging.warning(
            "cryptography not available. Install with: pip install dontlookup[crypto]"
        )
        return

    try:
        cert = x509.load_der_x509_certificate(cert_bytes, backend=default_backend())

        print("=== Certificate Details ===")
        print("Subject:         ", cert.subject.rfc4514_string())
        print("Issuer:          ", cert.issuer.rfc4514_string())
        print("Serial Number:   ", hex(cert.serial_number))
        print("Valid From:      ", cert.not_valid_before.isoformat())
        print("Valid To:        ", cert.not_valid_after.isoformat())
        print("Signature Algo:  ", cert.signature_algorithm_oid._name)
        print("Public Key Type: ", cert.public_key().__class__.__name__)
        print("Extensions:")
        for ext in cert.extensions:
            print(f"  - {ext.oid._name if ext.oid._name else ext.oid.dotted_string}: {ext.value}")
    except Exception as e:
        print("Failed to parse certificate:", str(e))

def create_pcap_handler(filename):
    pcap_file_writer = open(filename, 'wb')
    pcap_writer = Writer()
    pcap_writer.create_header(pcap_file_writer)    
    return pcap_file_writer, pcap_writer

def write_ip_packet_to_pcap(pcap_file_writer, pcap_writer, ip_packet_bytes):

    # Capture the current time and packet length for PCAP writing
    seconds_time = time.time()
    dt = datetime.now()
    packet_length = len(ip_packet_bytes)
    
    # Create a packet tuple as expected by the PCAP writer
    simple_packet = (
        int(seconds_time),  # timestamp seconds
        dt.microsecond,     # timestamp microseconds
        packet_length,      # captured length
        packet_length,      # original length
        ip_packet_bytes     # actual IP packet data
    )

    # Write the IP packet to the PCAP file
    pcap_writer.write([simple_packet], pcap_file_writer)

def close_pcap_handler(pcap_file_writer):
    if pcap_file_writer is not None:
        pcap_file_writer.close()

def flip_bytes(bytearray_input):
    bytearray_copy = bytearray_input.copy()  # Create a shallow copy of the input
    for i in range(0, len(bytearray_copy) - 1, 2):
        bytearray_copy[i], bytearray_copy[i + 1] = bytearray_copy[i + 1], bytearray_copy[i]
    return bytearray_copy

def crc32mpeg2(buf, crc=0xffffffff):
    # https://stackoverflow.com/questions/69332500/how-can-calculate-mpeg2-crc32-in-python
    for val in buf:
        crc ^= val << 24
        for _ in range(8):
            crc = crc << 1 if (crc & 0x80000000) == 0 else (crc << 1) ^ 0x104c11db7
    return crc

def create_file_logger(filename, level=logging.INFO):
    """
    Creates a logger that writes log messages to the given filename.
    """
    logger = logging.getLogger(filename)
    logger.setLevel(level)  # Set the desired log level
    
    # Create a file handler that logs messages to the specified file
    file_handler = logging.FileHandler(filename, mode='w')  # Open in binary write mode
    file_handler.setLevel(level)  # Set the level for the handler
    
    # Create a formatter and set it for the handler
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    # formatter = logging.Formatter('%(asctime)s - %(levelname)-7s - %(message)s')
    file_handler.setFormatter(formatter)
    
    # Add the handler to the logger
    logger.addHandler(file_handler)
    
    return logger


def open_file_writer(filename):
    return open(filename, 'wb')

def close_file_writer(file_writer):
    file_writer.close()


# Optional matplotlib import for plotting functionality
try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    plt = None


def plot_skips(file_name: str, skips: dict) -> None:
    """
    Generate a visualization of skipped byte ranges in the capture file.

    Args:
        file_name: Base name for the output plot file
        skips: Dictionary mapping start positions to end positions of skipped ranges

    Note:
        Requires matplotlib. Install with: pip install dontlookup[plot]
    """
    if not MATPLOTLIB_AVAILABLE:
        logging.warning(
            "matplotlib not available. Install with: pip install dontlookup[plot]"
        )
        return

    max_index = max(skips.values(), default=0)

    plt.figure(figsize=(20, 3))

    current_pos = 0
    for start, end in sorted(skips.items()):
        if start > current_pos:
            plt.fill_between([current_pos, start], 0, 1, color='g')
        plt.fill_between([start, end], 0, 1, color='r')
        current_pos = end + 1

    if current_pos <= max_index:
        plt.fill_between([current_pos, max_index], 0, 1, color='g')

    plt.title(f"Skipped Ranges in {os.path.basename(file_name)}")
    plt.xlabel("Index in File")
    plt.yticks([])
    plt.xlim(0, max_index)
    plt.ylim(0, 1)

    plot_filename = f"{file_name}.png"
    plt.savefig(plot_filename, bbox_inches='tight')
    plt.close()


class ParserBase:
    """
    Base class for all protocol parsers in the DVB-S2 framework.

    This class provides common functionality for parsing capture files,
    including file I/O, logging, progress tracking, and statistics.

    Attributes:
        read_file: Base name of the input file being processed
        protocol: Protocol identifier string (e.g., 'dvbs2', 'ip', 'gse')
        show_pbar: Whether to show progress bars during processing
        log_level: Logging verbosity level
        protocol_file: Path to output file for parsed protocol data
        skips_file: Path to output file for skipped/unparsed data
        bytes_searched: Total bytes examined during parsing
        bytes_skipped: Bytes that couldn't be parsed
        parsers: List of chained downstream parsers
    """

    def __init__(
        self,
        read_file: str,
        protocol: str,
        show_pbar: bool = False,
        log_level: int = logging.INFO
    ) -> None:
        """
        Initialize a parser instance.

        Args:
            read_file: Path to the input capture file
            protocol: Protocol identifier for output file naming
            show_pbar: Enable progress bar display
            log_level: Logging level (use logging constants or custom levels)
        """
        self.read_file = os.path.basename(read_file)
        self.protocol = protocol
        self.show_pbar = show_pbar
        self.log_level = log_level

        self.plot_file = plot_dir + self.read_file + f".{protocol}"
        self.protocol_file = write_dir + self.read_file + f".{protocol}"
        self.skips_file = write_dir + self.read_file + f".not_{protocol}"

        self.log_file = logs_dir + self.read_file + f".{protocol}.log"

        self.write_protocol = open_file_writer(self.protocol_file)
        self.write_skips = open_file_writer(self.skips_file)

        self.logger = create_file_logger(self.log_file, level=log_level)

        self.bytes_searched: int = 0
        self.bytes_skipped: int = 0
        self.skips: dict = {}
        self.parsers: list = []

    def reset(self) -> None:
        """Reset the parser state for reprocessing a file."""
        self.bytes_searched = 0
        self.bytes_skipped = 0
        self.skips = {}
        self.parsers = []
        self.write_protocol = open_file_writer(self.protocol_file)
        self.write_skips = open_file_writer(self.skips_file)
        self.logger = create_file_logger(self.log_file, level=self.log_level)

    def add_parser(self, parser: 'ParserBase') -> None:
        """
        Add a downstream parser to the processing chain.

        Args:
            parser: Parser instance to receive extracted data
        """
        self.parsers.append(parser)

    def process_capture(self, capture) -> None:
        """
        Process capture data. Override in subclasses.

        Args:
            capture: Memory-mapped file content or bytes-like object
        """
        pass

    def process_capture_file(
        self,
        capture_file: str,
        preview_len: int = None
    ) -> None:
        """
        Open and process a capture file using memory mapping.

        Args:
            capture_file: Path to the capture file
            preview_len: Optional limit on bytes to process (for previewing)
        """
        try:
            with open(capture_file, 'rb') as f:
                if preview_len is not None:
                    file_size = f.seek(0, 2)
                    preview_len = min(preview_len, file_size)
                    f.seek(0)
                    with mmap.mmap(f.fileno(), preview_len, access=mmap.ACCESS_READ) as capture:
                        self.process_capture(capture)
                else:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as capture:
                        self.process_capture(capture)
        except FileNotFoundError:
            self.logger.error(f"File not found: '{capture_file}'")
        except Exception as e:
            self.logger.error(f"Error processing file: {e}")

    def done_processing(self) -> None:
        """Clean up resources after processing is complete."""
        close_file_writer(self.write_protocol)
        close_file_writer(self.write_skips)

    def plot_skips(self) -> None:
        """Generate a visualization of skipped byte ranges."""
        plot_skips(self.plot_file, self.skips)

    def log_status(self, logger: logging.Logger = None) -> None:
        """
        Log parsing statistics.

        Args:
            logger: Optional alternative logger to use
        """
        logger = self.logger if logger is None else logger
        logger.info(f"After running the {self.protocol.upper()} Parser on {self.read_file}")
        logger.info(f"{self.bytes_skipped} bytes were skipped in a {self.bytes_searched} byte search space")
        if self.bytes_searched == 0:
            logger.info(f"{self.protocol.upper()} Parser was initialized, but never called")
        else:
            compliance = ((self.bytes_searched - self.bytes_skipped) / self.bytes_searched) * 100
            logger.info(f"{compliance:.2f}% of the capture is {self.protocol.upper()} compliant")
        logger.debug(f"num_bytes_searched {self.bytes_searched}")
        logger.debug(f"num_bytes_skipped {self.bytes_skipped}")
    def get_compliance(self) -> float:
        """
        Calculate the compliance ratio of the parsed data.

        Returns:
            Float between 0 and 1 representing the fraction of bytes
            that were successfully parsed (not skipped).
        """
        if self.bytes_searched == 0:
            return 0.0
        return (self.bytes_searched - self.bytes_skipped) / self.bytes_searched


import json

class ParserResults:
    def __init__(self):
        self.summary_file = "summary.json"
        self.current_file = None
        self.current_chain = []

    def start_file(self, capture_file):
        """Begin recording a new file's parser chain."""
        self.current_file = capture_file
        self.current_chain = []

    def add_parser(self, parser_name, compliance):
        """Append a parser stage to the current chain."""
        if self.current_file is None:
            raise RuntimeError("Call start_file() before adding parsers.")
        self.current_chain.append({
            "parser": parser_name,
            "compliance": float(compliance)
        })

    def finalize_file(self):
        """Write the current file's chain as a JSON line to summary.json."""
        if self.current_file is None:
            return
        record = {
            "file": self.current_file,
            "chain": self.current_chain
        }
        # Append as a single line (JSONL)
        with open(self.summary_file, "a") as f:
            f.write(json.dumps(record) + "\n")
        self.current_file = None
        self.current_chain = []
