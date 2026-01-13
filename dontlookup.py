#!/usr/bin/env python3
"""
Main entry point for running DVB-S2 parsers on capture files.
This tool allows you to run multiple parser combinations and see packet counts.
"""

import logging
import os
import argparse
import sys
import warnings

# Suppress IPv4 address warnings from scapy/dpkt
warnings.filterwarnings('ignore', message='.*No IPv4 address found.*')
warnings.filterwarnings('ignore', category=UserWarning)

# Suppress scapy warnings specifically
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from parser.config import plot_dir, write_dir, logs_dir
from parser.utils.parser_utils import get_log_level_from_verbosity

from parser.parsers.dvbs2.dvbs2_parser import DVBS2Parser
from parser.parsers.gse.gse_parser import (
    StandardLenSplitCacheGSEParser,
    StandardLenStandardCacheGSEParser,
    Len2SplitCacheGSEParser,
    Len2StandardCacheGSEParser
)
from parser.parsers.ip.ip_parser import IPv4Parser
from parser.parsers.mpegts.mpegts_parser import MpegtsParser
from parser.parsers.mpegts.generic_crc_parser import GenericCrcParser
from parser.parsers.mpegts.newtec_crc_parser import NewtecCrcParser
from parser.parsers.rev.rev_parser import ReverseParser


class ParserRunner:
    """Manages running various parser combinations and reporting results."""
    
    AVAILABLE_PARSERS = {
        'dvbs2-ip': 'DVBS2 -> IP',
        'dvbs2-rev-ip': 'DVBS2 -> Reverse -> IP',
        'dvbs2-mpegts': 'DVBS2 -> MPEG-TS',
        'dvbs2-mpegts-crc': 'DVBS2 -> MPEG-TS with Generic CRC',
        'dvbs2-mpegts-newtec': 'DVBS2 -> MPEG-TS with Newtec CRC',
        'dvbs2-gse-stdlen-split-ip': 'DVBS2 -> GSE (standard length, split frag ID) -> IP',
        'dvbs2-gse-stdlen-std-ip': 'DVBS2 -> GSE (standard length, standard frag ID) -> IP',
        'dvbs2-gse-len2-split-ip': 'DVBS2 -> GSE (hdrlen-2, split frag ID) -> IP',
        'dvbs2-gse-len2-std-ip': 'DVBS2 -> GSE (hdrlen-2, standard frag ID) -> IP',
    }
    
    def __init__(self, capture_file, log_level=logging.INFO, show_pbar=False):
        self.capture_file = capture_file
        self.log_level = log_level
        self.show_pbar = show_pbar
        self.results = {}
        
        # Ensure output directories exist
        for directory in [logs_dir, write_dir, plot_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)
    
    def run_dvbs2_ip(self):
        """Run DVBS2 -> IP."""
        print("\n=== Running: DVBS2 -> IP ===")
        dvbs2 = DVBS2Parser(self.capture_file, log_level=self.log_level, show_pbar=self.show_pbar)
        dvbs2.process_capture_file(self.capture_file)
        dvbs2.done_processing()
        
        ip = IPv4Parser(dvbs2.protocol_file, log_level=self.log_level, show_pbar=self.show_pbar)
        ip.process_capture_file(dvbs2.protocol_file)
        ip.done_processing()
        
        self.results['dvbs2-ip'] = {
            'bbframes': dvbs2.num_bbframes,
            'ip_packets': self._count_packets_in_file(ip.protocol_file)
        }
        print(f"  BBFrames found: {dvbs2.num_bbframes}")
        print(f"  IP packets found: {self.results['dvbs2-ip']['ip_packets']}")
    
    def run_dvbs2_rev_ip(self):
        """Run DVBS2 -> Reverse -> IP."""
        print("\n=== Running: DVBS2 -> Reverse -> IP ===")
        dvbs2 = DVBS2Parser(self.capture_file, log_level=self.log_level, show_pbar=self.show_pbar)
        rev = ReverseParser(dvbs2.protocol_file, log_level=self.log_level)
        dvbs2.add_parser(rev)
        
        dvbs2.process_capture_file(self.capture_file)
        dvbs2.done_processing()
        rev.done_processing()
        
        ip = IPv4Parser(rev.protocol_file, log_level=self.log_level, show_pbar=self.show_pbar)
        ip.process_capture_file(rev.protocol_file)
        ip.done_processing()
        
        self.results['dvbs2-rev-ip'] = {
            'bbframes': dvbs2.num_bbframes,
            'ip_packets': self._count_packets_in_file(ip.protocol_file)
        }
        print(f"  BBFrames found: {dvbs2.num_bbframes}")
        print(f"  IP packets found: {self.results['dvbs2-rev-ip']['ip_packets']}")
    
    def run_dvbs2_mpegts(self):
        """Run DVBS2 -> MPEG-TS."""
        print("\n=== Running: DVBS2 -> MPEG-TS ===")
        dvbs2 = DVBS2Parser(self.capture_file, log_level=self.log_level, show_pbar=self.show_pbar)
        dvbs2.process_capture_file(self.capture_file)
        dvbs2.done_processing()
        
        mpegts = MpegtsParser(dvbs2.protocol_file, log_level=self.log_level, show_pbar=self.show_pbar)
        mpegts.process_capture_file(dvbs2.protocol_file)
        mpegts.done_processing()
        
        self.results['dvbs2-mpegts'] = {
            'bbframes': dvbs2.num_bbframes,
            'mpegts_packets': mpegts.num_transport_packets
        }
        print(f"  BBFrames found: {dvbs2.num_bbframes}")
        print(f"  MPEG-TS packets found: {mpegts.num_transport_packets}")
    
    def run_dvbs2_mpegts_crc(self):
        """Run DVBS2 -> MPEG-TS with Generic CRC."""
        print("\n=== Running: DVBS2 -> MPEG-TS (Generic CRC) ===")
        dvbs2 = DVBS2Parser(self.capture_file, log_level=self.log_level, show_pbar=self.show_pbar)
        crc_mpegts = GenericCrcParser(dvbs2.protocol_file, log_level=self.log_level, write_unsafe=True)
        dvbs2.add_parser(crc_mpegts)
        
        dvbs2.process_capture_file(self.capture_file)
        dvbs2.done_processing()
        crc_mpegts.done_processing()
        
        self.results['dvbs2-mpegts-crc'] = {
            'bbframes': dvbs2.num_bbframes,
            'mpegts_packets': crc_mpegts.num_transport_packets
        }
        print(f"  BBFrames found: {dvbs2.num_bbframes}")
        print(f"  MPEG-TS packets found: {crc_mpegts.num_transport_packets}")
    
    def run_dvbs2_mpegts_newtec(self):
        """Run DVBS2 -> MPEG-TS with Newtec CRC."""
        print("\n=== Running: DVBS2 -> MPEG-TS (Newtec CRC) ===")
        dvbs2 = DVBS2Parser(self.capture_file, log_level=self.log_level, show_pbar=self.show_pbar)
        newtec_crc = NewtecCrcParser(dvbs2.protocol_file, log_level=self.log_level, write_unsafe=True)
        dvbs2.add_parser(newtec_crc)
        
        dvbs2.process_capture_file(self.capture_file)
        dvbs2.done_processing()
        newtec_crc.done_processing()
        
        self.results['dvbs2-mpegts-newtec'] = {
            'bbframes': dvbs2.num_bbframes,
            'mpegts_packets': newtec_crc.num_transport_packets
        }
        print(f"  BBFrames found: {dvbs2.num_bbframes}")
        print(f"  MPEG-TS packets found: {newtec_crc.num_transport_packets}")
    
    def run_dvbs2_gse_ip(self, variant):
        """Run DVBS2 -> GSE -> IP with specified variant."""
        variant_map = {
            'stdlen-split': ('standard length, split frag ID', StandardLenSplitCacheGSEParser, 'stdlen.split.gse'),
            'stdlen-std': ('standard length, standard frag ID', StandardLenStandardCacheGSEParser, 'stdlen.std.gse'),
            'len2-split': ('hdrlen-2, split frag ID', Len2SplitCacheGSEParser, 'len2.split.gse'),
            'len2-std': ('hdrlen-2, standard frag ID', Len2StandardCacheGSEParser, 'len2.std.gse'),
        }
        
        desc, parser_class, protocol = variant_map[variant]
        parser_name = f'dvbs2-gse-{variant}-ip'
        
        print(f"\n=== Running: DVBS2 -> GSE ({desc}) -> IP ===")
        
        dvbs2 = DVBS2Parser(self.capture_file, log_level=self.log_level, show_pbar=self.show_pbar)
        gse = parser_class(dvbs2.protocol_file, protocol=protocol, log_level=self.log_level)
        
        dvbs2.add_parser(gse)
        dvbs2.process_capture_file(self.capture_file)
        dvbs2.done_processing()
        gse.done_processing()
        
        ip = IPv4Parser(gse.protocol_file, log_level=self.log_level, show_pbar=self.show_pbar)
        ip.process_capture_file(gse.protocol_file)
        ip.done_processing()
        
        result = {
            'bbframes': dvbs2.num_bbframes,
            'gse_packets': gse.num_gse_packets,
            'gse_whole': gse.num_whole_pdu,
            'gse_start': gse.num_start_pdu,
            'gse_middle': gse.num_middle_pdu,
            'gse_end': gse.num_end_pdu,
            'gse_padding': gse.num_padding,
            'ip_packets': self._count_packets_in_file(ip.protocol_file)
        }
        
        print(f"  BBFrames found: {dvbs2.num_bbframes}")
        print(f"  GSE packets found: {gse.num_gse_packets}")
        print(f"    - Whole PDUs: {gse.num_whole_pdu}")
        print(f"    - Start PDUs: {gse.num_start_pdu}")
        print(f"    - Middle PDUs: {gse.num_middle_pdu}")
        print(f"    - End PDUs: {gse.num_end_pdu}")
        print(f"    - Padding: {gse.num_padding}")
        
        # Add fragment cache info
        if hasattr(gse, 'split_fragment_cache'):
            result['reassembled'] = gse.split_fragment_cache.num_reassembled
            print(f"    - Reassembled (split frag ID): {gse.split_fragment_cache.num_reassembled}")
        elif hasattr(gse, 'fragment_cache'):
            result['reassembled'] = gse.fragment_cache.num_reassembled
            print(f"    - Reassembled (std frag ID): {gse.fragment_cache.num_reassembled}")
        
        print(f"  IP packets found: {result['ip_packets']}")
        
        self.results[parser_name] = result
    
    def _count_packets_in_file(self, filename):
        """Count packets by file size (rough estimate)."""
        if os.path.exists(filename):
            size = os.path.getsize(filename)
            # Estimate: average IP packet is ~500 bytes
            return size // 500 if size > 0 else 0
        return 0
    
    def print_summary(self):
        """Print summary of all results."""
        print("\n" + "="*70)
        print("SUMMARY OF ALL PARSERS")
        print("="*70)
        
        for parser_name, results in self.results.items():
            print(f"\n{parser_name}:")
            for key, value in results.items():
                print(f"  {key}: {value}")


def main():
    parser = argparse.ArgumentParser(
        description="Run DVB-S2 parsers on capture files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available parsers:
  dvbs2-ip                   - DVBS2 -> IP
  dvbs2-rev-ip               - DVBS2 -> Reverse -> IP
  dvbs2-mpegts               - DVBS2 -> MPEG-TS
  dvbs2-mpegts-crc           - DVBS2 -> MPEG-TS with Generic CRC
  dvbs2-mpegts-newtec        - DVBS2 -> MPEG-TS with Newtec CRC
  dvbs2-gse-stdlen-split-ip  - DVBS2 -> GSE (standard length, split frag ID) -> IP
  dvbs2-gse-stdlen-std-ip    - DVBS2 -> GSE (standard length, standard frag ID) -> IP
  dvbs2-gse-len2-split-ip    - DVBS2 -> GSE (hdrlen-2, split frag ID) -> IP
  dvbs2-gse-len2-std-ip      - DVBS2 -> GSE (hdrlen-2, standard frag ID) -> IP
  all                        - Run all parsers

Examples:
  # Run a single parser
  python3 dontlookup.py capture.ts -p dvbs2-ip

  # Run multiple parsers
  python3 dontlookup.py capture.ts -p dvbs2-ip -p dvbs2-mpegts

  # Run all parsers (default)
  python3 dontlookup.py capture.ts -p all
  python3 dontlookup.py capture.ts  # same as above
        """
    )
    
    parser.add_argument(
        "capture_file",
        help="Path to the input capture file"
    )
    
    parser.add_argument(
        "-p", "--parser",
        action="append",
        dest="parsers",
        choices=list(ParserRunner.AVAILABLE_PARSERS.keys()) + ['all'],
        help="Parser(s) to run. Can be specified multiple times. Use 'all' to run all parsers."
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase logging verbosity. Default: INFO. -v: HEADER. -vv: DEBUG. -vvv: PAYLOAD."
    )
    
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress bars"
    )
    
    args = parser.parse_args()

    # Set log level
    log_level = get_log_level_from_verbosity(args.verbose)
    
    # Default to 'all' if no parsers specified
    if not args.parsers:
        args.parsers = ['all']
    
    # Expand 'all' to all available parsers
    parsers_to_run = []
    if 'all' in args.parsers:
        parsers_to_run = list(ParserRunner.AVAILABLE_PARSERS.keys())
    else:
        parsers_to_run = args.parsers
    
    # Validate capture file exists
    if not os.path.exists(args.capture_file):
        print(f"Error: Capture file '{args.capture_file}' not found", file=sys.stderr)
        sys.exit(1)
    
    # Create runner
    runner = ParserRunner(
        args.capture_file,
        log_level=log_level,
        show_pbar=not args.no_progress
    )
    
    print(f"Processing capture file: {args.capture_file}")
    print(f"Running {len(parsers_to_run)} parser(s)...")

    # Parser dispatch table - maps parser names to their run methods
    parser_dispatch = {
        'dvbs2-ip': runner.run_dvbs2_ip,
        'dvbs2-rev-ip': runner.run_dvbs2_rev_ip,
        'dvbs2-mpegts': runner.run_dvbs2_mpegts,
        'dvbs2-mpegts-crc': runner.run_dvbs2_mpegts_crc,
        'dvbs2-mpegts-newtec': runner.run_dvbs2_mpegts_newtec,
        'dvbs2-gse-stdlen-split-ip': lambda: runner.run_dvbs2_gse_ip('stdlen-split'),
        'dvbs2-gse-stdlen-std-ip': lambda: runner.run_dvbs2_gse_ip('stdlen-std'),
        'dvbs2-gse-len2-split-ip': lambda: runner.run_dvbs2_gse_ip('len2-split'),
        'dvbs2-gse-len2-std-ip': lambda: runner.run_dvbs2_gse_ip('len2-std'),
    }

    # Run parsers using dispatch table
    for parser_name in parsers_to_run:
        try:
            if parser_name in parser_dispatch:
                parser_dispatch[parser_name]()
            else:
                print(f"Unknown parser: {parser_name}", file=sys.stderr)
        except Exception as e:
            print(f"\nError running parser '{parser_name}': {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
    
    # Print summary
    runner.print_summary()
    
    logging.shutdown()


if __name__ == "__main__":
    main()
