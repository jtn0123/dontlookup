import logging
import os
import argparse
from tqdm import tqdm 
from collections import Counter
import math

from parser.config import plot_dir, write_dir, logs_dir
from parser.config import MPEG_TS_SYNC_BYTE
from parser.utils.parser_utils import get_log_level_from_verbosity, ensure_directories_exist

from parser.utils.parser_utils import ParserBase

from crccheck.crc import Crc8DvbS2

class GenericCrcParser(ParserBase):
    def __init__(self, read_file, show_pbar=False, log_level=logging.INFO, write_unsafe=False):
        super().__init__(read_file, protocol='crc', show_pbar=show_pbar, log_level=log_level)
        # add custom variables here
        self.num_transport_packets = 0
        self.prev_crc = 0
        self.prev_trailer = bytearray()
        self.write_unsafe = write_unsafe
        
        pass
    def reset(self):
        super().reset()
        self.num_transport_packets = 0
        self.prev_crc = 0
        self.prev_trailer = bytearray()

    def process_capture(self, data_field, UP_LEN, SYNC_DISTANCE):
        if UP_LEN != 188: 
            self.logger.warning(f"invalid upl={UP_LEN}")
            return
        # self.logger.debug(data_field.hex())
        if len(data_field) % 188 == 0:
            self.logger.debug(f"data field length is modulo 188")
        self.logger.debug(f"TRAILER: {self.prev_trailer}")
        self.logger.debug(f"DATA FIELD: {data_field}")
        user_packet_stream = self.prev_trailer + data_field
        self.logger.debug(f"START OF USER PACKET STREAM")
        while len(user_packet_stream) >= UP_LEN:
            self.logger.debug(f"USER PACKET STREAM: {user_packet_stream.hex()}")
            self.logger.debug(f"USER PACKET STREAM: {user_packet_stream}")
            user_packet_with_crc = user_packet_stream[0:UP_LEN]
            self.logger.debug(f"ATTEMPTING {user_packet_with_crc}")
            user_packet = user_packet_with_crc[1:UP_LEN]
            if self.prev_crc == user_packet_with_crc[0]:
                self.logger.header(f"USER PACKET {MPEG_TS_SYNC_BYTE+user_packet}")
                self.write_protocol.write(MPEG_TS_SYNC_BYTE + user_packet)
                self.logger.debug(f"CRIB {user_packet_with_crc[1:3].hex()}")
                self.num_transport_packets += 1
            else: 
                self.bytes_skipped += UP_LEN
            del user_packet_stream[0:UP_LEN]
            self.bytes_searched += 188
            self.prev_crc = Crc8DvbS2.calc(user_packet)
        
        self.prev_trailer = user_packet_stream

    def process_capture_file(self, capture_file, preview_len=None):
        super().process_capture_file(capture_file, preview_len)
    def done_processing(self):
        super().done_processing()
    def log_status(self, logger=None):
        super().log_status(logger)  
        logger = self.logger if logger == None else logger
        logger.info(f"{self.num_transport_packets} crc encoded transport packets were found")



def main():
    parser = argparse.ArgumentParser(description="Process TODO capture files with custom logging verbosity.")
    parser.add_argument("capture_file", help="Path to the input raw capture file.")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase logging verbosity. Default: INFO. -v: HEADER. -vv: DEBUG. -vvv: PAYLOAD (most verbose).")
    
    args = parser.parse_args()

    log_level = get_log_level_from_verbosity(args.verbose)
    ensure_directories_exist(logs_dir, write_dir, plot_dir)

    capture_file = args.capture_file
    
    crc = GenericCrcParser(capture_file, log_level=log_level)
    crc.process_capture_file(capture_file)
    crc.log_status()
    crc.done_processing()

    logging.shutdown() # Ensures all log handlers are properly flushed and closed

if __name__ == "__main__":
    main()
    