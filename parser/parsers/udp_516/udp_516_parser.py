import logging
import os
import argparse
from tqdm import tqdm 
from kaitaistruct import KaitaiStream

from parser.config import plot_dir, write_dir, logs_dir
from parser.utils.parser_utils import get_log_level_from_verbosity, ensure_directories_exist

from parser.utils.parser_utils import ParserBase


from udp_516 import Udp516

class Udp516Parser(ParserBase):
    def __init__(self, read_file, show_pbar=False, log_level=logging.INFO):
        super().__init__(read_file, protocol='udp_516', show_pbar=show_pbar, log_level=log_level)
        # add custom variables here
        pass
    def consume_byte(self, stream, pos, pbar=None):
        stream.seek(pos + 1)
        self.bytes_skipped += 1
        self.bytes_searched += 1
        if self.show_pbar and pbar:
            pbar.update(1)
    def consume_bytes(self, n, pbar=None):
        self.bytes_searched += n
        if self.show_pbar and pbar:
            pbar.update(n)
    def process_capture(self, capture):
        stream = KaitaiStream(capture)
        pbar = tqdm(total=len(capture), desc=f"Processing {self.protocol_file}") if self.show_pbar else None
        self.skips[0] = len(capture)

        while stream.pos() < len(capture):
            pos = stream.pos()
            self.logger.debug(f"Trying at position: {pos}")
            try:
                udp516 = Udp516(stream)
            except Exception as e:
                self.logger.debug(f"Parse error at {pos}: {e}")
                self.consume_byte(stream, pos, pbar)
            else:
                self.logger.header(f"{udp516.magic}, {udp516.seq}")
                self.logger.debug(f"{udp516.payload}")
                self.write_protocol.write(udp516.payload)
                udp516_bytes = stream._io[pos:stream.pos()]
                self.consume_bytes(len(udp516_bytes), pbar)


    def process_capture_file(self, capture_file, preview_len=None):
        super().process_capture_file(capture_file, preview_len)
    def done_processing(self):
        super().done_processing()
    def log_status(self, logger=None):
        super().log_status(self.logger)    
        logger = self.logger if logger == None else logger
        # udp_516 log custom performance metrics here


def main():
    parser = argparse.ArgumentParser(description="Process udp_516 capture files with custom logging verbosity.")
    parser.add_argument("capture_file", help="Path to the input raw capture file.")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase logging verbosity. Default: INFO. -v: HEADER. -vv: DEBUG. -vvv: PAYLOAD (most verbose).")
    
    args = parser.parse_args()

    log_level = get_log_level_from_verbosity(args.verbose)
    ensure_directories_exist(logs_dir, write_dir, plot_dir)

    capture_file = args.capture_file
    
    udp_516 = Udp516Parser(capture_file, log_level=log_level, show_pbar=True)
    udp_516.process_capture_file(capture_file)
    udp_516.log_status()
    udp_516.done_processing()

    logging.shutdown() # Ensures all log handlers are properly flushed and closed

if __name__ == "__main__":
    main()