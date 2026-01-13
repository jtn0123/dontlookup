import logging
import os
import argparse
from tqdm import tqdm 
from io import BytesIO

from parser.config import plot_dir, write_dir, logs_dir
from parser.utils.parser_utils import get_log_level_from_verbosity, ensure_directories_exist

from parser.utils.parser_utils import ParserBase, flip_bytes
from parser.parsers.gse.gse_parser import StandardGSEParser, HdrlenGSEParser
from parser.parsers.dvbs2.dvbs2_parser import MemoryViewReader

class ReverseParser(ParserBase):
    def __init__(self, read_file, show_pbar=False, log_level=logging.INFO):
        super().__init__(read_file, protocol='rev', show_pbar=show_pbar, log_level=log_level)
        # add custom variables here
        pass
    def format_bytes(self, data: bytearray):
        first_part = data[:104]
        rest = data[104:]

        # Format the first 104 bytes as hex
        output = [first_part.hex()]

        # Now format each 270-byte chunk from the rest
        for i in range(0, len(rest), 270):
            chunk = rest[i:i+270]
            output.append(chunk.hex())

        # Join chunks with a space or newline
        return ' \t'.join(output)  # use ' '.join(output) if you prefer space-separated

    def process_capture(self, capture):
        # TODO for user to implement
        flipped_bytes = flip_bytes(bytearray(capture))
        # on some captures, ip traffic is fragmented across reversed payloads and the header is a two byte identifier of some kind, so leaving it out will result in correctly bounded ip packets. This works because even on non-fragmented IP packets, there is a 4 byte header. 
        self.write_protocol.write(flipped_bytes[2:])
        # self.write_protocol.write(flipped_bytes)
        # self.logger.info(f"len={len(flipped_bytes)} {flipped_bytes.hex()}")
        self.logger.info(self.format_bytes(flipped_bytes))
        # self.logger.info(flipped_bytes.hex())
        for parser in self.parsers:
            if isinstance(parser, StandardGSEParser):
                parser.process_capture(MemoryViewReader(memoryview(flipped_bytes)))
            elif isinstance(parser, HdrlenGSEParser):
                parser.process_capture(MemoryViewReader(memoryview(flipped_bytes)))
                
        # pass
    def process_capture_file(self, capture_file, preview_len=None):
        super().process_capture_file(capture_file, preview_len)
    def done_processing(self):
        super().done_processing()
    def log_status(self, logger=None):
        super().log_status(self.logger)    
        logger = self.logger if logger == None else logger
        # TODO log custom performance metrics here


def main():
    parser = argparse.ArgumentParser(description="Reverse capture files with custom logging verbosity.")
    parser.add_argument("capture_file", help="Path to the input raw capture file.")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase logging verbosity. Default: INFO. -v: HEADER. -vv: DEBUG. -vvv: PAYLOAD (most verbose).")
    
    args = parser.parse_args()

    log_level = get_log_level_from_verbosity(args.verbose)
    ensure_directories_exist(logs_dir, write_dir, plot_dir)

    capture_file = args.capture_file
    
    rev = ReverseParser(capture_file, log_level=log_level)
    rev.process_capture_file(capture_file)
    # rev.log_status()
    rev.done_processing()

    logging.shutdown() # Ensures all log handlers are properly flushed and closed

if __name__ == "__main__":
    main()