import logging
import os
import argparse
from tqdm import tqdm 
from io import BytesIO

from parser.config import plot_dir, write_dir, logs_dir
from parser.config import BBHEADER_LEN, ZERO_SKIP, PREVIEW_LENGTH
from parser.utils.parser_utils import get_log_level_from_verbosity, ensure_directories_exist
from crccheck.crc import Crc8DvbS2

from parser.utils.parser_utils import ParserBase, crc32mpeg2
from kaitaistruct import KaitaiStream

from dvbs2 import Dvbs2
from parser.parsers.mpegts.crc_parser import CrcParser
from parser.parsers.gse.gse_parser import StandardLenSplitCacheGSEParser, StandardLenStandardCacheGSEParser, Len2SplitCacheGSEParser, Len2StandardCacheGSEParser
from parser.parsers.mpegts.newtec_crc_parser import NewtecCrcParser
from parser.parsers.mpegts.generic_crc_parser import GenericCrcParser
class MemoryViewReader:
    def __init__(self, mv):
        self._mv = mv
        self._pos = 0

    def read(self, n=-1):
        if n < 0:
            n = len(self._mv) - self._pos
        data = self._mv[self._pos:self._pos + n]
        self._pos += len(data)
        return data.tobytes()

    def seek(self, pos, whence=0):
        if whence == 0:
            self._pos = pos
        elif whence == 1:
            self._pos += pos
        elif whence == 2:
            self._pos = len(self._mv) + pos
        else:
            raise ValueError("Invalid whence")

    def tell(self):
        return self._pos

    def __len__(self):
        return len(self._mv)

    def __getitem__(self, key):
        return self._mv[key]


class DVBS2Parser(ParserBase):
    def __init__(self, read_file, show_pbar=False, log_level=logging.INFO):
        super().__init__(read_file, protocol='dvbs2', show_pbar=show_pbar, log_level=log_level)
        # add custom variables here
        self.num_00_skips = 0
        self.num_bbframes = 0
        self.num_crc_encoded_bbframes = 0
        pass
    def reset(self):
        super().reset()
        self.num_00_skips = 0
        self.num_bbframes = 0
        self.num_crc_encoded_bbframes = 0
    def check_bbheader(self, bbheader_bytes):
        assert Crc8DvbS2.calc(bbheader_bytes[:9]) == bbheader_bytes[9] and bbheader_bytes != bytearray(BBHEADER_LEN)
    def check_bbframe(self, bbframe):
        crc_calc = crc32mpeg2(bbframe[:-4], crc=0x00000000)
        crc_val = int.from_bytes(bbframe[-4:], byteorder="big")
        assert crc_calc == crc_val, "CRC does not match"
    def consume_byte(self, stream, pos, pbar):
        stream.seek(pos + 1)
        self.bytes_skipped += 1
        self.bytes_searched += 1
        if self.show_pbar and pbar:
            pbar.update(1)
    def consume_bytes(self, n, pbar):
        self.bytes_searched += n
        if self.show_pbar and pbar:
            pbar.update(n)
    def record_bbframe(self):
        self.num_bbframes += 1
    def extract_data_field(self, bbframe_bytes):
        try:
            self.check_bbframe(bbframe_bytes)
        except Exception:
            self.logger.debug("CRC FAILS")
            return bbframe_bytes[BBHEADER_LEN:]
        else:
            self.logger.debug("CRC SUCCEEDS")
            self.num_crc_encoded_bbframes += 1
            return bbframe_bytes[BBHEADER_LEN:-4]
    def print_bbheader(self, bbheader: Dvbs2, bbheader_bytes):
        DF_LEN = int(bbheader.dfl/8)
        UP_LEN = int(bbheader.upl/8)
        SYNC_D = int(bbheader.syncd/8)
        self.logger.debug(bbheader.matype.ts_gs)
        self.logger.debug(bbheader.matype.sis_mis)
        self.logger.debug(bbheader.matype.ccm_acm)
        self.logger.debug(bbheader.matype.issyi)
        self.logger.debug(bbheader.matype.npd)
        self.logger.debug(bbheader.matype.ro)
        
        
        self.logger.header(f"BBHEADER: {bbheader_bytes.hex()}, \tUP_LEN={UP_LEN}, \tSYNC_D={SYNC_D}, \tDF_LEN={DF_LEN}")
    def process_capture(self, capture):
        stream = KaitaiStream(capture)
        prev_frame_end = 0
        
        
        pbar = tqdm(total=len(capture), desc=f"Processing {self.protocol_file}") if self.show_pbar else None
        self.skips[0] = len(capture)
        while stream.pos() < len(capture):
            pos = stream.pos()
            self.logger.debug(f"Trying at position: {pos}")
            
            try:
                bbframe = Dvbs2(stream)
            except Exception as e:
                self.logger.debug(f"Parse error at {pos}: {e}")
                self.consume_byte(stream, pos, pbar)
            else: 
                
                self.logger.debug(f"Candidate bbframe at {pos}")
                
                bbframe_bytes = stream._io[pos:stream.pos()]
                bbheader_bytes = bbframe_bytes[0:BBHEADER_LEN]
                # self.logger.debug(bbheader_bytes.hex())
                try:
                    self.check_bbheader(bbheader_bytes)
                except AssertionError as e:
                    self.logger.debug(f"Invalid checksum at {pos}: {e}")
                    self.consume_byte(stream, pos, pbar)
                else: 
                    self.print_bbheader(bbframe, bbheader_bytes)
                    self.record_bbframe()

                    # self.logger.header(f"bbheader {bbheader_bytes.hex()}")
                    
                    data_field = self.extract_data_field(bbframe_bytes)
                    
                    self.logger.payload(f"data_field {data_field}")
                    for parser in self.parsers:
                        if isinstance(parser, CrcParser):
                            parser.process_capture(data_field, int(bbframe.upl/8), int(bbframe.syncd/8))
                        elif isinstance(parser, GenericCrcParser):
                           parser.process_capture(data_field, int(bbframe.upl/8), int(bbframe.syncd/8))
                        elif isinstance(parser, NewtecCrcParser):
                            parser.process_capture(data_field, int(bbframe.upl/8), int(bbframe.syncd/8))
                        elif isinstance(parser, StandardLenSplitCacheGSEParser):
                            mv = MemoryViewReader(memoryview(data_field))
                            parser.process_capture(mv)
                        elif isinstance(parser, StandardLenStandardCacheGSEParser):
                            mv = MemoryViewReader(memoryview(data_field))                        
                            parser.process_capture(mv)
                        elif isinstance(parser, Len2SplitCacheGSEParser):
                            mv = MemoryViewReader(memoryview(data_field))                        
                            parser.process_capture(mv)
                        elif isinstance(parser, Len2StandardCacheGSEParser):
                            mv = MemoryViewReader(memoryview(data_field))                        
                            parser.process_capture(mv)
                        else:
                            parser.process_capture(data_field)
                            # pass
                            

                    self.write_protocol.write(data_field)
                    self.skips[prev_frame_end] = pos
                    SKIPPED_BYTES = stream._io[prev_frame_end:pos]
                    self.logger.debug(f"skipped bytes {SKIPPED_BYTES.hex()}, matches {ZERO_SKIP}? {SKIPPED_BYTES==ZERO_SKIP}")
                    if SKIPPED_BYTES == ZERO_SKIP: 
                        self.num_00_skips += 1
                    else: 
                        self.write_skips.write(SKIPPED_BYTES)
                    prev_frame_end = stream.pos()    
                    self.consume_bytes(len(bbframe_bytes), pbar)  

    def process_capture_file(self, capture_file, preview_len=None):
        super().process_capture_file(capture_file, preview_len)
    def done_processing(self):
        super().done_processing()
    def log_status(self, logger=None):
        super().log_status(self.logger)    
        logger = self.logger if logger == None else logger
        # DVBS2 log custom performance metrics here
        logger.info(f"{self.num_bbframes} BBFRAMES were found")
        logger.info(f"{self.num_crc_encoded_bbframes} of {self.num_bbframes} BBFRAMES have a 4 byte CRC")
        logger.info(f"{self.num_00_skips} of {self.num_bbframes} BBFRAMES were padded with 0x00")



def main():
    parser = argparse.ArgumentParser(description="Process DVBS2 capture files with custom logging verbosity.")
    parser.add_argument("capture_file", help="Path to the input raw capture file.")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase logging verbosity. Default: INFO. -v: HEADER. -vv: DEBUG. -vvv: PAYLOAD (most verbose).")
    
    args = parser.parse_args()

    log_level = get_log_level_from_verbosity(args.verbose)
    ensure_directories_exist(logs_dir, write_dir, plot_dir)

    capture_file = args.capture_file
    
    DVBS2 = DVBS2Parser(capture_file, log_level=log_level, show_pbar=True)
    DVBS2.process_capture_file(capture_file)
    DVBS2.log_status()
    DVBS2.done_processing()
    # DVBS2.plot_skips()

    logging.shutdown() # Ensures all log handlers are properly flushed and closed

if __name__ == "__main__":
    main()