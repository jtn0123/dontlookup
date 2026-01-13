import logging
import os
import argparse
from tqdm import tqdm 
from collections import Counter

from parser.config import plot_dir, write_dir, logs_dir, promising_dir
from parser.config import PREVIEW_LENGTH
from parser.utils.parser_utils import get_log_level_from_verbosity, ensure_directories_exist

from parser.utils.parser_utils import ParserBase, crc32mpeg2, create_file_logger, open_file_writer, close_file_writer
from kaitaistruct import KaitaiStream

from gse_standard import GseStandard
from gse_standard_split import GseStandardSplit
from gse_hdrlen import GseHdrlen
from gse_hdrlen_split import GseHdrlenSplit
from gse_hdrlen_unsafe import GseHdrlenUnsafe

class FragmentCache:
    def __init__(self, logger):
        self.logger = logger
        self.fragment_cache = {}
        self.fragment_len_cache = {}
        self.num_fragments = 0
        self.num_collisions = 0
        self.num_reassembled = 0
        self.num_start_fragments = 0
        
    def check_pdu(self, pdu):
        crc_calc = crc32mpeg2(pdu[:-4], crc=0x00000000)
        crc_val = int.from_bytes(pdu[-4:], byteorder="big")
        assert crc_calc == crc_val, "CRC does not match"

    def print_fragment_cache(self):
        for frag_id, fragment in self.fragment_cache.items():
            self.logger.debug(
                f"Frag ID: {frag_id}, Fragment: {fragment.hex()}")

    def update(self, gse_header):
        if gse_header.is_padding:
            return None

        if gse_header.is_whole:
            return None

        else:
            self.num_fragments += 1
            frag_id = gse_header.payload.frag_id
            payload = bytearray(gse_header.payload.data)
            if gse_header.is_start:
                if frag_id in self.fragment_cache:
                    self.num_collisions += 1
                    partial_fragment = self.fragment_cache.pop(frag_id)
                    self.fragment_cache[frag_id] = payload
                    self.fragment_len_cache[frag_id] = gse_header.payload.total_length
                    self.logger.debug(
                        f"PARTIAL FRAGMENT {frag_id} {partial_fragment.hex()}")
                    # return partial_fragment
                    return None

                else:
                    self.num_start_fragments += 1
                    self.fragment_cache[frag_id] = payload
                    self.fragment_len_cache[frag_id] = gse_header.payload.total_length

            elif gse_header.is_middle:
                if frag_id in self.fragment_cache:
                    self.fragment_cache[frag_id] += payload

            elif gse_header.is_end:
                if frag_id in self.fragment_cache:
                    self.fragment_cache[frag_id] += payload
                    reassembled_pdu = self.fragment_cache.pop(frag_id)
                    total_length = self.fragment_len_cache.pop(frag_id)
                    self.logger.debug(gse_header.payload.crc)
                    if total_length >= len(reassembled_pdu):
                        try:
                            self.check_pdu(reassembled_pdu)
                        except AssertionError as e:
                            self.logger.debug(f"CRC FAILS: {e}")
                        else:
                            self.logger.debug("CRC SUCCEEDS")

                        self.logger.payload(
                            f"REASSEMBLED PDU: {reassembled_pdu.hex()}")

                        self.num_reassembled += 1

                        return reassembled_pdu

                    else:
                        self.logger.debug(
                            f"REASSEMBLED FRAGMENT HAS WRONG LENGTH")
                        return None

        return None

    def log_status(self, logger=None):
        logger = self.logger if logger is None else logger
        logger.debug(f"num_fragments {self.num_fragments}")
        logger.debug(f"num_collisions {self.num_collisions}")
        logger.debug(f"num_reassembled {self.num_reassembled}")
        logger.debug(f"num_start_fragments {self.num_start_fragments}")

    def can_parse(self):
        if self.num_reassembled == 0:
            return False
        if self.num_start_fragments == 0:
            return False
        return self.num_reassembled / self.num_start_fragments > 0.1


class GSEParserBase(ParserBase):
    def __init__(self, read_file, protocol='gse', show_pbar=False, log_level=logging.INFO):
        super().__init__(read_file, protocol=protocol, show_pbar=show_pbar, log_level=log_level)

        self.num_gse_packets = 0
        self.num_whole_pdu = 0
        self.num_start_pdu = 0
        self.num_middle_pdu = 0
        self.num_end_pdu = 0
        self.num_padding = 0
        
        self.protocol_types = Counter()
    def is_encrypted(self):
        if self.protocol_types:
            if self.protocol_types.most_common()[0][0] == '5':
                return True
            else: 
                return False
        else: 
            return False
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

    def count(self, gse_packet):
        self.num_gse_packets += 1
        if gse_packet.is_padding:
            self.num_padding += 1
        elif gse_packet.is_start:
            self.num_start_pdu += 1
        elif gse_packet.is_middle:
            self.num_middle_pdu += 1
        elif gse_packet.is_end:
            self.num_end_pdu += 1
        elif gse_packet.is_whole:
            self.num_whole_pdu += 1
    def print_gse_fields(self, gse_header):
        if gse_header.is_padding:
            self.logger.debug(f"PADDING")
        else:
            if gse_header.is_start:
                self.logger.header(f"START PDU, LTI {gse_header.label_type_indicator}, GSE_LEN {gse_header.gse_length}, FRAG_ID {gse_header.payload.frag_id} PROTOCOL {gse_header.payload.protocol_type}")
            elif gse_header.is_middle:
                self.logger.header(f"MIDDLE PDU, LTI {gse_header.label_type_indicator}, GSE_LEN {gse_header.gse_length}, FRAG_ID {gse_header.payload.frag_id}")
            elif gse_header.is_end:
                self.logger.header(f"END PDU, LTI {gse_header.label_type_indicator}, GSE_LEN {gse_header.gse_length}, FRAG_ID {gse_header.payload.frag_id} CRC {gse_header.payload.crc.hex()}")
            elif gse_header.is_whole:
                self.logger.header(f"WHOLE PDU, LTI {gse_header.label_type_indicator}, GSE_LEN {gse_header.gse_length}, PROTOCOL {gse_header.payload.protocol_type}")
            self.logger.header(f"GSE DATA {gse_header.payload.data.hex()}")

    def done_processing(self):
        super().done_processing()
        # close_file_writer(self.write_fragment_cache)
        # close_file_writer(self.write_split_fragment_cache)
    def log_status(self, logger=None):
        super().log_status(self.logger)
        logger = self.logger if logger is None else logger
        logger.info(f"num_gse_packets: {self.num_gse_packets}")
        logger.info(f"num_whole_pdu: {self.num_whole_pdu}")
        logger.info(f"num_start_pdu: {self.num_start_pdu}")
        logger.info(f"num_middle_pdu: {self.num_middle_pdu}")
        logger.info(f"num_end_pdu: {self.num_end_pdu}")
        logger.info(f"num_padding: {self.num_padding}")
        logger.info(f"protocol_types: {self.protocol_types.most_common()}")
        logger.info(f"is_encrypted: {self.is_encrypted()}")

class StandardGSEParser(GSEParserBase):
    def __init__(self, read_file, protocol='gse', show_pbar=False, log_level=logging.INFO):
        super().__init__(read_file, protocol=protocol, show_pbar=show_pbar, log_level=log_level)

    def process_capture(self, capture):
        stream = KaitaiStream(capture)
        self.logger.debug(stream)
        pbar = tqdm(total=len(capture), desc=f"Processing {self.protocol_file}") if self.show_pbar else None
        self.skips[0] = len(capture)
        
        self.logger.debug(f"capture type: {type(capture)}")
        # self.logger.debug(f"capture {capture.hex()}")
        self.logger.debug(f"stream type: {type(stream)}")

        self.logger.debug(f"{stream.pos()}")

        while stream.pos() < len(capture):
            pos = stream.pos()
            self.logger.debug(f"Trying at position: {pos}")
            try:
                gse_packet = GseStandard(stream)
            except Exception as e:
                self.logger.debug(f"Parse error at {pos}: {e}")
                self.consume_byte(stream, pos, pbar)
            else: 
                gse_packet_bytes = stream._io[pos:stream.pos()]
                self.consume_bytes(len(gse_packet_bytes), pbar)
                self.count(gse_packet)
                self.print_gse_fields(gse_packet)

                if not gse_packet.is_padding:
                    if gse_packet.is_whole:
                        self.write_protocol.write(gse_packet.payload.data)
                    else:
                        self.logger.debug(f"frag_id = {gse_packet.payload.frag_id}")
                        if (frag := self.fragment_cache.update(gse_packet)):
                            self.write_fragment_cache.write(frag)

                try:
                    gse_packet = GseStandardSplit.from_bytes(gse_packet_bytes)
                except Exception as e:
                    self.logger.debug(f"Error recasting to GseStandardSplit: {e}")
                else:
                    if (frag := self.split_fragment_cache.update(gse_packet)):
                        self.write_split_fragment_cache.write(frag)

class HdrlenGSEParser(GSEParserBase):
    def __init__(self, read_file, protocol='gse', show_pbar=False, log_level=logging.INFO):
        super().__init__(read_file, protocol=protocol, show_pbar=show_pbar, log_level=log_level)

    def process_capture(self, capture):
        stream = KaitaiStream(capture)
        pbar = tqdm(total=len(capture), desc=f"Processing {self.protocol_file}") if self.show_pbar else None
        self.skips[0] = len(capture)

        while stream.pos() < len(capture):
            pos = stream.pos()
            self.logger.debug(f"Trying at position: {pos}")
            try:
                gse_packet = GseHdrlen(stream)
            except Exception as e:
                self.logger.debug(f"Parse error at {pos}: {e}")
                try:
                    gse_packet = GseHdrlenUnsafe(stream)
                except Exception as e2:
                    self.logger.debug(f"Unsafe parse error at {pos}: {e2}")
                    self.consume_byte(stream, pos, pbar)
                else:
                    gse_packet_bytes = stream._io[pos:stream.pos()]
                    self.logger.payload(gse_packet_bytes.hex())
                    self.consume_bytes(len(gse_packet_bytes))
                    self.count(gse_packet)
            else:
                gse_packet_bytes = stream._io[pos:stream.pos()]
                self.consume_bytes(len(gse_packet_bytes), pbar)
                self.count(gse_packet)
                self.print_gse_fields(gse_packet)

                if not gse_packet.is_padding:
                    if gse_packet.is_whole:
                        self.write_protocol.write(gse_packet.payload.data)
                    else:
                        if (frag := self.fragment_cache.update(gse_packet)):
                            self.write_fragment_cache.write(frag)

                try:
                    gse_packet = GseHdrlenSplit.from_bytes(gse_packet_bytes)
                except Exception as e:
                    self.logger.debug(f"Error recasting to GseStandardSplit: {e}")
                else:
                    if (frag := self.split_fragment_cache.update(gse_packet)):
                        self.write_split_fragment_cache.write(frag)


class StandardLenSplitCacheGSEParser(GSEParserBase):
    def __init__(self, read_file, protocol='gse', show_pbar=False, log_level=logging.INFO):
        super().__init__(read_file, protocol=protocol, show_pbar=show_pbar, log_level=log_level)

        self.split_fragment_cache_log_file = logs_dir + self.read_file + f".{protocol}.cache.log"
        self.split_fragment_cache_logger = create_file_logger(self.split_fragment_cache_log_file, log_level)
        self.split_fragment_cache = FragmentCache(logger=self.split_fragment_cache_logger)
        self.split_fragment_cache_write_file = write_dir + self.read_file + f".{protocol}.cache"
        self.write_split_fragment_cache = open_file_writer(self.split_fragment_cache_write_file)
    def process_capture(self, capture):
        stream = KaitaiStream(capture)
        self.logger.debug(stream)
        pbar = tqdm(total=len(capture), desc=f"Processing {self.protocol_file}") if self.show_pbar else None
        self.skips[0] = len(capture)
        
        self.logger.debug(f"capture type: {type(capture)}")
        # self.logger.debug(f"capture {capture.hex()}")
        self.logger.debug(f"stream type: {type(stream)}")

        self.logger.debug(f"{stream.pos()}")

        while stream.pos() < len(capture):
            pos = stream.pos()
            self.logger.debug(f"Trying at position: {pos}")
            try:
                gse_packet = GseStandard(stream)
            except Exception as e:
                self.logger.debug(f"Parse error at {pos}: {e}")
                self.consume_byte(stream, pos, pbar)
            else: 
                gse_packet_bytes = stream._io[pos:stream.pos()]
                self.consume_bytes(len(gse_packet_bytes), pbar)
                self.count(gse_packet)
                self.print_gse_fields(gse_packet)

                if not gse_packet.is_padding:
                    if gse_packet.is_whole:
                        self.write_protocol.write(gse_packet.payload.data)
                        self.protocol_types.update([gse_packet.payload.protocol_type])
                    else: 
                        self.bytes_skipped += len(gse_packet.payload.data)
                try:
                    gse_packet = GseStandardSplit.from_bytes(gse_packet_bytes)
                except Exception as e:
                    self.logger.debug(f"Error recasting to GseStandardSplit: {e}")
                else:
                    if (frag := self.split_fragment_cache.update(gse_packet)):
                        self.write_split_fragment_cache.write(frag)
                        self.write_protocol.write(frag)
                        self.bytes_skipped -= len(frag)

    def done_processing(self):
        super().done_processing()
        close_file_writer(self.write_split_fragment_cache)
    def log_status(self, logger=None):
        super().log_status(self.logger)
        self.split_fragment_cache.log_status(self.logger)
        self.split_fragment_cache.log_status()
    pass
class StandardLenStandardCacheGSEParser(GSEParserBase):
    def __init__(self, read_file, protocol='gse', show_pbar=False, log_level=logging.INFO):
        super().__init__(read_file, protocol=protocol, show_pbar=show_pbar, log_level=log_level)

        self.fragment_cache_log_file = logs_dir + self.read_file + f".{protocol}.cache.log"
        self.fragment_cache_logger = create_file_logger(self.fragment_cache_log_file, log_level)
        self.fragment_cache = FragmentCache(logger=self.fragment_cache_logger)
        self.fragment_cache_write_file = write_dir + self.read_file + f".{protocol}.cache"
        self.write_fragment_cache = open_file_writer(self.fragment_cache_write_file)
        
    def process_capture(self, capture):
        stream = KaitaiStream(capture)
        self.logger.debug(stream)
        pbar = tqdm(total=len(capture), desc=f"Processing {self.protocol_file}") if self.show_pbar else None
        self.skips[0] = len(capture)
        
        self.logger.debug(f"capture type: {type(capture)}")
        # self.logger.debug(f"capture {capture.hex()}")
        self.logger.debug(f"stream type: {type(stream)}")

        self.logger.debug(f"{stream.pos()}")

        while stream.pos() < len(capture):
            pos = stream.pos()
            self.logger.debug(f"Trying at position: {pos}")
            try:
                gse_packet = GseStandard(stream)
            except Exception as e:
                self.logger.debug(f"Parse error at {pos}: {e}")
                self.consume_byte(stream, pos, pbar)
            else: 
                gse_packet_bytes = stream._io[pos:stream.pos()]
                self.consume_bytes(len(gse_packet_bytes), pbar)
                self.count(gse_packet)
                self.print_gse_fields(gse_packet)

                if not gse_packet.is_padding:
                    if gse_packet.is_whole:
                        self.write_protocol.write(gse_packet.payload.data)
                        self.protocol_types.update([gse_packet.payload.protocol_type])
                    else: 
                        self.bytes_skipped += len(gse_packet.payload.data)
                        self.logger.debug(f"frag_id = {gse_packet.payload.frag_id}")
                        if (frag := self.fragment_cache.update(gse_packet)):
                            self.write_fragment_cache.write(frag)
                            self.write_protocol.write(frag)
                            self.bytes_skipped -= len(frag)
                            
    def done_processing(self):
        super().done_processing()
        close_file_writer(self.write_fragment_cache)
    def log_status(self, logger=None):
        super().log_status(self.logger)
        self.fragment_cache.log_status(self.logger)
        self.fragment_cache.log_status()
    pass
class Len2SplitCacheGSEParser(GSEParserBase):
    def __init__(self, read_file, protocol='gse', show_pbar=False, log_level=logging.INFO):
        super().__init__(read_file, protocol=protocol, show_pbar=show_pbar, log_level=log_level)

        self.split_fragment_cache_log_file = logs_dir + self.read_file + f".{protocol}.cache.log"
        self.split_fragment_cache_logger = create_file_logger(self.split_fragment_cache_log_file, log_level)
        self.split_fragment_cache = FragmentCache(logger=self.split_fragment_cache_logger)
        self.split_fragment_cache_write_file = write_dir + self.read_file + f".{protocol}.cache"
        self.write_split_fragment_cache = open_file_writer(self.split_fragment_cache_write_file)
        
    def process_capture(self, capture):
        stream = KaitaiStream(capture)
        pbar = tqdm(total=len(capture), desc=f"Processing {self.protocol_file}") if self.show_pbar else None
        self.skips[0] = len(capture)

        while stream.pos() < len(capture):
            pos = stream.pos()
            self.logger.debug(f"Trying at position: {pos}")
            try:
                gse_packet = GseHdrlen(stream)
            except Exception as e:
                self.logger.debug(f"Parse error at {pos}: {e}")
                try:
                    gse_packet = GseHdrlenUnsafe(stream)
                except Exception as e2:
                    self.logger.debug(f"Unsafe parse error at {pos}: {e2}")
                    self.consume_byte(stream, pos, pbar)
                else:
                    gse_packet_bytes = stream._io[pos:stream.pos()]
                    self.logger.payload(gse_packet_bytes.hex())
                    self.consume_bytes(len(gse_packet_bytes))
                    self.count(gse_packet)
            else:
                gse_packet_bytes = stream._io[pos:stream.pos()]
                self.consume_bytes(len(gse_packet_bytes), pbar)
                self.count(gse_packet)
                self.print_gse_fields(gse_packet)

                if not gse_packet.is_padding:
                    if gse_packet.is_whole:
                        self.write_protocol.write(gse_packet.payload.data)
                        self.protocol_types.update([gse_packet.payload.protocol_type])
                    else:
                        self.bytes_skipped += len(gse_packet.payload.data)
                try:
                    gse_packet = GseHdrlenSplit.from_bytes(gse_packet_bytes)
                except Exception as e:
                    self.logger.debug(f"Error recasting to GseStandardSplit: {e}")
                else:
                    if (frag := self.split_fragment_cache.update(gse_packet)):
                        self.write_split_fragment_cache.write(frag)
                        self.write_protocol.write(frag)
                        self.bytes_skipped -= len(frag)

    def done_processing(self):
        super().done_processing()
        close_file_writer(self.write_split_fragment_cache)

    def log_status(self, logger=None):
        super().log_status(self.logger)
        self.split_fragment_cache.log_status(self.logger)
        self.split_fragment_cache.log_status()


class Len2StandardCacheGSEParser(GSEParserBase):
    def __init__(self, read_file, protocol='gse', show_pbar=False, log_level=logging.INFO):
        super().__init__(read_file, protocol=protocol, show_pbar=show_pbar, log_level=log_level)
        
        self.fragment_cache_log_file = logs_dir + self.read_file + f".{protocol}.cache.log"
        self.fragment_cache_logger = create_file_logger(self.fragment_cache_log_file, log_level)
        self.fragment_cache = FragmentCache(logger=self.fragment_cache_logger)
        self.fragment_cache_write_file = write_dir + self.read_file + f".{protocol}.cache"
        self.write_fragment_cache = open_file_writer(self.fragment_cache_write_file)
    def process_capture(self, capture):
        stream = KaitaiStream(capture)
        pbar = tqdm(total=len(capture), desc=f"Processing {self.protocol_file}") if self.show_pbar else None
        self.skips[0] = len(capture)

        while stream.pos() < len(capture):
            pos = stream.pos()
            self.logger.debug(f"Trying at position: {pos}")
            try:
                gse_packet = GseHdrlen(stream)
            except Exception as e:
                self.logger.debug(f"Parse error at {pos}: {e}")
                try:
                    gse_packet = GseHdrlenUnsafe(stream)
                except Exception as e2:
                    self.logger.debug(f"Unsafe parse error at {pos}: {e2}")
                    self.consume_byte(stream, pos, pbar)
                else:
                    gse_packet_bytes = stream._io[pos:stream.pos()]
                    self.logger.payload(gse_packet_bytes.hex())
                    self.consume_bytes(len(gse_packet_bytes))
                    self.count(gse_packet)
            else:
                gse_packet_bytes = stream._io[pos:stream.pos()]
                self.consume_bytes(len(gse_packet_bytes), pbar)
                self.count(gse_packet)
                self.print_gse_fields(gse_packet)

                if not gse_packet.is_padding:
                    if gse_packet.is_whole:
                        self.write_protocol.write(gse_packet.payload.data)
                        self.protocol_types.update([gse_packet.payload.protocol_type])
                    else:
                        self.bytes_skipped += len(gse_packet.payload.data)
                        if (frag := self.fragment_cache.update(gse_packet)):
                            self.write_fragment_cache.write(frag)
                            self.write_protocol.write(frag)
                            self.bytes_skipped -= len(frag)

    def done_processing(self):
        super().done_processing()
        close_file_writer(self.write_fragment_cache)

    def log_status(self, logger=None):
        super().log_status(self.logger)
        self.fragment_cache.log_status(self.logger)
        self.fragment_cache.log_status()


def main():
    parser = argparse.ArgumentParser(description="Process GSE capture files with custom logging verbosity.")
    parser.add_argument("capture_file", help="Path to the input raw capture file.")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase logging verbosity. Default: INFO. -v: HEADER. -vv: DEBUG. -vvv: PAYLOAD (most verbose).")
    
    args = parser.parse_args()

    log_level = get_log_level_from_verbosity(args.verbose)
    ensure_directories_exist(logs_dir, write_dir, plot_dir)

    capture_file = args.capture_file
    STDLEN_SPLITCACHE_GSE = StandardLenSplitCacheGSEParser(capture_file, protocol='stdlen.split.gse', log_level=log_level)
    STDLEN_STDCACHE_GSE = StandardLenStandardCacheGSEParser(capture_file, protocol='stdlen.std.gse', log_level=log_level)
    LEN2_SPLITCACHE_GSE = Len2SplitCacheGSEParser(capture_file, protocol='len2.split.gse', log_level=log_level)
    LEN2_STDCACHE_GSE = Len2StandardCacheGSEParser(capture_file, protocol='len2.std.gse', log_level=log_level)
    
    
    STDLEN_SPLITCACHE_GSE.process_capture_file(capture_file, PREVIEW_LENGTH)
    STDLEN_SPLITCACHE_GSE.log_status()
    STDLEN_SPLITCACHE_GSE.done_processing()
    STDLEN_STDCACHE_GSE.process_capture_file(capture_file, PREVIEW_LENGTH)
    STDLEN_STDCACHE_GSE.log_status()
    STDLEN_STDCACHE_GSE.done_processing()
    LEN2_SPLITCACHE_GSE.process_capture_file(capture_file, PREVIEW_LENGTH)
    LEN2_SPLITCACHE_GSE.log_status()
    LEN2_SPLITCACHE_GSE.done_processing()
    LEN2_STDCACHE_GSE.process_capture_file(capture_file, PREVIEW_LENGTH)
    LEN2_STDCACHE_GSE.log_status()
    LEN2_STDCACHE_GSE.done_processing()
    
    
    if STDLEN_SPLITCACHE_GSE.bytes_skipped > LEN2_SPLITCACHE_GSE.bytes_skipped:
        # print("hdrlen-2")
        if LEN2_SPLITCACHE_GSE.split_fragment_cache.num_reassembled > LEN2_STDCACHE_GSE.fragment_cache.num_reassembled:
            print("hdrlen-2 and 6/2 frag_id/counter gse")
            os.system(f"mv '{LEN2_SPLITCACHE_GSE.protocol_file}' {promising_dir}")
        else: 
            print("hdrlen-2 and standard frag_id gse")
            os.system(f"mv '{LEN2_STDCACHE_GSE.protocol_file}' {promising_dir}")
    else: 
        # print("standard length")
        if STDLEN_SPLITCACHE_GSE.split_fragment_cache.num_reassembled > LEN2_STDCACHE_GSE.fragment_cache.num_reassembled:
            print("standard length and 6/2 frag_id/counter gse")
            os.system(f"mv '{STDLEN_SPLITCACHE_GSE.protocol_file}' {promising_dir}")
        else:
            print("standard length and standard frag_id gse")
            os.system(f"mv '{STDLEN_STDCACHE_GSE.protocol_file}' {promising_dir}")
            
    logging.shutdown() # Ensures all log handlers are properly flushed and closed

if __name__ == "__main__":
    main()
    
    
    
