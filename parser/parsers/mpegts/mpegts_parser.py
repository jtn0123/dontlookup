import logging
import os
import mmap
import sys
import argparse
from tqdm import tqdm

from parser.config import plot_dir, write_dir, logs_dir
from parser.config import MPEG_TS_SYNC_BYTE, MPEG_FRAME_SIZE
from parser.utils.parser_utils import get_log_level_from_verbosity, ensure_directories_exist

from parser.utils.parser_utils import crc32mpeg2, create_file_logger, open_file_writer, close_file_writer
from parser.utils.parser_utils import write_ip_packet_to_pcap, create_pcap_handler, close_pcap_handler
from parser.utils.parser_utils import ParserBase

from mp2t import Mp2t

class MpegtsParser(ParserBase):
    def __init__(self, read_file, show_pbar=False, log_level=logging.INFO, write_pid_streams=False):
        super().__init__(read_file, protocol='mpegts', show_pbar=show_pbar, log_level=log_level)
        # add custom variables here
        self.num_transport_packet_headers = 0
        self.num_transport_packets = 0
        
        self.write_pid_streams = write_pid_streams
        self.pid_streams = {}
        pass
    def is_mpeg_ts(self, byte_window):
        try:
            mpeg_ts_frame = Mp2t.from_bytes(byte_window)
        except Exception as e:
            return None
        else:
            return mpeg_ts_frame

    def process_capture(self, capture):
        pbar = tqdm(total=len(capture), desc=f"Processing {self.protocol_file}") if self.show_pbar else None

        i = 0
        num_skipped_bytes = 0
        capture_len = len(capture)

        while i <= capture_len - MPEG_FRAME_SIZE:
            byte_window = capture[i:i+MPEG_FRAME_SIZE]
            if (mpeg_ts_frame := self.is_mpeg_ts(byte_window)):
                
                self.num_transport_packet_headers += 1
                SKIPPED_BYTES = capture[i - num_skipped_bytes:i]
                
                if num_skipped_bytes > 0:
                    self.write_skips.write(SKIPPED_BYTES)
                    self.skips[i - num_skipped_bytes] = i
                    self.logger.debug(f"SKIPPED BYTES: {SKIPPED_BYTES.hex()}")

                pid = mpeg_ts_frame.transport_packet.pid
                cc = mpeg_ts_frame.transport_packet.continuity_counter
                self.logger.header(f"PID {pid}, CC {cc}")
                self.logger.payload(mpeg_ts_frame.transport_packet.payload.hex())
                self.logger.payload(mpeg_ts_frame.transport_packet.payload)
                
                
                if self.write_pid_streams:
                    if pid in self.pid_streams:
                        self.pid_streams[pid].write(mpeg_ts_frame.transport_packet.payload) 
                    else:
                        self.pid_streams[pid] = open_file_writer(write_dir + self.read_file + f".mpegts_pid={pid}")
                # self.logger.debug(byte_window.hex())
                

                self.write_protocol.write(byte_window)

                num_skipped_bytes = 0

                if i + MPEG_FRAME_SIZE > capture_len:
                    break    
                else:
                    i += MPEG_FRAME_SIZE
                    self.num_transport_packets += 1
                    self.bytes_searched += MPEG_FRAME_SIZE
                    if pbar: pbar.update(MPEG_FRAME_SIZE)

            else:
                i += 1
                num_skipped_bytes += 1
                self.bytes_skipped += 1
                self.bytes_searched += 1
                if pbar: pbar.update(1)
                
        CUTOFF = capture[i:]
        CUTOFF_LEN = len(CUTOFF)
        num_skipped_bytes += CUTOFF_LEN
        self.bytes_skipped += CUTOFF_LEN
        self.bytes_searched += CUTOFF_LEN
        if pbar: pbar.update(CUTOFF_LEN)
        if pbar: pbar.close()
        self.logger.info(f"SKIPPED {CUTOFF_LEN} bytes at the end of the capture")
        self.logger.debug(f"SKIPPED BYTES: {CUTOFF.hex()}")
        self.skips[i] = len(capture)

    def process_capture_file(self, capture_file, preview_len=None):
        super().process_capture_file(capture_file, preview_len)
    def done_processing(self):
        super().done_processing()
        if self.write_pid_streams:
            for pid in self.pid_streams:
                close_file_writer(self.pid_streams[pid])
    def plot_skips(self):
        super().plot_skips()
    def log_status(self, logger=None):
        super().log_status(logger)  
        logger = self.logger if logger == None else logger
        logger.info(f"{self.num_transport_packets} TRANSPORT PACKETS were found")
  
        logger.debug(f"num_transport_packet_headers {self.num_transport_packet_headers}")
        logger.debug(f"num_transport_packets {self.num_transport_packets}")


def main():
    parser = argparse.ArgumentParser(description="Process TODO capture files with custom logging verbosity.")
    parser.add_argument("capture_file", help="Path to the input raw capture file.")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase logging verbosity. Default: INFO. -v: HEADER. -vv: DEBUG. -vvv: PAYLOAD (most verbose).")
    
    args = parser.parse_args()

    log_level = get_log_level_from_verbosity(args.verbose)
    ensure_directories_exist(logs_dir, write_dir, plot_dir)

    capture_file = args.capture_file

    mpegts = MpegtsParser(capture_file, show_pbar=True, log_level=log_level)
    mpegts.process_capture_file(capture_file)
    mpegts.log_status()
    mpegts.done_processing()
    # mpegts.plot_skips()

    logging.shutdown() # Ensures all log handlers are properly flushed and closed

if __name__ == "__main__":
    main()

