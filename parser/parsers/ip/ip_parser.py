import logging
import os
import argparse
from tqdm import tqdm 
import struct
import socket

from parser.config import plot_dir, write_dir, logs_dir
from parser.config import IP_HEADER_MIN_SIZE, PREVIEW_LENGTH
from parser.utils.parser_utils import get_log_level_from_verbosity, ensure_directories_exist
from parser.utils.parser_utils import ParserBase
from parser.utils.parser_utils import write_ip_packet_to_pcap, create_pcap_handler, close_pcap_handler

from ipv4_packet import Ipv4Packet
from kaitaistruct import KaitaiStream

class IPv4Parser(ParserBase):
    def __init__(self, read_file, show_pbar=False, log_level=logging.INFO):
        super().__init__(read_file, protocol='ip', show_pbar=show_pbar, log_level=log_level)
        # add custom variables here
        self.pcap_file = write_dir + self.read_file + ".ip.pcap"
        self.pcap_file_writer, self.pcap_writer = create_pcap_handler(self.pcap_file)
        self.num_ip_packets = 0
        pass
    def is_ipv4(self, byte_window):
        try:
            ipv4_packet = Ipv4Packet.from_bytes(byte_window)
        except Exception as e:
            # self.logger.error(f"Error parsing IPv4: {e}", exc_info=True)
            pass
        else:
            return ipv4_packet
    @staticmethod
    def ipv4_checksum(header: bytes) -> int:
        """Calculate the checksum of an IPv4 header."""
        if len(header) % 2 == 1:
            header += b'\x00'
        total = sum(struct.unpack("!%dH" % (len(header) // 2), header))
        while total > 0xFFFF:
            total = (total & 0xFFFF) + (total >> 16)
        return ~total & 0xFFFF
    @staticmethod
    def is_valid_ipv4_checksum(packet: bytes) -> bool:
        """
        Validate the checksum of an IPv4 header in a raw packet.
        
        Returns True if the checksum is correct, False otherwise.
        """
        if len(packet) < 20:
            return False  # Too short for a valid IPv4 header

        version_ihl = packet[0]
        ihl = version_ihl & 0x0F  # IHL in 32-bit words
        header_length = ihl * 4

        if len(packet) < header_length:
            return False  # Not enough bytes for full header

        header = bytearray(packet[:header_length])
        original_checksum = struct.unpack("!H", header[10:12])[0]
        header[10:12] = b'\x00\x00'  # Zero out checksum field before calculation

        computed_checksum = IPv4Parser.ipv4_checksum(header)
        assert computed_checksum == original_checksum
    def process_capture(self, capture):
        stream = KaitaiStream(capture)
        total_len = len(capture)
        end_last_valid_packet = 0
        self.bytes_skipped = 0
        pbar = tqdm(total=len(capture), desc=f"Processing {self.protocol_file}") if self.show_pbar else None
        self.skips[0] = len(capture)
        while stream.pos() < total_len:
            pos = stream.pos()
            
            def advance():
                stream.seek(pos + 1)
                self.bytes_skipped += 1
                self.bytes_searched += 1
                if self.show_pbar: pbar.update(1)
            self.logger.debug(f"Trying at position: {pos}")
            
            version = capture[pos] >> 4
            if version != 4:
                advance()
                continue
            try:
                ip_packet = Ipv4Packet(stream)
            except Exception as e:
                self.logger.debug(f"Parse error at {pos}: {e}")
                advance()
            else: 
                self.logger.debug(f"Candidate Ipv4Packet at {pos}")
                
                ip_packet_bytes = stream._io[pos:stream.pos()]
                try:
                    IPv4Parser.is_valid_ipv4_checksum(ip_packet_bytes)
                except (AssertionError, ValueError, struct.error) as e:
                    self.logger.debug(f"Invalid checksum at {pos}: {e}")
                    advance()
                else: 
                    self.logger.header(f"IP {ip_packet_bytes.hex()}")
                    # print(ip_packet.body)
                    # self.write_protocol.write(ip_packet.body)
                    self.write_protocol.write(ip_packet_bytes)
                    write_ip_packet_to_pcap(self.pcap_file_writer, self.pcap_writer, ip_packet_bytes)
                    self.skips[end_last_valid_packet] = pos
                    stream.seek(pos + len(ip_packet_bytes))

                    self.bytes_searched += len(ip_packet_bytes)
                    if self.show_pbar: pbar.update(len(ip_packet_bytes))
                    self.write_skips.write(stream._io[end_last_valid_packet:pos])
                    self.logger.warning(stream._io[end_last_valid_packet:pos].hex())
                    end_last_valid_packet = pos+len(ip_packet_bytes)
    def process_capture_file(self, capture_file, preview_len=None):
        super().process_capture_file(capture_file, preview_len)
    def done_processing(self):
        super().done_processing()
        close_pcap_handler(self.pcap_file_writer)
    def log_status(self, logger=None):
        super().log_status(self.logger)    
        logger = self.logger if logger == None else logger
        # IPv4 log custom performance metrics here


def main():
    parser = argparse.ArgumentParser(description="Process IPv4 capture files with custom logging verbosity.")
    parser.add_argument("capture_file", help="Path to the input raw capture file.")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase logging verbosity. Default: INFO. -v: HEADER. -vv: DEBUG. -vvv: PAYLOAD (most verbose).")
    
    args = parser.parse_args()

    log_level = get_log_level_from_verbosity(args.verbose)
    ensure_directories_exist(logs_dir, write_dir, plot_dir)

    capture_file = args.capture_file
    
    IPv4 = IPv4Parser(capture_file, log_level=log_level, show_pbar=True)
    IPv4.process_capture_file(capture_file)
    IPv4.log_status()
    IPv4.done_processing()
    IPv4.plot_skips()

    logging.shutdown() # Ensures all log handlers are properly flushed and closed

if __name__ == "__main__":
    main()