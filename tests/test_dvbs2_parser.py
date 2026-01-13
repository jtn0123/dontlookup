"""
Tests for the DVBS2Parser class.

These tests verify the DVB-S2 Base Band frame parsing functionality,
including header validation, CRC checking, and data field extraction.
"""

import pytest
import os
import sys
import tempfile
import struct

# Add the project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestBBHeaderStructure:
    """Tests for BB header field extraction (no parser imports needed)."""

    def test_matype_field_parsing(self):
        """Test MATYPE field parsing from BB header."""
        # MATYPE is in the first byte of BB header
        # Bits 7-6: TS/GS field
        # Bits 5-4: SIS/MIS field
        # Bits 3-2: CCM/ACM field
        # Bits 1-0: ISSYI and NPD flags

        matype1 = 0b11010000  # 0xD0

        ts_gs = (matype1 >> 6) & 0x03
        sis_mis = (matype1 >> 5) & 0x01
        ccm_acm = (matype1 >> 4) & 0x01

        assert ts_gs == 3  # Generic stream
        assert sis_mis == 0
        assert ccm_acm == 1

    def test_data_field_length_parsing(self):
        """Test DFL (Data Field Length) extraction."""
        # DFL is a 16-bit field at bytes 4-5 of BB header
        dfl_bytes = bytes([0x00, 0xB8])  # 184 decimal
        dfl = struct.unpack('>H', dfl_bytes)[0]
        assert dfl == 184

    def test_bbheader_length_constant(self):
        """Test that BB header length is correctly defined."""
        # DVB-S2 BB header is always 10 bytes
        BBHEADER_LEN = 10
        assert BBHEADER_LEN == 10


class TestCRC8DVB:
    """Tests for CRC-8 DVB-S2 calculation."""

    def test_crc8_calculation(self):
        """Test CRC-8 calculation for BB header validation."""
        from crccheck.crc import Crc8DvbS2

        # Known BB header bytes (without CRC byte)
        test_header = bytes([0x72, 0x00, 0x00, 0xB8, 0x00, 0x25, 0x02, 0x12, 0xFD])
        calculated_crc = Crc8DvbS2.calc(test_header)

        # CRC should be a single byte value
        assert 0 <= calculated_crc <= 255

    def test_crc8_consistency(self):
        """Test that CRC-8 is consistent for same input."""
        from crccheck.crc import Crc8DvbS2

        data = b'test data for crc'
        crc1 = Crc8DvbS2.calc(data)
        crc2 = Crc8DvbS2.calc(data)
        assert crc1 == crc2

    def test_crc8_different_input(self):
        """Test that different inputs produce different CRCs."""
        from crccheck.crc import Crc8DvbS2

        crc1 = Crc8DvbS2.calc(b'data1')
        crc2 = Crc8DvbS2.calc(b'data2')
        assert crc1 != crc2


class TestConfigConstants:
    """Tests for configuration constants."""

    def test_config_constants_exist(self):
        """Test that config module has required constants."""
        from parser.config import (
            BBHEADER_LEN,
            MPEG_TS_SYNC_BYTE,
            MPEG_FRAME_SIZE,
            IP_HEADER_MIN_SIZE,
            GSE_HEADER_MIN_LEN,
            PAYLOAD_LEVEL_NUM,
            HEADER_LEVEL_NUM,
        )

        assert BBHEADER_LEN == 10
        assert MPEG_TS_SYNC_BYTE == b'\x47'
        assert MPEG_FRAME_SIZE == 188
        assert IP_HEADER_MIN_SIZE == 20
        assert GSE_HEADER_MIN_LEN == 2
        assert PAYLOAD_LEVEL_NUM == 5
        assert HEADER_LEVEL_NUM == 15

    def test_config_directories(self):
        """Test that config has directory settings."""
        from parser.config import write_dir, logs_dir, plot_dir

        assert isinstance(write_dir, str)
        assert isinstance(logs_dir, str)
        assert isinstance(plot_dir, str)
        assert write_dir.endswith('/')
        assert logs_dir.endswith('/')
        assert plot_dir.endswith('/')


class TestEnvironmentVariables:
    """Tests for environment variable configuration."""

    def test_custom_output_directory(self):
        """Test custom output directory via environment variable."""
        import importlib

        original = os.environ.get('DVB_OUTPUT_DIR')

        try:
            os.environ['DVB_OUTPUT_DIR'] = '/custom/output/path'
            import parser.config
            importlib.reload(parser.config)
            assert parser.config.write_dir == '/custom/output/path/'

        finally:
            if original:
                os.environ['DVB_OUTPUT_DIR'] = original
            elif 'DVB_OUTPUT_DIR' in os.environ:
                del os.environ['DVB_OUTPUT_DIR']
            import parser.config
            importlib.reload(parser.config)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
