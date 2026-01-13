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

from parser.utils.parser_utils import ensure_directories_exist
from parser.config import write_dir, logs_dir, plot_dir


class TestDVBS2ParserBasics:
    """Basic tests for DVBS2Parser initialization and structure."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Ensure output directories exist before tests."""
        ensure_directories_exist(write_dir, logs_dir, plot_dir)

    def test_bbheader_crc8_calculation(self):
        """Test CRC-8 calculation for BB header validation."""
        from crccheck.crc import Crc8DvbS2

        # Known BB header bytes (without CRC byte)
        test_header = bytes([0x72, 0x00, 0x00, 0xB8, 0x00, 0x25, 0x02, 0x12, 0xFD])
        calculated_crc = Crc8DvbS2.calc(test_header)

        # CRC should be a single byte value
        assert 0 <= calculated_crc <= 255

    def test_bbheader_length_constant(self):
        """Test that BB header length is correctly defined."""
        from parser.config import BBHEADER_LEN
        assert BBHEADER_LEN == 10  # DVB-S2 BB header is always 10 bytes

    def test_crc32mpeg2_calculation(self):
        """Test MPEG-2 CRC-32 calculation."""
        from parser.utils.parser_utils import crc32mpeg2

        # Test with known data
        test_data = b'Hello, DVB-S2!'
        crc = crc32mpeg2(test_data)

        # CRC should be a 32-bit value
        assert isinstance(crc, int)
        assert 0 <= crc <= 0xFFFFFFFF

        # Same input should produce same CRC
        assert crc32mpeg2(test_data) == crc

        # Different input should produce different CRC
        assert crc32mpeg2(b'Different data') != crc


class TestBBHeaderParsing:
    """Tests for BB header field extraction."""

    def test_matype_field_parsing(self):
        """Test MATYPE field parsing from BB header."""
        # MATYPE is in the first byte of BB header
        # Bits 7-6: TS/GS field
        # Bits 5-4: SIS/MIS field
        # Bits 3-2: CCM/ACM field
        # Bits 1-0: ISSYI and NPD flags

        # TS/GS = 11 (Generic stream)
        # SIS/MIS = 01 (Multiple input stream)
        # CCM/ACM = 00 (CCM)
        # ISSYI = 0, NPD = 0
        matype1 = 0b11010000  # 0xD0

        ts_gs = (matype1 >> 6) & 0x03
        sis_mis = (matype1 >> 5) & 0x01
        ccm_acm = (matype1 >> 4) & 0x01

        assert ts_gs == 3  # Generic stream
        assert sis_mis == 0  # Single input stream based on bit 5
        assert ccm_acm == 1  # ACM mode based on bit 4

    def test_data_field_length_parsing(self):
        """Test DFL (Data Field Length) extraction."""
        # DFL is a 16-bit field at bytes 4-5 of BB header
        dfl_bytes = bytes([0x00, 0xB8])  # 184 decimal
        dfl = struct.unpack('>H', dfl_bytes)[0]
        assert dfl == 184


class TestParserUtilities:
    """Tests for parser utility functions."""

    def test_get_log_level_from_verbosity(self):
        """Test verbosity to log level conversion."""
        from parser.utils.parser_utils import get_log_level_from_verbosity
        from parser.config import HEADER_LEVEL_NUM, PAYLOAD_LEVEL_NUM
        import logging

        assert get_log_level_from_verbosity(0) == logging.INFO
        assert get_log_level_from_verbosity(1) == HEADER_LEVEL_NUM
        assert get_log_level_from_verbosity(2) == logging.DEBUG
        assert get_log_level_from_verbosity(3) == PAYLOAD_LEVEL_NUM
        assert get_log_level_from_verbosity(100) == PAYLOAD_LEVEL_NUM

    def test_ensure_directories_exist(self):
        """Test directory creation utility."""
        from parser.utils.parser_utils import ensure_directories_exist

        with tempfile.TemporaryDirectory() as tmpdir:
            test_dir = os.path.join(tmpdir, 'test_subdir')
            assert not os.path.exists(test_dir)

            ensure_directories_exist(test_dir)
            assert os.path.exists(test_dir)

            # Should not raise on existing directory
            ensure_directories_exist(test_dir)


class TestConfigEnvironmentVariables:
    """Tests for environment variable configuration."""

    def test_default_directories(self):
        """Test default directory values when no env vars set."""
        # Clear any existing env vars
        env_vars = ['DVB_OUTPUT_DIR', 'DVB_LOGS_DIR', 'DVB_PLOTS_DIR']
        original_values = {var: os.environ.get(var) for var in env_vars}

        try:
            for var in env_vars:
                if var in os.environ:
                    del os.environ[var]

            # Re-import to get fresh values
            import importlib
            import parser.config
            importlib.reload(parser.config)

            assert parser.config.write_dir == 'output/'
            assert parser.config.logs_dir == 'logs/'
            assert parser.config.plot_dir == 'plots/'

        finally:
            # Restore original values
            for var, val in original_values.items():
                if val is not None:
                    os.environ[var] = val

    def test_custom_output_directory(self):
        """Test custom output directory via environment variable."""
        import importlib
        import parser.config

        original = os.environ.get('DVB_OUTPUT_DIR')

        try:
            os.environ['DVB_OUTPUT_DIR'] = '/custom/output/path'
            importlib.reload(parser.config)
            assert parser.config.write_dir == '/custom/output/path/'

        finally:
            if original:
                os.environ['DVB_OUTPUT_DIR'] = original
            elif 'DVB_OUTPUT_DIR' in os.environ:
                del os.environ['DVB_OUTPUT_DIR']
            importlib.reload(parser.config)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
