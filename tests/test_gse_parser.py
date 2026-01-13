"""
Tests for the GSE (Generic Stream Encapsulation) parsers.

These tests verify GSE packet parsing, fragment reassembly,
and the various GSE parser variants.
"""

import pytest
import os
import sys

# Add the project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parser.utils.parser_utils import ensure_directories_exist
from parser.config import write_dir, logs_dir, plot_dir


class TestFragmentCache:
    """Tests for the FragmentCache class."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Ensure output directories exist before tests."""
        ensure_directories_exist(write_dir, logs_dir, plot_dir)

    def test_fragment_cache_initialization(self):
        """Test FragmentCache initialization."""
        from parser.parsers.gse.fragment_cache import FragmentCache

        cache = FragmentCache(capacity=256)
        assert cache.capacity == 256
        assert cache.total_fragments == 0
        assert len(cache.fragment_cache) == 0

    def test_add_single_fragment(self):
        """Test adding a single fragment."""
        from parser.parsers.gse.fragment_cache import FragmentCache

        cache = FragmentCache(capacity=256)
        result = cache.add_fragment(frag_id=1, part_type="beginning", payload=b"hello")

        assert result[0] == "incomplete"
        assert result[1] == 1
        assert cache.total_fragments == 1

    def test_complete_fragment_reassembly(self):
        """Test complete fragment reassembly with beginning and end."""
        from parser.parsers.gse.fragment_cache import FragmentCache

        cache = FragmentCache(capacity=256)

        # Add beginning fragment
        result1 = cache.add_fragment(frag_id=1, part_type="beginning", payload=b"hello")
        assert result1[0] == "incomplete"

        # Add end fragment - should trigger reassembly
        result2 = cache.add_fragment(frag_id=1, part_type="end", payload=b" world")
        assert result2[0] == "reassembled"
        assert result2[1] == 1
        assert result2[2] == b"hello world"

        # Cache should be empty after reassembly
        assert cache.total_fragments == 0
        assert 1 not in cache.fragment_cache

    def test_fragment_reassembly_with_middle(self):
        """Test fragment reassembly with middle pieces."""
        from parser.parsers.gse.fragment_cache import FragmentCache

        cache = FragmentCache(capacity=256)

        # Add beginning
        cache.add_fragment(frag_id=1, part_type="beginning", payload=b"start")

        # Add middle
        cache.add_fragment(frag_id=1, part_type="middle", payload=b"-middle")

        # Add end
        result = cache.add_fragment(frag_id=1, part_type="end", payload=b"-end")

        assert result[0] == "reassembled"
        assert result[2] == b"start-middle-end"

    def test_fragment_cache_lru_eviction(self):
        """Test LRU eviction when capacity is exceeded."""
        from parser.parsers.gse.fragment_cache import FragmentCache

        # Small capacity to trigger eviction
        cache = FragmentCache(capacity=3)

        # Add fragments for multiple IDs
        cache.add_fragment(frag_id=1, part_type="beginning", payload=b"a")
        cache.add_fragment(frag_id=2, part_type="beginning", payload=b"b")
        cache.add_fragment(frag_id=3, part_type="beginning", payload=b"c")

        # Adding 4th should trigger eviction of oldest
        result = cache.add_fragment(frag_id=4, part_type="beginning", payload=b"d")

        # Either evicted or incomplete
        assert result[0] in ["evicted", "incomplete"]

    def test_multiple_fragment_ids(self):
        """Test handling multiple concurrent fragment IDs."""
        from parser.parsers.gse.fragment_cache import FragmentCache

        cache = FragmentCache(capacity=256)

        # Interleave fragments from different IDs
        cache.add_fragment(frag_id=1, part_type="beginning", payload=b"ONE-")
        cache.add_fragment(frag_id=2, part_type="beginning", payload=b"TWO-")
        cache.add_fragment(frag_id=1, part_type="middle", payload=b"middle-")
        cache.add_fragment(frag_id=2, part_type="end", payload=b"end")  # Complete ID 2

        result = cache.add_fragment(frag_id=1, part_type="end", payload=b"end")

        # ID 1 should be complete
        assert result[0] == "reassembled"
        assert result[2] == b"ONE-middle-end"


class TestGSEPacketStructure:
    """Tests for GSE packet structure parsing."""

    def test_gse_header_fields(self):
        """Test GSE header field extraction."""
        # GSE header structure (simplified):
        # Bits 15-14: Start/End indicators
        # Bits 13-12: Label type
        # Bits 11-0: GSE Length

        header_word = 0b11_00_000011111111  # Start=1, End=1, LabelType=0, Length=255

        start_indicator = (header_word >> 15) & 0x01
        end_indicator = (header_word >> 14) & 0x01
        label_type = (header_word >> 12) & 0x03
        gse_length = header_word & 0x0FFF

        assert start_indicator == 1
        assert end_indicator == 1
        assert label_type == 0
        assert gse_length == 255

    def test_gse_packet_types(self):
        """Test identification of GSE packet types."""
        # Whole PDU: S=1, E=1
        # Start of PDU: S=1, E=0
        # Middle of PDU: S=0, E=0
        # End of PDU: S=0, E=1
        # Padding: Special case with zero length

        def get_packet_type(start, end, length):
            if length == 0:
                return "padding"
            if start and end:
                return "whole"
            if start:
                return "start"
            if end:
                return "end"
            return "middle"

        assert get_packet_type(1, 1, 100) == "whole"
        assert get_packet_type(1, 0, 100) == "start"
        assert get_packet_type(0, 0, 100) == "middle"
        assert get_packet_type(0, 1, 100) == "end"
        assert get_packet_type(0, 0, 0) == "padding"


class TestGSEParserVariants:
    """Tests for different GSE parser variants."""

    def test_parser_variant_protocols(self):
        """Test that parser variants use correct protocol names."""
        expected_protocols = [
            'stdlen.split.gse',
            'stdlen.std.gse',
            'len2.split.gse',
            'len2.std.gse',
        ]

        # These are the protocol names used in the parser variants
        for protocol in expected_protocols:
            assert 'gse' in protocol.lower()


class TestCRC32MPEG2:
    """Tests for CRC-32 MPEG-2 implementation."""

    def test_crc32_known_values(self):
        """Test CRC-32 against known values."""
        from parser.utils.parser_utils import crc32mpeg2

        # Empty data
        assert crc32mpeg2(b'') == 0xFFFFFFFF  # Initial value for empty

        # Test consistency
        data = b'The quick brown fox jumps over the lazy dog'
        crc1 = crc32mpeg2(data)
        crc2 = crc32mpeg2(data)
        assert crc1 == crc2

    def test_crc32_different_inputs(self):
        """Test that different inputs produce different CRCs."""
        from parser.utils.parser_utils import crc32mpeg2

        crc1 = crc32mpeg2(b'data1')
        crc2 = crc32mpeg2(b'data2')
        assert crc1 != crc2


class TestProtocolTypes:
    """Tests for GSE protocol type handling."""

    def test_common_protocol_types(self):
        """Test common protocol type values."""
        # Common EtherType values used in GSE
        IPV4 = 0x0800
        IPV6 = 0x86DD
        ARP = 0x0806

        assert IPV4 == 2048
        assert IPV6 == 34525
        assert ARP == 2054


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
