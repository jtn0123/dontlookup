# Don't Look Up - Architecture Documentation

## Overview

Don't Look Up is a DVB-S2(X) IP packet encapsulation parser designed to extract IP packets from raw satellite captures. The tool supports multiple encapsulation standards and proprietary variants.

## Directory Structure

```
dontlookup/
├── dontlookup.py          # Main entry point and CLI
├── parser/
│   ├── config.py          # Configuration and constants
│   ├── exceptions.py      # Custom exception hierarchy
│   ├── registry.py        # Parser registry pattern
│   ├── utils/
│   │   ├── parser_utils.py    # Base classes and utilities
│   │   └── pcaplib.py         # PCAP file writing
│   └── parsers/
│       ├── dvbs2/         # DVB-S2 Base Band parser
│       ├── gse/           # Generic Stream Encapsulation parsers
│       ├── ip/            # IPv4 packet parser
│       ├── mpegts/        # MPEG-TS transport stream parsers
│       ├── rev/           # Byte reversal parser
│       └── ...            # Additional protocol parsers
├── tests/                 # Test suite
└── output/                # Parsed output files (generated)
```

## Core Concepts

### Parser Chain Architecture

The system uses a chain of parsers where each parser:
1. Receives raw or partially processed data
2. Extracts protocol-specific information
3. Passes extracted payloads to downstream parsers

```
Raw Capture → DVBS2Parser → GSEParser → IPv4Parser → PCAP Output
                    ↓            ↓           ↓
              BBFrames       PDUs      IP Packets
```

### Parser Base Class

All parsers inherit from `ParserBase` which provides:

- **File I/O**: Memory-mapped file reading, output file writing
- **Logging**: Per-parser log files with configurable verbosity
- **Statistics**: Byte counting, compliance calculation
- **Parser Chaining**: `add_parser()` for downstream processing

```python
class MyParser(ParserBase):
    def __init__(self, read_file, log_level=logging.INFO):
        super().__init__(read_file, protocol='myproto', log_level=log_level)

    def process_capture(self, capture):
        # Parse capture data
        # Write extracted data to self.write_protocol
        # Pass to downstream parsers
        for parser in self.parsers:
            parser.process_capture(extracted_data)
```

### Fragment Reassembly

GSE packets can be fragmented across multiple Base Band frames. The `FragmentCache` class handles:

- **Fragment Identification**: Tracks fragments by ID
- **Reassembly**: Combines beginning/middle/end fragments
- **LRU Eviction**: Prevents memory exhaustion

```python
cache = FragmentCache(capacity=256)
result = cache.add_fragment(frag_id, part_type, payload)
# result: ("reassembled", frag_id, complete_data)
#     or: ("incomplete", frag_id, None)
#     or: ("evicted", old_frag_id, None)
```

## Parser Variants

### DVB-S2 Parser
Extracts Base Band frames from raw captures:
- CRC-8 header validation
- Data field length extraction
- Modulation/coding identification

### GSE Parser Variants
Four variants for different header formats:

| Variant | Header Length | Fragment ID |
|---------|--------------|-------------|
| StandardLenSplitCache | 12-bit | Split 6/2-bit |
| StandardLenStandardCache | 12-bit | Standard 8-bit |
| Len2SplitCache | 2-byte | Split 6/2-bit |
| Len2StandardCache | 2-byte | Standard 8-bit |

### MPEG-TS Parsers
Three variants for transport stream extraction:
- **Standard**: Direct MPEG-TS parsing
- **GenericCRC**: With CRC-8 DVB-S2 validation
- **NewtecCRC**: Newtec-specific CRC handling

## Data Flow

### Input Processing
1. Memory-map input file for efficient access
2. Scan for protocol sync patterns
3. Validate headers (CRC, length fields)
4. Extract payloads

### Output Generation
- **Protocol files**: `output/<filename>.<protocol>`
- **Skip files**: `output/<filename>.not_<protocol>`
- **PCAP files**: `output/<filename>.pcap`
- **Log files**: `logs/<filename>.<protocol>.log`

## Configuration

### Environment Variables
```bash
DVB_OUTPUT_DIR=/path/to/output    # Output directory
DVB_LOGS_DIR=/path/to/logs        # Log directory
DVB_PLOTS_DIR=/path/to/plots      # Plot directory
```

### Logging Levels
- `INFO` (20): Standard operation info
- `HEADER` (15): Protocol header details
- `DEBUG` (10): Detailed debugging
- `PAYLOAD` (5): Full payload dumps

Use `-v` flags to increase verbosity:
```bash
python dontlookup.py capture.ts          # INFO
python dontlookup.py capture.ts -v       # HEADER
python dontlookup.py capture.ts -vv      # DEBUG
python dontlookup.py capture.ts -vvv     # PAYLOAD
```

## Exception Hierarchy

```
ParserError (base)
├── InvalidFormatError      # Malformed data
├── ChecksumError           # CRC/checksum failures
├── FragmentReassemblyError
│   ├── FragmentCollisionError
│   └── IncompleteFragmentError
├── CaptureFileError        # File I/O errors
├── UnsupportedProtocolError
└── ParserChainError        # Chain configuration errors
```

## Adding New Parsers

1. Create parser directory in `parser/parsers/<protocol>/`
2. Create `__init__.py` with sys.path setup (for Kaitai imports)
3. Create parser class inheriting from `ParserBase`
4. Implement `process_capture()` method
5. Add to `dontlookup.py` parser dispatch table

```python
class NewProtocolParser(ParserBase):
    def __init__(self, read_file, log_level=logging.INFO):
        super().__init__(read_file, protocol='newproto', log_level=log_level)
        self.packet_count = 0

    def process_capture(self, capture):
        # Implement protocol-specific parsing
        while has_more_data:
            packet = parse_packet(capture)
            self.write_protocol.write(packet.payload)
            self.packet_count += 1

    def log_status(self, logger=None):
        super().log_status(logger)
        self.logger.info(f"Found {self.packet_count} packets")
```

## Testing

Run tests with pytest:
```bash
pytest tests/ -v
pytest tests/test_ip_extractor.py -v
pytest tests/test_dvbs2_parser.py -v
```

## Kaitai Struct Integration

Protocol definitions use Kaitai Struct (`.ksy` files) for binary format specification. Generated Python parsers are in parser directories alongside the `.ksy` files.

To regenerate parsers:
```bash
kaitai-struct-compiler -t python protocol.ksy
```

## Performance Considerations

- **Memory Mapping**: Uses `mmap` for efficient large file handling
- **Progress Bars**: Optional via `--no-progress` flag
- **Preview Mode**: Limit processing with `preview_len` parameter
- **Fragment Cache**: LRU eviction prevents memory exhaustion
