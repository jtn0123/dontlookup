# Don't Look Up: IP encapsulation parser from raw DVB-S2(X) captures

## Features

- Support for many DVB-S2(X) IP packet encapsulation variants, including: GSE, MPEG-TS, IP, and Reverse encoding
- Output showing packet counts for each parser

## Installation

First, install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

Run all parsers (default):
```bash
python3 dontlookup.py capture_file.ts
```

Run a specific parser:
```bash
python3 dontlookup.py capture_file.ts -p dvbs2-ip
```

Run multiple specific parsers:
```bash
python3 dontlookup.py capture_file.ts -p dvbs2-ip -p dvbs2-mpegts
```

### Available Parsers

- `dvbs2-ip` - DVBS2 -> IP
- `dvbs2-rev-ip` - DVBS2 -> Reverse -> IP
- `dvbs2-mpegts` - DVBS2 -> MPEG-TS
- `dvbs2-mpegts-crc` - DVBS2 -> MPEG-TS with Generic CRC
- `dvbs2-mpegts-newtec` - DVBS2 -> MPEG-TS with Newtec CRC
- `dvbs2-gse-stdlen-split-ip` - DVBS2 -> GSE (standard length, split frag ID) -> IP
- `dvbs2-gse-stdlen-std-ip` - DVBS2 -> GSE (standard length, standard frag ID) -> IP
- `dvbs2-gse-len2-split-ip` - DVBS2 -> GSE (hdrlen-2, split frag ID) -> IP
- `dvbs2-gse-len2-std-ip` - DVBS2 -> GSE (hdrlen-2, standard frag ID) -> IP
- `all` - Run all parsers

### Options

- `-p, --parser` - Specify parser(s) to run (can be used multiple times)
- `-v, --verbose` - Increase logging verbosity
  - Default: INFO level
  - `-v`: HEADER level
  - `-vv`: DEBUG level
  - `-vvv`: PAYLOAD level (most verbose)
- `--no-progress` - Disable progress bars
- `-h, --help` - Show help message

### Examples

```bash
# Run all parsers with default settings
python3 dontlookup.py capture.ts -p all

# Run only IP-related parsers
python3 dontlookup.py capture.ts -p dvbs2-ip -p dvbs2-rev-ip

# Run GSE parsers with verbose output
python3 dontlookup.py capture.ts -p dvbs2-gse-stdlen-split-ip -p dvbs2-gse-len2-split-ip -v

# Run MPEG-TS parsers without progress bars
python3 dontlookup.py capture.ts -p dvbs2-mpegts -p dvbs2-mpegts-crc --no-progress
```

## Output

The tool will:
1. Run each specified parser in sequence
2. Display packet counts as each parser completes
3. Generate a summary at the end showing all results
4. Generate parsed files in the `output/` directory
5. Generate log files in the `logs/` directory

### Understanding Output Files

Each parser creates a chain of intermediate files by appending extensions. For example:

**dvbs2-ip parser chain:**
- `capture.ts.dvbs2` - Raw BBFrame payloads (intermediate)
- `capture.ts.dvbs2.ip` - IP packets as PCAP (final)

**dvbs2-gse-stdlen-split-ip parser chain:**
- `capture.ts.dvbs2` - Raw BBFrame payloads (intermediate)
- `capture.ts.dvbs2.stdlen.split.gse` - GSE PDU payloads (intermediate)
- `capture.ts.dvbs2.stdlen.split.gse.ip` - IP packets as PCAP (final)

**dvbs2-mpegts parser chain:**
- `capture.ts.dvbs2` - Raw BBFrame payloads (intermediate)
- `capture.ts.dvbs2.mpegts` - MPEG-TS stream (final)

### Which Files to Examine

The `output/` directory will contain many intermediate files, but **you only need to examine the final output files**:

- **For IP packet analysis**: Look at `.ip.pcap` files - open these in Wireshark
- **For MPEG-TS analysis**: Look at `.mpegts` files - open these in Wireshark/tshark

The intermediate files (`.dvbs2`, `.gse`, `.rev`, etc.) are kept for debugging but are not needed for normal analysis.

### Sample Output

```
Processing capture file: capture.ts
Running 2 parser(s)...

=== Running: DVBS2 -> IP ===
  BBFrames found: 1234
  IP packets found: 567

=== Running: DVBS2 -> MPEG-TS ===
  BBFrames found: 1234
  MPEG-TS packets found: 890

======================================================================
SUMMARY OF ALL PARSERS
======================================================================

dvbs2-ip:
  bbframes: 1234
  ip_packets: 567

dvbs2-mpegts:
  bbframes: 1234
  mpegts_packets: 890
```

## Parser Details

### DVBS2 Parsers
- Extracts BBFrames from DVB-S2 captures
- Reports number of frames and CRC-encoded frames
- Performs blind IP header search by checking for correct IP CRCs on all byte offsets (slow)

### GSE Parsers
- Four variants based on header length and fragment ID type:
  
  **Header Length Variants:**
  - **Standard length**: Uses standard GSE length field encoding (12 bits)
  - **hdrlen-2**: Uses non-standard 2-byte header length field (some proprietary implementations)
  
  **Fragment ID Encoding Variants:**
  - **Standard (std)**: Parses fragment ID as standard 8-bit field
  - **Split**: Parses fragment ID using 6/2 bit split encoding (6 bits for fragment ID + 2 bits for counter)
  
  The difference is in HOW they parse the fragment ID field from the GSE header.
  The "split" variant is for non-standard DVB-S2 implementations where the 8-bit fragment ID field is actually split into a 6-bit fragment ID and a 2-bit counter.

- Reports whole PDUs, fragmented PDUs, and reassembled packets

### MPEG-TS Parsers
- Three variants:
  - Standard MPEG-TS
  - Generic CRC-protected MPEG-TS
  - Newtec CRC-protected MPEG-TS
- Reports transport packet counts
- Generates MPEGTS files that can be opened in Wireshark/tshark

### IP Parsers
- Extracts IPv4 packets
- Validates checksums
- Generates PCAP files that can be opened in Wireshark/tshark

### Reverse Parser
- Swaps every pair of bytes (byte-swap 16-bit words)

## Notes
- The tool does NOT perform heuristics to determine the best parser
- You need to open each output file in Wireshark to find the correctly parsed version
- All specified parsers are run independently
- Output files are organized by parser type in the `write/` directory
- Each parser run is logged separately in the `logs/` directory
