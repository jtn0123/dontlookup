"""
Custom exception hierarchy for the DVB-S2 parser framework.

This module defines specialized exceptions for different error conditions
that can occur during parsing, making error handling more precise and
informative.
"""


class ParserError(Exception):
    """Base exception for all parser-related errors."""
    pass


class InvalidFormatError(ParserError):
    """
    Raised when input data does not conform to expected format.

    This includes malformed headers, invalid field values, or
    unexpected data structures.
    """
    pass


class ChecksumError(ParserError):
    """
    Raised when a checksum validation fails.

    Attributes:
        expected: The expected checksum value
        actual: The actual computed checksum value
    """
    def __init__(self, message: str, expected: int = None, actual: int = None):
        super().__init__(message)
        self.expected = expected
        self.actual = actual


class FragmentReassemblyError(ParserError):
    """
    Raised when fragment reassembly fails.

    This can occur due to missing fragments, out-of-order fragments,
    or fragment cache overflow.
    """
    pass


class FragmentCollisionError(FragmentReassemblyError):
    """Raised when a fragment ID collision is detected in the cache."""
    pass


class IncompleteFragmentError(FragmentReassemblyError):
    """Raised when attempting to reassemble an incomplete fragment sequence."""
    pass


class CaptureFileError(ParserError):
    """
    Raised for errors related to capture file operations.

    This includes file not found, permission errors, or corrupted files.
    """
    pass


class UnsupportedProtocolError(ParserError):
    """
    Raised when an unsupported protocol type is encountered.

    Attributes:
        protocol_type: The unsupported protocol identifier
    """
    def __init__(self, message: str, protocol_type: int = None):
        super().__init__(message)
        self.protocol_type = protocol_type


class ParserChainError(ParserError):
    """Raised when there's an error in the parser chain configuration."""
    pass
