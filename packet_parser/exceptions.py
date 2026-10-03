"""Custom exceptions for packet parser module."""

class PacketParsingError(Exception):
    """Raised when packet parsing fails or packet structure is invalid."""
    pass

class UnsupportedProtocolError(PacketParsingError):
    """Raised when a packet uses an unsupported network/transport protocol."""
    pass
