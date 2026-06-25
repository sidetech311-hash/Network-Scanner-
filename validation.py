"""
Input validation and sanitization for the Network Scanner.
"""

import re
import ipaddress


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


def validate_target(target):
    """
    Validate and normalize a target IP or hostname.
    Raises ValidationError if invalid.
    """
    if not target or not isinstance(target, str):
        raise ValidationError("Target must be a non-empty string.")
    
    target = target.strip()
    if len(target) > 255:
        raise ValidationError("Target exceeds maximum length (255 characters).")
    
    # Try to parse as IP address
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    
    # Try to parse as hostname (basic DNS name validation)
    hostname_pattern = r'^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)*[a-zA-Z0-9-]{1,63}(?<!-)$'
    if re.match(hostname_pattern, target):
        return target
    
    raise ValidationError(
        f"Invalid target '{target}'. Must be a valid IPv4/IPv6 address or hostname."
    )


def validate_port_range(start_port, end_port):
    """
    Validate port range.
    Raises ValidationError if invalid.
    """
    try:
        start = int(start_port)
        end = int(end_port)
    except (ValueError, TypeError):
        raise ValidationError("Ports must be integers.")
    
    if start < 1 or start > 65535:
        raise ValidationError("Start port must be between 1 and 65535.")
    
    if end < 1 or end > 65535:
        raise ValidationError("End port must be between 1 and 65535.")
    
    if start > end:
        raise ValidationError("Start port must be less than or equal to end port.")
    
    port_range = end - start + 1
    if port_range > 10000:
        raise ValidationError(
            f"Port range too large ({port_range} ports). "
            "Maximum recommended is 10000 ports per scan."
        )
    
    return start, end


def validate_timeout(timeout):
    """
    Validate timeout value in seconds.
    Raises ValidationError if invalid.
    """
    try:
        t = float(timeout)
    except (ValueError, TypeError):
        raise ValidationError("Timeout must be a number.")
    
    if t < 0.1 or t > 30:
        raise ValidationError("Timeout must be between 0.1 and 30 seconds.")
    
    return t


def validate_max_threads(max_threads):
    """
    Validate max threads value.
    Raises ValidationError if invalid.
    """
    try:
        threads = int(max_threads)
    except (ValueError, TypeError):
        raise ValidationError("Max threads must be an integer.")
    
    if threads < 1 or threads > 1000:
        raise ValidationError("Max threads must be between 1 and 1000.")
    
    return threads


def validate_scan_params(target, start_port, end_port, timeout, max_threads):
    """
    Validate all scan parameters at once.
    Returns tuple of (target, start_port, end_port, timeout, max_threads).
    Raises ValidationError if any parameter is invalid.
    """
    target = validate_target(target)
    start_port, end_port = validate_port_range(start_port, end_port)
    timeout = validate_timeout(timeout)
    max_threads = validate_max_threads(max_threads)
    
    return target, start_port, end_port, timeout, max_threads
