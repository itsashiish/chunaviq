"""Independent verifier for evlab election records (shares no code with `evlab`)."""

from .verifier import verify_receipt, verify_record

__all__ = ["verify_record", "verify_receipt"]
