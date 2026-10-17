"""Independent verifier for chunaviq election records (shares no code with `chunaviq`)."""

from .verifier import verify_receipt, verify_record

__all__ = ["verify_record", "verify_receipt"]
