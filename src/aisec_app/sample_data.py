from __future__ import annotations

from .models import BinaryMetadata, CVECase


def demo_case() -> CVECase:
    return CVECase(
        case_id="demo-parse-header",
        cve_id="CVE-2021-XXXX",
        advisory=(
            "A heap buffer overflow can occur in parse_header() when attacker-controlled "
            "input_len is copied into a fixed-size buffer without bounds checking."
        ),
        binary_metadata=BinaryMetadata(
            path="samples/bin/vulnscan",
            architecture="x86_64",
            compiler="gcc-12",
            optimization="O2",
        ),
        patch_diff=(
            "- memcpy(buf, input, input_len);\n"
            "+ if (input_len > sizeof(buf)) return -1;\n"
            "+ memcpy(buf, input, input_len);"
        ),
        decompiler_excerpt=(
            "parse_header @ 0x401234\n"
            "if (header_ready) {\n"
            "    memcpy(buf, input, input_len);\n"
            "}\n"
            "return 0;"
        ),
    )
