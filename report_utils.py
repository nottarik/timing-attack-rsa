# Zajednički alati za generisanje Markdown izvještaja

from __future__ import annotations
import os
import platform
import socket
import sys
from datetime import datetime
from typing import Optional


class MarkdownReport:
    def __init__(self, title: str):
        self._lines: list[str] = []
        self.add_heading(1, title)

    def add_heading(self, level: int, text: str) -> None:
        self._lines.append(f"\n{'#' * level} {text}\n")

    def add_paragraph(self, text: str) -> None:
        self._lines.append(f"{text}\n")

    def add_table(
        self,
        headers: list[str],
        rows: list[list[str]],
        alignment: Optional[list[str]] = None,
    ) -> None:
        if alignment is None:
            alignment = ["l"] * len(headers)
        sep_chars = {"l": ":---", "r": "---:", "c": ":---:"}
        header_row = "| " + " | ".join(headers) + " |"
        sep_row = "| " + " | ".join(sep_chars.get(a, ":---") for a in alignment) + " |"
        self._lines.append(header_row)
        self._lines.append(sep_row)
        for row in rows:
            self._lines.append("| " + " | ".join(str(c) for c in row) + " |")
        self._lines.append("")

    def add_code_block(self, code: str, language: str = "") -> None:
        self._lines.append(f"```{language}")
        self._lines.append(code)
        self._lines.append("```\n")

    def add_stat_line(self, name: str, value, unit: str = "") -> None:
        unit_str = f" {unit}" if unit else ""
        self._lines.append(f"- **{name}:** {value}{unit_str}")

    def add_verdict(self, passed: bool, message: str) -> None:
        icon = "PASS" if passed else "FAIL"
        self._lines.append(f"- [{icon}] {message}")

    def save(self, filepath: str) -> None:
        os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(self._lines))

    def to_string(self) -> str:
        return "\n".join(self._lines)


def get_metadata() -> dict:
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "hostname": socket.gethostname(),
    }


def try_convert_to_pdf(md_path: str) -> Optional[str]:
    import shutil
    import subprocess
    if not shutil.which("pandoc"):
        return None
    pdf_path = md_path.replace(".md", ".pdf")
    try:
        subprocess.run(
            ["pandoc", md_path, "-o", pdf_path, "--pdf-engine=xelatex"],
            check=True, capture_output=True,
        )
        return pdf_path
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
