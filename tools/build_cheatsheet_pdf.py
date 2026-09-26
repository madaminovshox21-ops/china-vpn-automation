"""Cheat sheet .md faylini chiroyli PDF mahsulotga aylantiradi.

Foydalanish:
    python tools/build_cheatsheet_pdf.py products/web-pentest-cheatsheet.md

Oddiy markdown qism to'plamini qo'llab-quvvatlaydi: sarlavhalar (#/##/###),
ro'yxatlar (-, [ ]), kod bloklari (```), gorizontal chiziq (---), sitata (>),
va oddiy paragraflar. Standart Helvetica/Courier shriftlari (latin-1).
"""
from __future__ import annotations

import os
import re
import sys

from fpdf import FPDF

ACCENT = (20, 90, 160)
CODE_BG = (244, 244, 248)
GREY = (110, 110, 110)


def _latin(s: str) -> str:
    repl = {"’": "'", "‘": "'", "“": '"', "”": '"', "–": "-", "—": "-",
            "•": "-", "…": "...", "⚠️": "[!]", "©": "(c)", "→": "->", "≥": ">="}
    for a, b in repl.items():
        s = s.replace(a, b)
    return s.encode("latin-1", "replace").decode("latin-1")


class Doc(FPDF):
    def header(self) -> None:
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*GREY)
        self.cell(0, 8, "Web Application Pentest Cheat Sheet", align="R")
        self.set_text_color(0, 0, 0)
        self.ln(6)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*GREY)
        self.cell(0, 8, f"SecBot  |  {self.page_no()}", align="C")
        self.set_text_color(0, 0, 0)


def render(md_path: str, out_path: str | None = None) -> str:
    with open(md_path, encoding="utf-8") as f:
        lines = f.read().splitlines()

    pdf = Doc(format="A4")
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.add_page()
    epw = pdf.w - pdf.l_margin - pdf.r_margin

    in_code = False
    code_buf: list[str] = []

    def flush_code() -> None:
        if not code_buf:
            return
        pdf.set_font("Courier", "", 8.5)
        pdf.set_fill_color(*CODE_BG)
        for cl in code_buf:
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(epw, 4.6, _latin(cl) or " ", fill=True,
                           new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1.5)
        code_buf.clear()

    for raw in lines:
        line = raw.rstrip()

        if line.strip().startswith("```"):
            if in_code:
                flush_code()
            in_code = not in_code
            continue
        if in_code:
            code_buf.append(raw)
            continue

        if not line.strip():
            pdf.ln(2.5)
            continue

        if re.match(r"^---+$", line.strip()):
            pdf.ln(1)
            pdf.set_draw_color(*ACCENT)
            pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
            pdf.ln(2.5)
            continue

        # Sarlavhalar
        m = re.match(r"^(#{1,3})\s+(.*)$", line)
        if m:
            level = len(m.group(1))
            text = re.sub(r"[*`]", "", m.group(2))
            size = {1: 18, 2: 13, 3: 11}[level]
            pdf.ln(1)
            pdf.set_font("Helvetica", "B", size)
            pdf.set_text_color(*ACCENT)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(epw, size * 0.5, _latin(text), new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
            pdf.ln(1)
            continue

        # Sitata
        if line.strip().startswith(">"):
            text = re.sub(r"[*`>]", "", line).strip()
            pdf.set_font("Helvetica", "I", 9.5)
            pdf.set_text_color(*GREY)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(epw, 5, _latin(text), new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
            continue

        # Jadval qatorini soddalashtirib matn qilamiz
        if line.strip().startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if all(set(c) <= set("-: ") for c in cells):
                continue  # ajratuvchi qator
            text = "  |  ".join(cells)
            pdf.set_font("Helvetica", "", 9.5)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(epw, 5, _latin(text), new_x="LMARGIN", new_y="NEXT")
            continue

        # Ro'yxat
        m = re.match(r"^(\s*)([-*]|\d+\.)\s+(.*)$", line)
        if m:
            indent = len(m.group(1))
            text = re.sub(r"[*`]", "", m.group(3))
            text = text.replace("[ ]", "[ ]").replace("[x]", "[x]")
            pdf.set_font("Helvetica", "", 10)
            pdf.set_x(pdf.l_margin + 4 + indent)
            pdf.multi_cell(epw - 4 - indent, 5, _latin("- " + text),
                           new_x="LMARGIN", new_y="NEXT")
            continue

        # Oddiy paragraf
        text = re.sub(r"[*`]", "", line)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(epw, 5, _latin(text), new_x="LMARGIN", new_y="NEXT")

    if in_code:
        flush_code()

    if out_path is None:
        out_path = os.path.splitext(md_path)[0] + ".pdf"
    pdf.output(out_path)
    return out_path


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "products/web-pentest-cheatsheet.md"
    out = render(src)
    print("Yaratildi:", out, os.path.getsize(out), "bayt")
