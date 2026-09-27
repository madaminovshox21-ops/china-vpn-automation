"""Nuclei integratsiyasi — mashhur, qonuniy zaiflik skaneri.

`nuclei` binariysini subprocess sifatida ishga tushiradi va JSON natijani
o'qiydi. Bu FAOL skan (nishonga so'rov yuboradi), shuning uchun ruxsat handler
qatlamida tekshiriladi (admin yoki tasdiqlangan nishon).

Nuclei o'rnatilmagan bo'lsa — yumshoq xabar va o'rnatish yo'riqnomasi.
Nuclei: https://github.com/projectdiscovery/nuclei
"""
from __future__ import annotations

import asyncio
import json
import shutil
from typing import Any

INSTALL_HINT = (
    "Nuclei o'rnatilmagan. O'rnatish:\n"
    "  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n"
    "yoki https://github.com/projectdiscovery/nuclei relizidan yuklab oling."
)


def is_installed() -> bool:
    return shutil.which("nuclei") is not None


async def run_nuclei(target: str, timeout: int = 8,
                     severities: str = "critical,high,medium",
                     max_seconds: int = 150) -> dict[str, Any]:
    if not is_installed():
        return {"ok": False, "installed": False, "error": INSTALL_HINT, "findings": []}

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    cmd = [
        "nuclei", "-u", target, "-jsonl", "-silent",
        "-severity", severities, "-timeout", str(min(timeout, 10)),
        "-retries", "1", "-rate-limit", "50", "-no-color",
        "-disable-update-check",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
    except Exception as e:
        return {"ok": False, "installed": True, "error": f"Ishga tushmadi: {e}", "findings": []}

    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=max_seconds)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return {"ok": False, "installed": True, "error": "Vaqt tugadi (juda uzoq).", "findings": []}

    findings: list[dict] = []
    for line in stdout.decode(errors="ignore").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except Exception:
            continue
        info = j.get("info", {})
        findings.append({
            "sev": str(info.get("severity", "info")).upper(),
            "title": info.get("name", j.get("template-id", "?")),
            "detail": j.get("matched-at", j.get("host", "")),
            "template": j.get("template-id", ""),
        })
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: order.get(f["sev"], 9))
    return {"ok": True, "installed": True, "findings": findings, "target": target}
