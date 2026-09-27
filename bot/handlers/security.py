"""Xavfsizlik tekshiruvi handlerlari: passiv (bepul), faol (gated), tasdiqlash."""
from __future__ import annotations

import html

from aiogram import F, Router
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from aiogram.types import FSInputFile

from ..access import can_active_scan
from ..keyboards import report_kb, scan_menu_kb, verify_method_kb
from ..services import report, scanner, verify
from ..states import ScanFlow, VerifyFlow

router = Router()

# Foydalanuvchining oxirgi skan natijasi (PDF uchun), xotirada
_last_scan: dict[int, dict] = {}


def _fmt_passive(r: dict) -> str:
    d, s, h = r["dns"], r["ssl"], r["http"]
    lines = [f"🛡 <b>Passiv hisobot — {r['domain']}</b>\n"]

    # DNS
    lines.append("<b>DNS</b>")
    lines.append(f"  A: {', '.join(d['A']) or '—'}")
    if d["MX"]:
        lines.append(f"  MX: {len(d['MX'])} ta")
    lines.append(f"  SPF: {'✅' if d['has_spf'] else '❌ yo‘q'}   DMARC: {'✅' if d['has_dmarc'] else '❌ yo‘q'}")

    # SSL
    lines.append("\n<b>SSL/TLS</b>")
    if s.get("ok"):
        dl = s.get("days_left")
        warn = " ⚠️" if (dl is not None and dl < 21) else ""
        lines.append(f"  Protokol: {s.get('protocol')}")
        lines.append(f"  Beruvchi: {s.get('issuer')}")
        lines.append(f"  Muddati: {dl} kun qoldi{warn}")
    elif h.get("ok") and not h.get("https"):
        lines.append("  ❌ HTTPS yo‘q (sayt faqat HTTP orqali ishlaydi) — jiddiy kamchilik")
    else:
        lines.append("  ❌ HTTPS (443) ochiq emas yoki javob bermadi")

    # HTTP(S) headers
    scheme = (h.get("scheme") or "?").upper()
    lines.append(f"\n<b>Xavfsizlik header'lari</b> ({scheme})")
    if h.get("ok"):
        if not h.get("https"):
            lines.append("  ⚠️ Sayt faqat HTTP — trafik shifrlanmagan")
        if h["present"]:
            lines.append(f"  ✅ Bor: {', '.join(h['present'])}")
        if h["missing"]:
            lines.append(f"  ❌ Yo‘q: {', '.join(h['missing'])}")
        if h.get("server"):
            lines.append(f"  Server: {h['server']}")
        lines.append(f"  Status: {h.get('status')}   security.txt: {'✅' if h.get('security_txt') else '❌ yo‘q'}")
    else:
        lines.append(f"  ❌ Javob yo‘q: {h.get('error', '—')}")

    # Tavsiyalar
    recs = []
    if h.get("ok") and not h.get("https"):
        recs.append("HTTPS (SSL sertifikat) o'rnating — HTTP shifrlanmagan, xavfli.")
    if h.get("ok") and h.get("missing"):
        recs.append("Yetishmayotgan xavfsizlik header'larini qo'shing.")
    if not d["has_spf"] or not d["has_dmarc"]:
        recs.append("Email spoofingdan himoya uchun SPF/DMARC sozlang.")
    if s.get("ok") and s.get("days_left") is not None and s["days_left"] < 21:
        recs.append("SSL sertifikat muddati tugayapti — yangilang.")
    if recs:
        lines.append("\n<b>💡 Tavsiyalar</b>")
        lines += [f"  • {x}" for x in recs]

    lines.append("\n<i>To'liq faol tekshiruv (portlar) uchun domenni tasdiqlang.</i>")
    return "\n".join(lines)


def register(router_parent: Router, cfg, db) -> None:
    @router.message(F.text == "🛡 Xavfsizlik tekshiruvi")
    async def scan_menu(msg: Message):
        await msg.answer(
            "🛡 <b>Xavfsizlik tekshiruvi</b>\n\n"
            "• <b>Passiv</b> — bepul, ochiq ma'lumot (SSL, header, DNS).\n"
            "• <b>Faol</b> — port skani, faqat tasdiqlangan domeningizga.\n"
            "• <b>Domen tasdiqlash</b> — DNS-TXT yoki fayl orqali.",
            reply_markup=scan_menu_kb(),
        )

    @router.message(F.text == "🌐 Mening domenlarim")
    async def my_domains(msg: Message):
        rows = await db.list_targets_for(msg.from_user.id)
        if not rows:
            await msg.answer("Sizda tasdiqlangan domen yo'q. /verify bilan qo'shing.")
            return
        txt = "🌐 <b>Mening domenlarim</b>\n\n"
        for r in rows:
            txt += f"{'✅' if r['verified'] else '⏳'} {r['domain']}\n"
        txt += "\n⏳ = tasdiq kutilyapti (/check &lt;domen&gt;)"
        await msg.answer(txt)

    # ---- Passiv ----
    @router.callback_query(F.data == "scan:passive")
    async def ask_passive(cb: CallbackQuery, state: FSMContext):
        await state.set_state(ScanFlow.passive_domain)
        await cb.message.answer("Domen yoki URL yuboring (masalan: example.com):")
        await cb.answer()

    @router.message(ScanFlow.passive_domain)
    async def do_passive(msg: Message, state: FSMContext):
        await state.clear()
        domain = scanner.normalize_domain(msg.text or "")
        if not domain:
            await msg.answer("❌ Domen noto'g'ri. Qayta urinib ko'ring: /start")
            return
        wait = await msg.answer(f"🔎 <code>{domain}</code> tekshirilyapti...")
        try:
            r = await scanner.run_passive(domain, cfg.scan_timeout)
        except Exception as e:
            await wait.edit_text(f"❌ Xatolik: {e}")
            return
        await db.log_scan(msg.from_user.id, domain, "passive", "ok")
        _last_scan[msg.from_user.id] = {"passive": r, "active": None}
        await wait.edit_text(_fmt_passive(r))
        await msg.answer("To'liq hujjatni yuklab olasizmi?", reply_markup=report_kb())

    # ---- Faol (gated) ----
    @router.callback_query(F.data == "scan:active")
    async def ask_active(cb: CallbackQuery, state: FSMContext):
        await state.set_state(ScanFlow.active_domain)
        await cb.message.answer("Faol tekshiruv uchun <b>tasdiqlangan</b> domeningizni yuboring:")
        await cb.answer()

    @router.message(ScanFlow.active_domain)
    async def do_active(msg: Message, state: FSMContext):
        await state.clear()
        domain = scanner.normalize_domain(msg.text or "")
        if not domain:
            await msg.answer("❌ Domen noto'g'ri.")
            return
        if not cfg.enable_active_scan:
            await msg.answer("Faol skan admin tomonidan o'chirilgan.")
            return
        allowed, reason = await can_active_scan(cfg, db, msg.from_user.id, domain)
        if not allowed:
            await msg.answer(reason)
            return
        wait = await msg.answer(f"🎯 <code>{domain}</code> faol tekshirilyapti ({reason})...")
        try:
            res = await scanner.scan_ports(domain, cfg.scan_timeout, authorized=True)
            await db.log_scan(msg.from_user.id, domain, "active", f"open={res.get('open')}")
            prev = _last_scan.get(msg.from_user.id, {})
            if prev.get("passive", {}).get("domain") == domain:
                prev["active"] = res
                _last_scan[msg.from_user.id] = prev
            if res.get("error"):
                await wait.edit_text(f"❌ {html.escape(str(res['error']))}")
                return
            openp = res.get("open", [])
            txt = (
                f"🎯 <b>Faol hisobot — {domain}</b> ({res.get('ip')})\n\n"
                f"Ochiq portlar: {', '.join(map(str, openp)) if openp else 'topilmadi'}\n"
            )
            if openp:
                txt += "\n<i>Har bir ochiq port — potensial kirish nuqtasi. Keraksizlarini yoping.</i>"
            await wait.edit_text(txt)
        except Exception as e:
            await wait.edit_text(f"❌ Skan xatosi: {html.escape(type(e).__name__)}: {html.escape(str(e))[:300]}")

    # ---- PDF hisobot ----
    @router.callback_query(F.data == "report:pdf")
    async def send_report(cb: CallbackQuery):
        data = _last_scan.get(cb.from_user.id)
        if not data or not data.get("passive"):
            await cb.answer("Avval tekshiruv o'tkazing.", show_alert=True)
            return
        await cb.answer("Hujjat tayyorlanyapti...")
        import os as _os
        out_dir = _os.path.join(_os.path.dirname(cfg.db_path) or ".", "reports")
        try:
            path = await __import__("asyncio").to_thread(
                report.generate_pdf, data["passive"], out_dir, data.get("active")
            )
            await cb.message.answer_document(FSInputFile(path), caption="📄 Xavfsizlik hisoboti")
            try:
                _os.remove(path)
            except OSError:
                pass
        except Exception as e:
            await cb.message.answer(f"❌ PDF yaratishda xatolik: {e}")

    # ---- Tasdiqlash ----
    @router.message(Command("verify"))
    @router.callback_query(F.data == "verify:add")
    async def verify_start(event, state: FSMContext):
        msg = event.message if isinstance(event, CallbackQuery) else event
        await state.set_state(VerifyFlow.domain)
        await msg.answer("Tasdiqlamoqchi bo'lgan domeningizni yuboring (masalan: example.com):")
        if isinstance(event, CallbackQuery):
            await event.answer()

    @router.message(VerifyFlow.domain)
    async def verify_domain(msg: Message, state: FSMContext):
        domain = scanner.normalize_domain(msg.text or "")
        if not domain:
            await msg.answer("❌ Domen noto'g'ri.")
            return
        await state.clear()
        token = verify.make_token(msg.from_user.id, domain)
        await db.add_target(msg.from_user.id, domain, token)
        await msg.answer(
            f"Domen: <b>{domain}</b>\nQaysi usul bilan tasdiqlaysiz?",
            reply_markup=verify_method_kb(domain),
        )

    @router.callback_query(F.data.startswith("vm:"))
    async def verify_method(cb: CallbackQuery):
        _, method, domain = cb.data.split(":", 2)
        tgt = await db.get_target(cb.from_user.id, domain)
        if not tgt:
            await cb.answer("Avval /verify bilan domen qo'shing.", show_alert=True)
            return
        token = tgt["verify_token"]
        if method == "dns":
            await cb.message.answer(verify.dns_instructions(domain, token))
        else:
            await cb.message.answer(verify.file_instructions(domain, token))
        await cb.answer()

    @router.message(Command("check"))
    async def verify_check(msg: Message):
        # /check example.com
        parts = (msg.text or "").split()
        if len(parts) < 2:
            await msg.answer("Foydalanish: /check example.com")
            return
        domain = scanner.normalize_domain(parts[1])
        if not domain:
            await msg.answer("❌ Domen noto'g'ri.")
            return
        tgt = await db.get_target(msg.from_user.id, domain)
        if not tgt:
            await msg.answer("Avval /verify bilan domen qo'shing.")
            return
        token = tgt["verify_token"]
        wait = await msg.answer("🔍 Tasdiq tekshirilyapti...")
        ok = await verify.verify_dns_txt(domain, token, cfg.scan_timeout) or \
            await verify.verify_file(domain, token, cfg.scan_timeout)
        if ok:
            await db.mark_target_verified(msg.from_user.id, domain)
            await wait.edit_text(f"✅ <b>{domain}</b> tasdiqlandi! Endi faol tekshiruv qila olasiz.")
        else:
            await wait.edit_text(
                "❌ Tasdiq topilmadi. TXT yozuv yoki fayl to'g'ri joylashtirilganini "
                "tekshiring va qayta /check qiling. (DNS tarqalishi vaqt olishi mumkin.)"
            )

    router_parent.include_router(router)
