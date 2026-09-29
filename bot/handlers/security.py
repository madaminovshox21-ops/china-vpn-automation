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
from ..services import breach, nuclei, recon, report, scanner, verify, vulnscan
from ..states import ScanFlow, VerifyFlow

SEV_EMOJI = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦", "INFO": "⬜"}

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


def _fmt_deep(r: dict) -> str:
    c = r["counts"]
    score = r["score"]
    bar = "🟢" if score >= 80 else ("🟡" if score >= 50 else "🔴")
    lines = [
        f"🔬 <b>Chuqur skan — {r['domain']}</b>",
        f"{bar} Xavfsizlik bali: <b>{score}/100</b>",
        f"🟥 {c.get('CRITICAL',0)}  🟧 {c.get('HIGH',0)}  🟨 {c.get('MEDIUM',0)}  🟦 {c.get('LOW',0)}",
        "",
    ]
    findings = r["findings"]
    if not findings:
        lines.append("✅ Jiddiy muammo topilmadi.")
    else:
        shown = [f for f in findings if f["sev"] != "INFO"][:15]
        for f in shown:
            em = SEV_EMOJI.get(f["sev"], "•")
            lines.append(f"{em} <b>{f['title']}</b>")
            if f.get("detail"):
                lines.append(f"    {f['detail']}")
            if f.get("fix"):
                lines.append(f"    💡 {f['fix']}")
        extra = len(findings) - len(shown)
        if extra > 0:
            lines.append(f"\n<i>...va yana {extra} ta. To'liq ro'yxat PDF hisobotda.</i>")
    return "\n".join(lines)


def _fmt_recon(r: dict) -> str:
    t = r.get("tech", {})
    subs = r.get("subdomains", [])
    ips = r.get("ips", {})
    lines = [f"🌐 <b>Recon — {html.escape(r['domain'])}</b>\n"]

    lines.append("<b>Texnologiyalar</b>")
    if t.get("ok"):
        if t.get("server"):
            lines.append(f"  Server: {html.escape(str(t['server']))}")
        if t.get("powered_by"):
            lines.append(f"  X-Powered-By: {html.escape(str(t['powered_by']))}")
        techs = t.get("tech", [])
        lines.append(f"  Aniqlangan: {html.escape(', '.join(techs)) if techs else '—'}")
    else:
        lines.append("  ❌ HTTP javob yo'q")

    lines.append(f"\n<b>Subdomenlar ({len(subs)})</b> <i>(crt.sh, passiv)</i>")
    if not subs:
        lines.append("  Certificate Transparency da topilmadi.")
    else:
        for host in subs[:25]:
            ip = ips.get(host)
            lines.append(f"  • <code>{html.escape(host)}</code>" + (f" → {ip}" if ip else ""))
        if len(subs) > 25:
            lines.append(f"  <i>...va yana {len(subs) - 25} ta (to'liq ro'yxat PDF'da).</i>")

    lines.append("\n<i>Passiv OSINT — nishonga so'rov yuborilmadi. Hujum yuzasini "
                 "kamaytirish uchun keraksiz subdomenlarni yoping.</i>")
    return "\n".join(lines)


def _fmt_nuclei(r: dict) -> str:
    findings = r.get("findings", [])
    lines = [f"⚡ <b>Nuclei skan — {html.escape(str(r.get('target', '')))}</b>\n"]
    if not findings:
        lines.append("✅ Tanlangan darajalarda (critical/high/medium) muammo topilmadi.")
        return "\n".join(lines)
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["sev"]] = counts.get(f["sev"], 0) + 1
    lines.append(
        f"🟥 {counts.get('CRITICAL', 0)}  🟧 {counts.get('HIGH', 0)}  "
        f"🟨 {counts.get('MEDIUM', 0)}  (jami {len(findings)})\n")
    for f in findings[:15]:
        em = SEV_EMOJI.get(f["sev"], "•")
        lines.append(f"{em} <b>{html.escape(str(f['title']))}</b>")
        if f.get("detail"):
            lines.append(f"    {html.escape(str(f['detail']))}")
    if len(findings) > 15:
        lines.append(f"\n<i>...va yana {len(findings) - 15} ta. To'liq ro'yxat PDF hisobotda.</i>")
    return "\n".join(lines)


def _fmt_breach_email(email: str, r: dict) -> str:
    lines = [f"📧 <b>Email sizishi — {html.escape(email)}</b>\n"]
    if not r.get("breached"):
        lines.append("✅ Ma'lum ommaviy sizishlarda ko'rilmagan (HIBP).")
        return "\n".join(lines)
    breaches = r.get("breaches", [])
    lines.append(f"🔴 <b>{len(breaches)} ta sizishda</b> ko'rilgan:\n")
    for b in breaches[:20]:
        lines.append(f"  • <b>{html.escape(str(b['name']))}</b> ({html.escape(str(b['date']))})")
        if b.get("data"):
            lines.append(f"    Sizgan: {html.escape(str(b['data']))}")
    if len(breaches) > 20:
        lines.append(f"  <i>...va yana {len(breaches) - 20} ta.</i>")
    lines.append("\n<i>💡 Ushbu emaildagi barcha hisoblar parolini o'zgartiring va "
                 "2FA yoqing.</i>")
    return "\n".join(lines)


def register(router_parent: Router, cfg, db) -> None:
    @router.message(F.text == "🛡 Xavfsizlik tekshiruvi")
    async def scan_menu(msg: Message):
        await msg.answer(
            "🛡 <b>Xavfsizlik tekshiruvi</b>\n\n"
            "• <b>🔎 Passiv</b> — tez ko'rinish (SSL, header, DNS).\n"
            "• <b>🔬 Chuqur skan</b> — avtomatik pentester: ochiq fayllar, CORS, TLS, "
            "cookie, HTTP metodlar + xavfsizlik bali va PDF hisobot.\n"
            "• <b>🌐 Recon</b> — subdomenlar (crt.sh, passiv) + texnologiya aniqlash.\n"
            "• <b>⚡ Nuclei</b> — ochiq shablonli faol zaiflik skani.\n"
            "• <b>🎯 Port skani</b> — ochiq portlar va xizmatlar.\n"
            "• <b>📧 Email sizishi</b> — email ma'lumot sizishlarida ko'rilganmi (HIBP).\n"
            "• <b>➕ Domen tasdiqlash</b> — o'z domeningizni tasdiqlash.\n\n"
            "<i>Recon, Nuclei, Port va Email — faqat tasdiqlangan yoki ruxsat "
            "berilgan nishonlar uchun.</i>",
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
            lines = [f"🎯 <b>Faol hisobot — {domain}</b>",
                     f"IP: <code>{res.get('ip')}</code>\n"]
            if not openp:
                lines.append("Ochiq port topilmadi (tekshirilgan keng tarqalgan portlarda).")
            else:
                lines.append(f"<b>Ochiq portlar ({len(openp)}):</b>")
                risky = 0
                for p in openp:
                    svc, note = scanner.PORT_INFO.get(p, ("?", None))
                    line = f"  🔓 <b>{p}</b> — {svc}"
                    if note:
                        line += f"\n       {note}"
                        if note.startswith("🔴"):
                            risky += 1
                    lines.append(line)
                lines.append("")
                if risky:
                    lines.append(f"🔴 <b>{risky} ta yuqori xavfli</b> port ochiq — darhol yoping yoki cheklang.")
                lines.append("<i>Har bir keraksiz portni yoping; kerakini firewall bilan cheklang.</i>")
            await wait.edit_text("\n".join(lines))
        except Exception as e:
            await wait.edit_text(f"❌ Skan xatosi: {html.escape(type(e).__name__)}: {html.escape(str(e))[:300]}")

    # ---- Chuqur skan (auto-pentester) ----
    @router.callback_query(F.data == "scan:deep")
    async def ask_deep(cb: CallbackQuery, state: FSMContext):
        await state.set_state(ScanFlow.deep_domain)
        await cb.message.answer(
            "🔬 <b>Chuqur skan</b> — domeningizni yuboring.\n"
            "Zararsiz (faqat o'qish) lekin ko'plab tekshiruv: ochiq fayllar, header, "
            "CORS, TLS, HTTP metodlar, DNS...")
        await cb.answer()

    @router.message(ScanFlow.deep_domain)
    async def do_deep(msg: Message, state: FSMContext):
        await state.clear()
        domain = scanner.normalize_domain(msg.text or "")
        if not domain:
            await msg.answer("❌ Domen noto'g'ri.")
            return
        allowed, reason = await can_active_scan(cfg, db, msg.from_user.id, domain)
        if not allowed:
            await msg.answer(reason)
            return
        wait = await msg.answer(f"🔬 <code>{domain}</code> chuqur tekshirilyapti... (30 soniyagacha)")
        try:
            r = await vulnscan.deep_scan(domain, cfg.scan_timeout)
        except Exception as e:
            await wait.edit_text(f"❌ Skan xatosi: {html.escape(type(e).__name__)}: {html.escape(str(e))[:300]}")
            return
        if not r.get("ok"):
            err = r.get("error") or "ulanib bo'lmadi"
            await wait.edit_text("❌ " + html.escape(str(err)))
            return
        await db.log_scan(msg.from_user.id, domain, "deep",
                          f"score={r['score']} n={len(r['findings'])}")
        _last_scan[msg.from_user.id] = {"deep": r}
        await wait.edit_text(_fmt_deep(r))
        await msg.answer("To'liq PDF hisobotni olasizmi?", reply_markup=report_kb())

    # ---- Recon (subdomen + texnologiya) — passiv OSINT, lekin gated ----
    @router.callback_query(F.data == "scan:recon")
    async def ask_recon(cb: CallbackQuery, state: FSMContext):
        await state.set_state(ScanFlow.recon_domain)
        await cb.message.answer(
            "🌐 <b>Recon</b> — <b>tasdiqlangan</b> domeningizni yuboring.\n"
            "Subdomenlar crt.sh (Certificate Transparency) dan olinadi (passiv), "
            "texnologiya HTTP javobidan aniqlanadi.")
        await cb.answer()

    @router.message(ScanFlow.recon_domain)
    async def do_recon(msg: Message, state: FSMContext):
        await state.clear()
        domain = scanner.normalize_domain(msg.text or "")
        if not domain:
            await msg.answer("❌ Domen noto'g'ri.")
            return
        # Passiv bo'lsa-da, hujum yuzasini ochadi — shuning uchun gated (qattiq).
        allowed, reason = await can_active_scan(cfg, db, msg.from_user.id, domain)
        if not allowed:
            await msg.answer(reason)
            return
        wait = await msg.answer(f"🌐 <code>{domain}</code> recon qilinyapti... ({reason})")
        try:
            r = await recon.run_recon(domain, cfg.scan_timeout)
        except Exception as e:
            await wait.edit_text(f"❌ Recon xatosi: {html.escape(type(e).__name__)}: "
                                 f"{html.escape(str(e))[:300]}")
            return
        await db.log_scan(msg.from_user.id, domain, "recon",
                          f"subs={len(r.get('subdomains', []))}")
        _last_scan[msg.from_user.id] = {"recon": r}
        await wait.edit_text(_fmt_recon(r))
        await msg.answer("To'liq PDF hisobotni olasizmi?", reply_markup=report_kb())

    # ---- Nuclei skan (faol, gated) ----
    @router.callback_query(F.data == "scan:nuclei")
    async def ask_nuclei(cb: CallbackQuery, state: FSMContext):
        if not nuclei.is_installed():
            await cb.message.answer("⚠️ " + nuclei.INSTALL_HINT)
            await cb.answer()
            return
        await state.set_state(ScanFlow.nuclei_domain)
        await cb.message.answer(
            "⚡ <b>Nuclei skan</b> — <b>tasdiqlangan</b> domeningizni yuboring.\n"
            "Faol skan (nishonga so'rov yuboriladi). critical/high/medium darajalar "
            "tekshiriladi, bir necha daqiqa olishi mumkin.")
        await cb.answer()

    @router.message(ScanFlow.nuclei_domain)
    async def do_nuclei(msg: Message, state: FSMContext):
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
        wait = await msg.answer(
            f"⚡ <code>{domain}</code> Nuclei bilan tekshirilyapti ({reason})...\n"
            "<i>Iltimos kuting — bu bir necha daqiqa olishi mumkin.</i>")
        try:
            r = await nuclei.run_nuclei(domain, cfg.scan_timeout)
        except Exception as e:
            await wait.edit_text(f"❌ Nuclei xatosi: {html.escape(type(e).__name__)}: "
                                 f"{html.escape(str(e))[:300]}")
            return
        if not r.get("ok"):
            await wait.edit_text("❌ " + html.escape(str(r.get("error") or "xatolik")))
            return
        await db.log_scan(msg.from_user.id, domain, "nuclei",
                          f"n={len(r.get('findings', []))}")
        _last_scan[msg.from_user.id] = {"nuclei": r}
        await wait.edit_text(_fmt_nuclei(r))
        await msg.answer("To'liq PDF hisobotni olasizmi?", reply_markup=report_kb())

    # ---- Email sizishi (HIBP) — email domeni bo'yicha gated ----
    @router.callback_query(F.data == "scan:breach")
    async def ask_breach(cb: CallbackQuery, state: FSMContext):
        await state.set_state(ScanFlow.breach_email)
        await cb.message.answer(
            "📧 <b>Email sizishi</b> — tekshiriladigan emailni yuboring.\n"
            "<i>Ruxsat: faqat tasdiqlangan/ruxsat berilgan domendagi emaillar "
            "(admin — istalgan). Email domeni tekshiriladi.</i>")
        await cb.answer()

    @router.message(ScanFlow.breach_email)
    async def do_breach(msg: Message, state: FSMContext):
        await state.clear()
        email = (msg.text or "").strip().lower()
        if "@" not in email or "." not in email.split("@")[-1] or len(email) > 254:
            await msg.answer("❌ Email noto'g'ri. Masalan: kimdir@example.com")
            return
        email_domain = scanner.normalize_domain(email.split("@")[-1])
        if not email_domain:
            await msg.answer("❌ Email domeni noto'g'ri.")
            return
        # Suiiste'molning oldini olish: faqat o'z/ruxsatli domendagi emaillar.
        allowed, reason = await can_active_scan(cfg, db, msg.from_user.id, email_domain)
        if not allowed:
            await msg.answer(
                "❌ Bu emailni tekshirishga ruxsat yo'q. Faqat o'zingiz tasdiqlagan "
                f"yoki ruxsat berilgan domendagi ({email_domain}) emaillarni "
                "tekshira olasiz.\n\n" + reason)
            return
        wait = await msg.answer(f"📧 <code>{html.escape(email)}</code> tekshirilyapti...")
        try:
            r = await breach.check_email(email, cfg.hibp_api_key, cfg.scan_timeout)
        except Exception as e:
            await wait.edit_text(f"❌ Xatolik: {html.escape(type(e).__name__)}: "
                                 f"{html.escape(str(e))[:200]}")
            return
        if not r.get("ok"):
            if r.get("need_key"):
                await wait.edit_text("⚠️ " + html.escape(str(r.get("error"))))
            else:
                await wait.edit_text("❌ " + html.escape(str(r.get("error") or "xatolik")))
            return
        await db.log_scan(msg.from_user.id, email_domain, "breach",
                          f"breached={r.get('breached')}")
        await wait.edit_text(_fmt_breach_email(email, r))

    # ---- PDF hisobot ----
    @router.callback_query(F.data == "report:pdf")
    async def send_report(cb: CallbackQuery):
        data = _last_scan.get(cb.from_user.id)
        if not data or not any(data.get(k) for k in ("passive", "deep", "recon", "nuclei")):
            await cb.answer("Avval tekshiruv o'tkazing.", show_alert=True)
            return
        await cb.answer("Hujjat tayyorlanyapti...")
        import asyncio as _asyncio
        import os as _os
        out_dir = _os.path.join(_os.path.dirname(cfg.db_path) or ".", "reports")
        try:
            if data.get("deep"):
                path = await _asyncio.to_thread(report.generate_deep_pdf, data["deep"], out_dir)
            elif data.get("recon"):
                path = await _asyncio.to_thread(report.generate_recon_pdf, data["recon"], out_dir)
            elif data.get("nuclei"):
                path = await _asyncio.to_thread(report.generate_nuclei_pdf, data["nuclei"], out_dir)
            else:
                path = await _asyncio.to_thread(
                    report.generate_pdf, data["passive"], out_dir, data.get("active"))
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
