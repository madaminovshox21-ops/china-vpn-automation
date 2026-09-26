"""Admin panel: mahsulotlar, operatorlar, engagement, statistika.

Faqat admin (config ADMIN_IDS yoki DB role='admin') kira oladi.
"""
from __future__ import annotations

from aiogram import F, Router
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from ..access import is_admin
from ..keyboards import admin_menu_kb
from ..states import AddEngagement, AddOperator, AddProduct

router = Router()


def register(router_parent: Router, cfg, db) -> None:

    async def guard(user_id: int) -> bool:
        return await is_admin(cfg, db, user_id)

    @router.message(Command("admin"))
    @router.message(F.text == "⚙️ Admin panel")
    async def admin_panel(msg: Message):
        if not await guard(msg.from_user.id):
            await msg.answer("⛔ Faqat admin uchun.")
            return
        await msg.answer("⚙️ <b>Admin panel</b>", reply_markup=admin_menu_kb())

    # ---------- statistika ----------
    @router.callback_query(F.data == "adm:stats")
    async def stats(cb: CallbackQuery):
        if not await guard(cb.from_user.id):
            await cb.answer("⛔", show_alert=True)
            return
        s = await db.stats()
        await cb.message.answer(
            f"📊 <b>Statistika</b>\n\n"
            f"👤 Foydalanuvchilar: {s['users']}\n"
            f"🛒 Sotuvlar: {s['sales']}\n"
            f"⭐ Umumiy daromad: {s['revenue']} Stars\n"
            f"🛡 Tekshiruvlar: {s['scans']}"
        )
        await cb.answer()

    # ---------- mahsulotlar ----------
    @router.callback_query(F.data == "adm:products")
    async def list_products(cb: CallbackQuery):
        if not await guard(cb.from_user.id):
            await cb.answer("⛔", show_alert=True)
            return
        prods = await db.list_products(only_active=False)
        if not prods:
            await cb.message.answer("Mahsulot yo'q.")
        else:
            txt = "📦 <b>Mahsulotlar</b>\n\n"
            for p in prods:
                st = "🟢" if p["active"] else "🔴"
                txt += f"{st} #{p['id']} {p['title']} — ⭐{p['price_stars']} ({p['kind']})\n"
            txt += "\nO'chirish/yoqish: /toggle &lt;id&gt;"
            await cb.message.answer(txt)
        await cb.answer()

    @router.message(Command("toggle"))
    async def toggle(msg: Message):
        if not await guard(msg.from_user.id):
            return
        parts = (msg.text or "").split()
        if len(parts) < 2 or not parts[1].isdigit():
            await msg.answer("Foydalanish: /toggle <id>")
            return
        pid = int(parts[1])
        p = await db.get_product(pid)
        if not p:
            await msg.answer("Topilmadi.")
            return
        await db.set_product_active(pid, not p["active"])
        await msg.answer(f"#{pid} holati o'zgartirildi.")

    @router.callback_query(F.data == "adm:addprod")
    async def add_prod_start(cb: CallbackQuery, state: FSMContext):
        if not await guard(cb.from_user.id):
            await cb.answer("⛔", show_alert=True)
            return
        await state.set_state(AddProduct.title)
        await cb.message.answer("Mahsulot nomi:")
        await cb.answer()

    @router.message(AddProduct.title)
    async def ap_title(msg: Message, state: FSMContext):
        await state.update_data(title=msg.text)
        await state.set_state(AddProduct.description)
        await msg.answer("Tavsif:")

    @router.message(AddProduct.description)
    async def ap_desc(msg: Message, state: FSMContext):
        await state.update_data(description=msg.text)
        await state.set_state(AddProduct.price)
        await msg.answer("Narxi (Stars, butun son):")

    @router.message(AddProduct.price)
    async def ap_price(msg: Message, state: FSMContext):
        if not (msg.text or "").strip().isdigit():
            await msg.answer("Faqat son yuboring.")
            return
        await state.update_data(price=int(msg.text))
        await state.set_state(AddProduct.kind)
        await msg.answer("Yetkazish turi — <code>text</code> / <code>file</code> / <code>link</code> dan birini yozing:")

    @router.message(AddProduct.kind)
    async def ap_kind(msg: Message, state: FSMContext):
        kind = (msg.text or "").strip().lower()
        if kind not in ("text", "file", "link"):
            await msg.answer("text, file yoki link deb yozing.")
            return
        await state.update_data(kind=kind)
        await state.set_state(AddProduct.payload)
        prompt = {
            "text": "Yetkaziladigan matnni yuboring:",
            "file": "Faylni shu yerga yuboring (document):",
            "link": "Havolani (masalan yopiq kanal invite) yuboring:",
        }[kind]
        await msg.answer(prompt)

    @router.message(AddProduct.payload)
    async def ap_payload(msg: Message, state: FSMContext):
        data = await state.get_data()
        kind = data["kind"]
        if kind == "file":
            if not msg.document:
                await msg.answer("Iltimos, document yuboring.")
                return
            payload = msg.document.file_id
        else:
            payload = msg.text or ""
        pid = await db.add_product(data["title"], data["description"], data["price"], kind, payload)
        await state.clear()
        await msg.answer(f"✅ Mahsulot qo'shildi. ID #{pid}")

    # ---------- operatorlar ----------
    @router.callback_query(F.data == "adm:ops")
    async def ops(cb: CallbackQuery):
        if not await guard(cb.from_user.id):
            await cb.answer("⛔", show_alert=True)
            return
        rows = await db.list_operators()
        txt = "👥 <b>Xodimlar</b>\n\n"
        if rows:
            for r in rows:
                txt += f"• {r['tg_id']} @{r['username'] or '—'} [{r['role']}]\n"
        else:
            txt += "Yo'q.\n"
        txt += (
            "\n➕ Operator qo'shish: /addop &lt;tg_id&gt;\n"
            "➖ Olib tashlash: /delop &lt;tg_id&gt;"
        )
        await cb.message.answer(txt)
        await cb.answer()

    @router.message(Command("addop"))
    async def addop(msg: Message):
        if not await guard(msg.from_user.id):
            return
        parts = (msg.text or "").split()
        if len(parts) < 2 or not parts[1].lstrip("-").isdigit():
            await msg.answer("Foydalanish: /addop <tg_id>")
            return
        await db.set_role(int(parts[1]), "operator")
        await msg.answer(f"✅ {parts[1]} operator qilindi.")

    @router.message(Command("delop"))
    async def delop(msg: Message):
        if not await guard(msg.from_user.id):
            return
        parts = (msg.text or "").split()
        if len(parts) < 2 or not parts[1].lstrip("-").isdigit():
            await msg.answer("Foydalanish: /delop <tg_id>")
            return
        await db.set_role(int(parts[1]), "user")
        await msg.answer(f"✅ {parts[1]} oddiy foydalanuvchi qilindi.")

    # ---------- engagement ----------
    @router.callback_query(F.data == "adm:eng")
    async def eng(cb: CallbackQuery):
        if not await guard(cb.from_user.id):
            await cb.answer("⛔", show_alert=True)
            return
        rows = await db.list_engagements()
        txt = "📝 <b>Engagement (ruxsatnomalar)</b>\n\n"
        if rows:
            for r in rows:
                txt += f"• #{r['id']} {r['domain']} — {r['note'] or ''}\n"
        else:
            txt += "Yo'q.\n"
        txt += "\n➕ Yangi: /addeng"
        await cb.message.answer(txt)
        await cb.answer()

    @router.message(Command("addeng"))
    async def addeng_start(msg: Message, state: FSMContext):
        if not await guard(msg.from_user.id):
            return
        await state.set_state(AddEngagement.domain)
        await msg.answer(
            "📝 Yangi engagement.\n\n"
            "⚠️ Faqat mijoz <b>yozma ruxsat bergan</b> domenni kiriting. "
            "Bu domenga xodimlaringiz faol skan qila oladi.\n\nDomen:"
        )

    @router.message(AddEngagement.domain)
    async def addeng_domain(msg: Message, state: FSMContext):
        from ..services import scanner
        domain = scanner.normalize_domain(msg.text or "")
        if not domain:
            await msg.answer("❌ Domen noto'g'ri.")
            return
        await state.update_data(domain=domain)
        await state.set_state(AddEngagement.note)
        await msg.answer("Izoh (mijoz nomi, shartnoma raqami va h.k.):")

    @router.message(AddEngagement.note)
    async def addeng_note(msg: Message, state: FSMContext):
        data = await state.get_data()
        eid = await db.add_engagement(data["domain"], msg.text or "", msg.from_user.id)
        await state.clear()
        await msg.answer(f"✅ Engagement #{eid} yaratildi: {data['domain']}")

    router_parent.include_router(router)
