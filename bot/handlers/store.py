"""Do'kon: katalog, Telegram Stars orqali to'lov, avtomatik yetkazish."""
from __future__ import annotations

from aiogram import F, Router
from aiogram.filters import Command
from aiogram.types import (
    CallbackQuery,
    LabeledPrice,
    Message,
    PreCheckoutQuery,
)

from ..keyboards import products_kb

router = Router()


def register(router_parent: Router, cfg, db) -> None:
    @router.message(Command("shop"))
    @router.message(F.text == "🛒 Do'kon")
    async def show_shop(msg: Message):
        products = await db.list_products(only_active=True)
        if not products:
            await msg.answer("🛒 Hozircha mahsulot yo'q. Tez orada qo'shiladi.")
            return
        text = "🛒 <b>Do'kon</b>\nMahsulotni tanlang:\n\n"
        for p in products:
            text += f"• <b>{p['title']}</b> — ⭐{p['price_stars']}\n{p['description']}\n\n"
        await msg.answer(text, reply_markup=products_kb(products))

    @router.callback_query(F.data.startswith("buy:"))
    async def buy(cb: CallbackQuery):
        pid = int(cb.data.split(":")[1])
        p = await db.get_product(pid)
        if not p or not p["active"]:
            await cb.answer("Mahsulot topilmadi.", show_alert=True)
            return
        await cb.message.answer_invoice(
            title=p["title"][:32],
            description=(p["description"] or p["title"])[:255],
            payload=f"product:{pid}",
            currency="XTR",  # Telegram Stars
            prices=[LabeledPrice(label=p["title"][:32], amount=int(p["price_stars"]))],
        )
        await cb.answer()

    @router.pre_checkout_query()
    async def pre_checkout(pcq: PreCheckoutQuery):
        # Stars uchun har doim ok; xohlasangiz bu yerda tekshiruv qo'shasiz
        await pcq.answer(ok=True)

    @router.message(F.successful_payment)
    async def on_paid(msg: Message):
        sp = msg.successful_payment
        payload = sp.invoice_payload
        if not payload.startswith("product:"):
            return
        pid = int(payload.split(":")[1])
        p = await db.get_product(pid)
        await db.add_purchase(
            msg.from_user.id, pid, sp.total_amount, sp.telegram_payment_charge_id
        )
        if not p:
            await msg.answer("To'lov qabul qilindi, lekin mahsulot topilmadi. Admin bilan bog'laning.")
            return
        await msg.answer("✅ To'lov qabul qilindi! Mahsulotingiz:")
        kind, data = p["kind"], p["payload"]
        try:
            if kind == "file":
                await msg.answer_document(data, caption=p["title"])
            elif kind == "link":
                await msg.answer(f"🔗 {p['title']}\n{data}")
            else:  # text
                await msg.answer(data or "(bo'sh)")
        except Exception:
            # file_id boshqa botniki bo'lsa yoki xato — fallback
            await msg.answer(f"{p['title']}\n\n{data}")

    router_parent.include_router(router)
