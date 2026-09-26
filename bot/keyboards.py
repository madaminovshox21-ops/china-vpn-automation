"""Inline va reply klaviaturalar."""
from __future__ import annotations

from aiogram.types import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    ReplyKeyboardMarkup,
)


def main_menu(is_staff: bool = False) -> ReplyKeyboardMarkup:
    rows = [
        [KeyboardButton(text="🛒 Do'kon"), KeyboardButton(text="🛡 Xavfsizlik tekshiruvi")],
        [KeyboardButton(text="🌐 Mening domenlarim"), KeyboardButton(text="ℹ️ Yordam")],
    ]
    if is_staff:
        rows.append([KeyboardButton(text="⚙️ Admin panel")])
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True)


def products_kb(products) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(text=f"{p['title']} — ⭐{p['price_stars']}", callback_data=f"buy:{p['id']}")]
        for p in products
    ]
    return InlineKeyboardMarkup(inline_keyboard=rows or [[InlineKeyboardButton(text="Bo'sh", callback_data="noop")]])


def scan_menu_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔎 Passiv tekshiruv (bepul)", callback_data="scan:passive")],
        [InlineKeyboardButton(text="🎯 Faol tekshiruv (tasdiq kerak)", callback_data="scan:active")],
        [InlineKeyboardButton(text="➕ Domen tasdiqlash", callback_data="verify:add")],
    ])


def verify_method_kb(domain: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="DNS-TXT usuli", callback_data=f"vm:dns:{domain}")],
        [InlineKeyboardButton(text="Fayl usuli", callback_data=f"vm:file:{domain}")],
    ])


def report_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📄 PDF hisobotni olish", callback_data="report:pdf")],
    ])


def admin_menu_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="➕ Mahsulot qo'shish", callback_data="adm:addprod")],
        [InlineKeyboardButton(text="📦 Mahsulotlar", callback_data="adm:products")],
        [InlineKeyboardButton(text="👥 Operatorlar", callback_data="adm:ops")],
        [InlineKeyboardButton(text="📝 Engagement (ruxsatnoma)", callback_data="adm:eng")],
        [InlineKeyboardButton(text="📊 Statistika", callback_data="adm:stats")],
    ])
