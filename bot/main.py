"""Kirish nuqtasi: botni ishga tushiradi."""
from __future__ import annotations

import asyncio
import logging

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode

from .config import Config
from .db import Database
from .handlers import admin, common, security, store
from .seed import seed_products


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    cfg = Config.load()

    db = Database(cfg.db_path)
    await db.connect()
    added = await seed_products(db)
    if added:
        logging.info("Do'kon seed: %d ta mahsulot qo'shildi", added)

    bot = Bot(cfg.bot_token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher()

    # Handlerlarni ro'yxatga olamiz
    common.register(dp, cfg, db)
    store.register(dp, cfg, db)
    security.register(dp, cfg, db)
    admin.register(dp, cfg, db)

    logging.info("Bot ishga tushdi. Adminlar: %s", cfg.admin_ids)
    try:
        await bot.delete_webhook(drop_pending_updates=True)
        await dp.start_polling(bot)
    finally:
        await db.close()
        await bot.session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass
