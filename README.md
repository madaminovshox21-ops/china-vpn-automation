# SecBot — Xavfsizlik tekshiruvi + Raqamli do'kon (Telegram)

Ikki funksiyali Telegram bot:

1. **🛒 Do'kon** — raqamli mahsulotlar (cheat sheet, lab, skript, yopiq kanal)
   Telegram Stars (⭐ XTR) evaziga sotiladi, to'lovdan keyin avtomatik yetkaziladi.
2. **🛡 Xavfsizlik tekshiruvi**
   - **Passiv** (bepul, hammaga): SSL/TLS, HTTP xavfsizlik header'lari, DNS (SPF/DMARC), security.txt.
   - **Faol** (port skani): **faqat tasdiqlangan domenga** — quyidagi chegara bilan.

## ⚖️ Huquqiy chegara (muhim)

Faol skan begona tizimga ishlamaydi. Ruxsat uch yo'l bilan beriladi:

- Foydalanuvchi domenni **DNS-TXT** yoki **fayl** orqali tasdiqlaydi (boshqaruv isboti), yoki
- **Admin** o'sha domen uchun **engagement** (yozma ruxsatga asoslangan) yaratadi — keyin xodimlar skan qila oladi.

Bu bot egasini va mijozni qonuniy himoya qiladi. **Hech qachon ruxsatsiz domenni engagementga qo'shmang.**

## Rollar

- **admin** — to'liq boshqaruv (`.env` dagi `ADMIN_IDS` yoki DB'da `role=admin`).
- **operator** — engagement bor domenlarga faol skan qila oladi (`/addop <tg_id>`).
- **user** — do'kon + passiv skan + o'z domenini tasdiqlab faol skan.

## O'rnatish

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # keyin .env ni to'ldiring
python -m bot.main
```

### `.env`
- `BOT_TOKEN` — @BotFather dan.
- `ADMIN_IDS` — sizning Telegram ID (@userinfobot dan), vergul bilan bir nechta.
- `ENABLE_ACTIVE_SCAN` — `true`/`false`.

## Telegram Stars

To'lov `XTR` valyutasida ishlaydi, provayder token kerak emas. Yig'ilgan Stars'ni
Telegram qoidalari bo'yicha yechib olasiz. To'lovlarni yoqish uchun @BotFather →
bot sozlamalarida hech narsa qo'shimcha shart emas (Stars standart yoqilgan).

## Buyruqlar

| Buyruq | Kim | Vazifa |
|---|---|---|
| `/start`, `/help` | hamma | menyu, yordam |
| `/shop` | hamma | do'kon |
| `/verify` | hamma | domen tasdiqlash |
| `/check <domen>` | hamma | tasdiqni tekshirish |
| `/admin` | admin | admin panel |
| `/addop`, `/delop <id>` | admin | operator qo'shish/olib tashlash |
| `/addeng` | admin | engagement yaratish |
| `/toggle <id>` | admin | mahsulotni yoq/o'chir |

## Struktura

```
bot/
  config.py          # .env sozlamalari
  db.py              # SQLite (aiosqlite)
  access.py          # rol va ruxsat chegarasi
  states.py          # FSM holatlari
  keyboards.py       # tugmalar
  main.py            # kirish nuqtasi
  services/
    scanner.py       # passiv + gated faol skan
    verify.py        # DNS-TXT / fayl tasdiqlash
  handlers/
    common.py store.py security.py admin.py
```

## Deploy (server)

Oddiy VPS'da systemd bilan doimiy ishlatish:

```ini
# /etc/systemd/system/secbot.service
[Unit]
Description=SecBot
After=network.target
[Service]
WorkingDirectory=/opt/secbot
ExecStart=/opt/secbot/.venv/bin/python -m bot.main
Restart=always
[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now secbot
```
