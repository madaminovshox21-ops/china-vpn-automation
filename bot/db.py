"""SQLite (aiosqlite) ma'lumotlar bazasi qatlami."""
from __future__ import annotations

import os
import time
from typing import Any, Optional

import aiosqlite

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    tg_id      INTEGER PRIMARY KEY,
    username   TEXT,
    role       TEXT NOT NULL DEFAULT 'user',   -- user | operator | admin
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    price_stars INTEGER NOT NULL,
    -- yetkazish turi: text | file | link
    kind        TEXT NOT NULL DEFAULT 'text',
    payload     TEXT NOT NULL DEFAULT '',       -- matn / file_id / invite link
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS purchases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tg_id       INTEGER NOT NULL,
    product_id  INTEGER NOT NULL,
    stars       INTEGER NOT NULL,
    charge_id   TEXT,
    created_at  INTEGER NOT NULL
);

-- Foydalanuvchi tasdiqlagan domenlari (DNS-TXT egalik isboti)
CREATE TABLE IF NOT EXISTS targets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_tg_id  INTEGER NOT NULL,
    domain       TEXT NOT NULL,
    verify_token TEXT NOT NULL,
    verified     INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL,
    UNIQUE(owner_tg_id, domain)
);

-- Admin yaratgan engagement (ruxsatnoma) — mijoz uchun rasmiy skan doirasi
CREATE TABLE IF NOT EXISTS engagements (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    domain     TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    created_by INTEGER NOT NULL,
    active     INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    tg_id      INTEGER NOT NULL,
    domain     TEXT NOT NULL,
    scan_type  TEXT NOT NULL,      -- passive | active
    summary    TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
"""


class Database:
    def __init__(self, path: str) -> None:
        self.path = path
        self._conn: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._conn = await aiosqlite.connect(self.path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(SCHEMA)
        await self._conn.commit()

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()

    @property
    def conn(self) -> aiosqlite.Connection:
        assert self._conn is not None, "DB ulanmagan"
        return self._conn

    # ---------- users / rollar ----------
    async def upsert_user(self, tg_id: int, username: str | None) -> None:
        await self.conn.execute(
            """INSERT INTO users (tg_id, username, created_at) VALUES (?, ?, ?)
               ON CONFLICT(tg_id) DO UPDATE SET username=excluded.username""",
            (tg_id, username or "", int(time.time())),
        )
        await self.conn.commit()

    async def get_role(self, tg_id: int) -> str:
        cur = await self.conn.execute("SELECT role FROM users WHERE tg_id=?", (tg_id,))
        row = await cur.fetchone()
        return row["role"] if row else "user"

    async def set_role(self, tg_id: int, role: str) -> None:
        await self.conn.execute(
            """INSERT INTO users (tg_id, role, created_at) VALUES (?, ?, ?)
               ON CONFLICT(tg_id) DO UPDATE SET role=excluded.role""",
            (tg_id, role, int(time.time())),
        )
        await self.conn.commit()

    async def list_operators(self) -> list[aiosqlite.Row]:
        cur = await self.conn.execute(
            "SELECT tg_id, username, role FROM users WHERE role IN ('operator','admin') ORDER BY role"
        )
        return list(await cur.fetchall())

    # ---------- products ----------
    async def add_product(self, title, description, price_stars, kind, payload) -> int:
        cur = await self.conn.execute(
            """INSERT INTO products (title, description, price_stars, kind, payload, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (title, description, price_stars, kind, payload, int(time.time())),
        )
        await self.conn.commit()
        return cur.lastrowid

    async def list_products(self, only_active: bool = True) -> list[aiosqlite.Row]:
        q = "SELECT * FROM products"
        if only_active:
            q += " WHERE active=1"
        q += " ORDER BY id DESC"
        cur = await self.conn.execute(q)
        return list(await cur.fetchall())

    async def get_product(self, pid: int) -> Optional[aiosqlite.Row]:
        cur = await self.conn.execute("SELECT * FROM products WHERE id=?", (pid,))
        return await cur.fetchone()

    async def set_product_active(self, pid: int, active: bool) -> None:
        await self.conn.execute("UPDATE products SET active=? WHERE id=?", (1 if active else 0, pid))
        await self.conn.commit()

    # ---------- purchases ----------
    async def add_purchase(self, tg_id, product_id, stars, charge_id) -> None:
        await self.conn.execute(
            """INSERT INTO purchases (tg_id, product_id, stars, charge_id, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (tg_id, product_id, stars, charge_id, int(time.time())),
        )
        await self.conn.commit()

    async def stats(self) -> dict[str, Any]:
        c = self.conn
        users = (await (await c.execute("SELECT COUNT(*) n FROM users")).fetchone())["n"]
        sales = (await (await c.execute("SELECT COUNT(*) n FROM purchases")).fetchone())["n"]
        revenue = (await (await c.execute("SELECT COALESCE(SUM(stars),0) s FROM purchases")).fetchone())["s"]
        scans = (await (await c.execute("SELECT COUNT(*) n FROM scan_logs")).fetchone())["n"]
        return {"users": users, "sales": sales, "revenue": revenue, "scans": scans}

    # ---------- targets (ownership) ----------
    async def add_target(self, owner_tg_id, domain, token) -> None:
        await self.conn.execute(
            """INSERT INTO targets (owner_tg_id, domain, verify_token, created_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(owner_tg_id, domain) DO UPDATE SET verify_token=excluded.verify_token""",
            (owner_tg_id, domain, token, int(time.time())),
        )
        await self.conn.commit()

    async def get_target(self, owner_tg_id, domain) -> Optional[aiosqlite.Row]:
        cur = await self.conn.execute(
            "SELECT * FROM targets WHERE owner_tg_id=? AND domain=?", (owner_tg_id, domain)
        )
        return await cur.fetchone()

    async def mark_target_verified(self, owner_tg_id, domain) -> None:
        await self.conn.execute(
            "UPDATE targets SET verified=1 WHERE owner_tg_id=? AND domain=?", (owner_tg_id, domain)
        )
        await self.conn.commit()

    async def list_targets_for(self, owner_tg_id) -> list[aiosqlite.Row]:
        cur = await self.conn.execute(
            "SELECT domain, verified FROM targets WHERE owner_tg_id=? ORDER BY id DESC",
            (owner_tg_id,),
        )
        return list(await cur.fetchall())

    async def is_domain_verified_for(self, owner_tg_id, domain) -> bool:
        cur = await self.conn.execute(
            "SELECT verified FROM targets WHERE owner_tg_id=? AND domain=?", (owner_tg_id, domain)
        )
        row = await cur.fetchone()
        return bool(row and row["verified"])

    # ---------- engagements (admin ruxsatnomasi) ----------
    async def add_engagement(self, domain, note, created_by) -> int:
        cur = await self.conn.execute(
            "INSERT INTO engagements (domain, note, created_by, created_at) VALUES (?, ?, ?, ?)",
            (domain, note, created_by, int(time.time())),
        )
        await self.conn.commit()
        return cur.lastrowid

    async def is_domain_in_engagement(self, domain) -> bool:
        cur = await self.conn.execute(
            "SELECT 1 FROM engagements WHERE domain=? AND active=1 LIMIT 1", (domain,)
        )
        return (await cur.fetchone()) is not None

    async def list_engagements(self) -> list[aiosqlite.Row]:
        cur = await self.conn.execute(
            "SELECT * FROM engagements WHERE active=1 ORDER BY id DESC"
        )
        return list(await cur.fetchall())

    # ---------- logs ----------
    async def log_scan(self, tg_id, domain, scan_type, summary) -> None:
        await self.conn.execute(
            "INSERT INTO scan_logs (tg_id, domain, scan_type, summary, created_at) VALUES (?, ?, ?, ?, ?)",
            (tg_id, domain, scan_type, summary[:500], int(time.time())),
        )
        await self.conn.commit()
