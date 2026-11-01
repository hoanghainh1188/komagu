#!/usr/bin/env python3
"""Parameterizing JS/TS sql tagged templates are not injection candidates (Issue #326).

Drizzle, postgres.js, @vercel/postgres, Slonik and Prisma ($queryRaw, Prisma.sql) send ${...}
inside a tagged template as a bound parameter. Raw-text escape hatches (sql.raw, Prisma.raw,
sql.unsafe, $queryRawUnsafe) and untagged templates are still flagged.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from typing import Dict, List

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from detect_stack import detect  # noqa: E402
from find_injection import find_injection  # noqa: E402
from lsa_common import load_config  # noqa: E402

SAFE_TAGGED = '''\
import { sql } from "drizzle-orm";
import { Prisma } from "@prisma/client";

export async function counts(db, prisma, orderId, req) {
  const id = req.query.id;
  const lineCount = sql<number>`(select count(*)::int from ${orderLine} where ${orderLine.orderId} = ${orderId})`;
  const rows = await db.execute(sql`select * from orders where id = ${id}`);
  const p = await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;
  await prisma.$executeRaw`UPDATE users SET name = ${req.body.name} WHERE id = ${id}`;
  const frag = Prisma.sql`SELECT * FROM users WHERE email = ${req.body.email}`;
  const pg = await pool.sql`select * from items where owner_id = ${id}`;
  return [lineCount, rows, p, frag, pg];
}
'''

UNSAFE = '''\
import { sql } from "drizzle-orm";

export async function unsafe(db, prisma, req) {
  const id = req.query.id;
  const a = await db.execute(`SELECT * FROM orders WHERE id = ${id}`);
  const b = await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${id}`);
  const c = await db.execute(sql`select * from orders order by ${sql.raw(req.query.sort)}`);
  const d = await db.execute(sql`select nextval(${sql.raw(`'${customerSeq.seqName}'`)}) as value`);
  const e = await db.execute(sql`select * from t order by ${sql.raw("created_at")}`);
  const f = await prisma.$queryRaw`SELECT * FROM t ORDER BY ${Prisma.raw(req.query.sort)}`;
  return [a, b, c, d, e, f];
}
'''

NO_INPUT = '''\
import { sql } from "drizzle-orm";

export async function nextCode(tx, sequence) {
  return tx.execute(sql`select nextval(${sql.raw(`'${sequence.seqName}'`)}) as value`);
}
'''


def _scan(files: Dict[str, str]) -> List[Dict]:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        for rel, text in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        return find_injection(root, load_config(None))["candidates"]


def _by_line(cands: List[Dict]) -> Dict[int, Dict]:
    return {c["line"]: c for c in cands}


class TestJsTaggedSql(unittest.TestCase):
    def test_parameterizing_tags_not_flagged(self) -> None:
        self.assertEqual(_scan({"src/safe.ts": SAFE_TAGGED}), [])

    def test_untagged_and_unsafe_calls_flagged(self) -> None:
        got = _by_line(_scan({"src/unsafe.ts": UNSAFE}))
        self.assertEqual(got[5]["rule"], "sql-interpolation")  # untagged template to db.execute
        self.assertEqual(got[6]["rule"], "sql-interpolation")  # $queryRawUnsafe

    def test_raw_fragments(self) -> None:
        got = _by_line(_scan({"src/unsafe.ts": UNSAFE}))
        self.assertEqual(got[7]["rule"], "sql-raw-fragment")  # sql.raw(req.query.sort)
        self.assertEqual(got[7]["priority"], "high")
        self.assertEqual(got[8]["rule"], "sql-raw-fragment")  # sql.raw of a schema property
        self.assertNotIn(9, got)  # sql.raw("literal") is a constant
        self.assertEqual(got[10]["rule"], "sql-raw-fragment")  # Prisma.raw(req.query.sort)
        self.assertEqual(got[10]["priority"], "high")

    def test_raw_fragment_without_request_input_is_low(self) -> None:
        got = _scan({"src/seq.ts": NO_INPUT})
        self.assertEqual([(c["rule"], c["priority"]) for c in got], [("sql-raw-fragment", "low")])

    def test_data_access_names_library(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.ts").write_text('import { sql } from "drizzle-orm";\n', encoding="utf-8")
            (root / "b.ts").write_text('import postgres from "postgres";\n', encoding="utf-8")
            da = detect(root, load_config(None))["data_access"]
            self.assertIn("Drizzle ORM (Node/TS)", da)
            self.assertIn("postgres.js (Node/TS)", da)


if __name__ == "__main__":
    unittest.main()
