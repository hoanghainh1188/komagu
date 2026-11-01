#!/usr/bin/env python3
"""Next.js stack detection and route inventory (Issue #324).

Covers App Router route handlers (route groups, dynamic and catch-all segments, `export const`
handlers), Pages Router API routes, server actions (file-level and inline "use server"), dynamic
server-component pages, and middleware / proxy notes.
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
from lsa_common import load_config  # noqa: E402
from map_routes import map_routes  # noqa: E402

FILES: Dict[str, str] = {
    "next.config.ts": "const nextConfig = {};\nexport default nextConfig;\n",
    "src/proxy.ts": (
        'import { NextResponse } from "next/server";\n'
        "export async function proxy(request) { return NextResponse.next(); }\n"
        'export const config = { matcher: ["/((?!_next|login).*)"] };\n'
    ),
    # unguarded BOLA: id from the path, no owner filter
    "src/app/api/orders/[id]/route.ts": (
        'import { db } from "@/db";\n'
        "export async function GET(request, { params }) {\n"
        "  const { id } = await params;\n"
        "  return Response.json(await db.query.orders.findFirst({ where: eq(orders.id, id) }));\n"
        "}\n"
        "\n"
        "export async function DELETE(request, { params }) {\n"
        "  const session = await auth();\n"
        "  await db.delete(orders).where(eq(orders.id, params.id));\n"
        "  return new Response(null, { status: 204 });\n"
        "}\n"
    ),
    # route group, export const with a guard wrapper, query + JSON body inputs
    "src/app/(admin)/api/users/[userId]/route.ts": (
        'import { withAuth } from "@/lib/auth/guard";\n'
        "export const PATCH = withAuth(async (request, { actor, params }) => {\n"
        "  const { role, tenantId } = await request.json();\n"
        '  const dry = request.nextUrl.searchParams.get("dryRun");\n'
        "  return changeRole(actor, params.userId, role);\n"
        '}, { permission: "users.manage" });\n'
    ),
    "app/api/files/[...path]/route.js": "export async function GET(req, ctx) { return serve(ctx.params.path); }\n",
    "app/api/health/route.ts": "export function GET() { return Response.json({ ok: true }); }\n",
    # private folder: not routable
    "app/_lib/route.ts": "export function GET() {}\n",
    "pages/api/invoices/[invoiceId].ts": (
        "export default async function handler(req, res) {\n"
        '  if (req.method === "DELETE") { await removeInvoice(req.query.invoiceId); }\n'
        '  if (req.method === "GET") { res.json(await getInvoice(req.query.invoiceId)); }\n'
        "}\n"
    ),
    "pages/api/index.ts": "export default function handler(req, res) { res.json({}); }\n",
    "src/app/orders/actions.ts": (
        '"use server";\n'
        'import { auth } from "@/auth";\n'
        "export async function cancelOrder(orderId: number, reason: string) {\n"
        "  const session = await auth();\n"
        "  await db.update(orders).set({ status: 'cancelled' }).where(eq(orders.id, orderId));\n"
        "}\n"
        "export const archiveOrder = async (formData: FormData) => {\n"
        '  const id = formData.get("orderId");\n'
        "  await db.delete(orders).where(eq(orders.id, id));\n"
        "};\n"
        "function helper() {}\n"
    ),
    "src/app/orders/[code]/page.tsx": (
        "export default async function OrderPage({ params }) {\n"
        "  const { code } = await params;\n"
        "  const order = await getOrderByCode(code);\n"
        "  async function approve() {\n"
        '    "use server";\n'
        "    await approveOrder(order.id);\n"
        "  }\n"
        "  return <form action={approve}><p>{order.code}</p></form>;\n"
        "}\n"
    ),
    "src/app/about/page.tsx": "export default function About() { return <p>about</p>; }\n",
}


def _write(root: Path) -> None:
    for rel, text in FILES.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _routes(root: Path) -> List[Dict]:
    cfg = load_config(None)
    stacks = {s["id"] for s in detect(root, cfg)["stacks"]}
    return map_routes(root, cfg, stacks)["candidates"]


def _find(routes: List[Dict], method: str, path: str) -> Dict:
    hits = [r for r in routes if r["path"] == path and method in r["method"]]
    if len(hits) != 1:
        raise AssertionError(f"{method} {path}: {len(hits)} hits in {[(r['method'], r['path']) for r in routes]}")
    return hits[0]


def _names(route: Dict) -> Dict[str, str]:
    return {p["name"]: p["source"] for p in route["id_params"]}


class TestNextjs(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._td = tempfile.TemporaryDirectory()
        cls.root = Path(cls._td.name)
        _write(cls.root)
        cls.routes = _routes(cls.root)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._td.cleanup()

    def test_stack_detected(self) -> None:
        prof = detect(self.root, load_config(None))
        self.assertIn("node-nextjs", {s["id"] for s in prof["stacks"]})
        self.assertIn("knowledge/stacks/nextjs.md", prof["knowledge_files"])

    def test_all_routes_are_nextjs(self) -> None:
        self.assertEqual({r["stack"] for r in self.routes}, {"node-nextjs"})

    def test_route_handlers_per_method(self) -> None:
        get = _find(self.routes, "GET", "/api/orders/{id}")
        self.assertEqual(get["kind"], "declared_route")
        self.assertEqual(get["handler"]["file"], "src/app/api/orders/[id]/route.ts")
        self.assertEqual(get["handler"]["line"], 2)
        self.assertEqual(_names(get), {"id": "path"})
        self.assertTrue(get["needs_audit_hint"])
        self.assertEqual(get["guard_hints"], [])
        delete = _find(self.routes, "DELETE", "/api/orders/{id}")
        self.assertTrue(any("auth()" in g["hint"] for g in delete["guard_hints"]))

    def test_route_group_and_export_const(self) -> None:
        patch = _find(self.routes, "PATCH", "/api/users/{userId}")
        self.assertEqual(_names(patch), {"userId": "path", "role": "body", "tenantId": "body", "dryRun": "query"})
        hints = " ".join(g["hint"] for g in patch["guard_hints"])
        self.assertIn("withAuth", hints)
        self.assertIn("users.manage", hints)

    def test_catch_all_and_static(self) -> None:
        _find(self.routes, "GET", "/api/files/{path*}")
        self.assertEqual(_find(self.routes, "GET", "/api/health")["id_params"], [])

    def test_private_folder_skipped(self) -> None:
        self.assertFalse(any(r["handler"]["file"] == "app/_lib/route.ts" for r in self.routes))

    def test_pages_api(self) -> None:
        inv = _find(self.routes, "DELETE", "/api/invoices/{invoiceId}")
        self.assertEqual(sorted(inv["method"]), ["DELETE", "GET"])
        self.assertEqual(_names(inv)["invoiceId"], "path")
        self.assertEqual(_find(self.routes, "ANY", "/api")["handler"]["file"], "pages/api/index.ts")

    def test_server_actions(self) -> None:
        cancel = _find(self.routes, "POST", "action:src/app/orders/actions.ts#cancelOrder")
        self.assertEqual(_names(cancel), {"orderId": "body", "reason": "body"})
        self.assertTrue(any("auth" in g["hint"] for g in cancel["guard_hints"]))
        archive = _find(self.routes, "POST", "action:src/app/orders/actions.ts#archiveOrder")
        self.assertEqual(_names(archive), {"orderId": "form"})
        self.assertFalse(any(r["path"].endswith("#helper") for r in self.routes))

    def test_inline_server_action_and_page(self) -> None:
        _find(self.routes, "POST", "action:src/app/orders/[code]/page.tsx#approve")
        page = _find(self.routes, "GET", "/orders/{code}")
        self.assertEqual(page["kind"], "file_endpoint")
        self.assertEqual(_names(page), {"code": "path"})
        self.assertFalse(any(r["path"] == "/about" for r in self.routes))

    def test_proxy_noted(self) -> None:
        get = _find(self.routes, "GET", "/api/orders/{id}")
        self.assertIn("src/proxy.ts", get["notes"])
        self.assertIn("matcher", get["notes"])


if __name__ == "__main__":
    unittest.main()
