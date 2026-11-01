# Next.js Knowledge Profile (App Router, Pages Router, Server Actions)

## Stack Identification
- **Markers:** `next.config.(js|mjs|ts)`, `"next"` in `package.json`, an `app/` or `src/app/` tree with
  `route.ts` / `page.tsx`, a `pages/api/` tree, imports from `next/server`, `next/navigation`, `next/headers`.
- **Auth libraries:** Auth.js / NextAuth (`auth()`, `getServerSession`), Better Auth (`getSession`,
  `getSessionCookie`), Clerk (`auth()`, `currentUser()`), Lucia, iron-session, or a project wrapper such as
  `withAuth(handler, { permission })`.
- **Data access:** Drizzle (`db.query.x.findFirst`, `db.select().from(x).where(...)`), Prisma
  (`prisma.x.findUnique`), postgres.js, `@vercel/postgres`, Mongoose.

## Entry points (what the pre-scan inventories)
| Kind | File | URL | Notes |
|---|---|---|---|
| Route handler | `app/**/route.ts` | folder path; `(group)` and `@slot` dropped, `[id]` → `{id}`, `[...x]` / `[[...x]]` → `{x*}` | One route per exported `GET`/`POST`/... function or `export const GET = wrap(...)`. `_folder` is private (not routed). |
| Pages API | `pages/api/**.ts` | `/api/...`, `index` dropped | One handler for all methods; method from `req.method` checks. |
| Server action | file starting with `"use server"`, or a function whose body starts with `"use server"` | `action:<file>#<name>` | **Every exported function is a public POST endpoint**, callable with any arguments, even if the UI never calls it that way. |
| Page | `app/**/page.tsx` with a dynamic segment or `searchParams` | folder path | A GET that renders data loaded by id. |

## Where the guard lives
1. **`middleware.ts` / `proxy.ts` (Next.js 16):** runs before routes listed in `config.matcher`. Usually only
   checks that a session cookie exists; it rarely checks roles or ownership, and a matcher gap leaves routes
   open. Never accept middleware alone as an ownership check.
2. **Per handler:** `const session = await auth(); if (!session) return 401`, or a wrapper (`withAuth`).
   Check the wrapper once and reuse the result for every route that uses it.
3. **Server actions:** need their own check inside the action. Layout or page checks do **not** protect an
   action, because the action can be called directly.

## BOLA / IDOR Patterns
- **Vulnerable:** id from `params` / `searchParams` / action argument / JSON body used without the user or
  tenant in the query:
  ```ts
  export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
    const { id } = await params;
    const order = await db.query.orders.findFirst({ where: eq(orders.id, id) }); // any user's order
    return Response.json(order);
  }

  "use server";
  export async function cancelOrder(orderId: number) {
    const session = await auth();          // authenticated, but...
    await db.update(orders).set({ status: "cancelled" }).where(eq(orders.id, orderId)); // ...not owner-scoped
  }
  ```
- **Protected:** the session user or tenant is part of the lookup, or the loaded row is compared to it, and
  a miss returns 404:
  ```ts
  const order = await db.query.orders.findFirst({
    where: and(eq(orders.id, id), eq(orders.tenantId, session.user.tenantId)),
  });
  if (!order) return new Response(null, { status: 404 });
  ```
- **Mass assignment:** `db.update(users).set(await req.json())` or spreading `formData` into `.set({...})`
  lets a user write `role`, `tenantId`, `ownerId`.
- **BFLA:** admin routes guarded only by "is logged in" (middleware cookie check, `auth()` without a role or
  permission check).

## SQL Injection Patterns
- **Safe:** Drizzle query builder, Drizzle / postgres.js / Prisma tagged templates (`` sql`... ${x}` ``,
  `` prisma.$queryRaw`...` ``): `${x}` is a bound parameter.
- **Vulnerable:** `sql.raw(x)`, `sql.unsafe(x)`, `Prisma.raw(x)`, `$queryRawUnsafe(`...${x}`)`, or an untagged
  template passed to `db.execute(...)`, with `x` from the request.
