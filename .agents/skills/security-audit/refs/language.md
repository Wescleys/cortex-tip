# Padrões por linguagem — JavaScript / TypeScript / React / Next.js

Carregar no **Step 1** **depois** de `refs/project-stack.md` (versões **instaladas** no lockfile).

Aplicar seções condicionais pelo **major** detectado (ex.: `unauthorized()` só se Next ≥ 16). Complementa `refs/nextjs-checklist.md` e `refs/false-positives.md`.

---

## APIs de alto risco (sinks)

Investigar sempre que **input do usuário** possa alcançar:

```ts
eval()
new Function()
child_process.exec / execSync / spawn
fs.readFile / writeFile / unlink  // path controlado pelo usuário
fetch(url)  // url controlada pelo usuário → SSRF
dangerouslySetInnerHTML
element.innerHTML
document.write()
```

Prisma:

```ts
// CRITICAL — concatenação / unsafe
prisma.$queryRawUnsafe(`SELECT * FROM t WHERE id = ${id}`)
prisma.$executeRawUnsafe(userInput)

// Avaliar com cuidado — tagged template com parâmetros é o padrão seguro
prisma.$queryRaw`SELECT ...`
prisma.$queryRaw(Prisma.sql`...`, ...)

// Seguro quando where usa tipos + input validado (Zod)
prisma.appointment.findMany({ where: { userId: sessionUserId } })
```

---

## React (versão instalada — major 18 ou 19+)

### XSS — reportar quando

```tsx
// HTML de usuário/CMS sem sanitização
<div dangerouslySetInnerHTML={{ __html: post.content }} />

// NÃO reportar automaticamente — CSS de config interna (shadcn chart, temas)
<style dangerouslySetInnerHTML={{ __html: generatedFromThemeConfig }} />
```

```tsx
// React escapa — NÃO é XSS
<p>{user.bio}</p>

// Reportar se URL vem do usuário sem validação
<a href={userUrl}>link</a>
// Fix: allowlist http/https ou use URL + block javascript: e data:
```

### Cliente

- Tokens/sessão em `localStorage` sem necessidade → preferir cookie httpOnly (Auth.js)
- `NEXT_PUBLIC_*` com secret de API → **CRITICAL**

---

## Next.js — App Router (13+ se `app/` existir)

### Server Actions (15+ comum; 14+ possível)

Tratar como **endpoint público** ([data security](https://nextjs.org/docs/app/guides/data-security)):

> Proteção na **página ou layout não se estende** à Server Action: a action é outro ponto de entrada e precisa de `auth()` / autorização **dentro** da action (ou helper chamado no topo). Válido em qualquer major recente; reforçado na doc Next 15+.

```ts
'use server'

import { auth } from '@/lib/auth'
import { z } from 'zod'

const schema = z.object({ name: z.string().min(1) })

export async function updateProfile(data: unknown) {
  const session = await auth()
  if (!session?.user?.id) {
    throw new Error('Unauthorized')
  }

  const parsed = schema.parse(data)

  await prisma.user.update({
    where: { id: session.user.id }, // ownership — NÃO usar id do formData sem checar
    data: { name: parsed.name },
  })
}
```

**Next.js ≥ 16 (instalado)** — `unauthorized()` / `forbidden()`:

```ts
import { unauthorized } from 'next/navigation'

export async function updateProfile(data: unknown) {
  const session = await auth()
  if (!session?.user?.id) {
    unauthorized()
  }
  // ...
}
```

Se Next **&lt; 16**: usar `throw`, `redirect('/login')` ou `NextResponse.json(..., { status: 401 })` — não reportar “falta unauthorized()” como HIGH.

Sinais de problema:

- `'use server'` sem `auth()` (e sem helper que chama auth no topo)
- `where: { id: formData.get('userId') }` com ID do cliente
- Mutação destrutiva (`delete`, `updateMany`) sem escopo por `session.user.id`

CSRF: Next (14+) mitiga origem em Server Actions; com proxy/CDN/multi-zones revisar `serverActions.allowedOrigins` no `next.config` **da versão instalada** (path `experimental` vs top-level varia por major — ler o arquivo real do projeto).

### Route Handlers (`app/api/**/route.ts`)

```ts
import { auth } from '@/lib/auth'
import { NextResponse } from 'next/server'

export const GET = auth(async function GET(request) {
  if (!request.auth) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const clinicId = request.auth.user?.id
  // usar clinicId da sessão — evitar clinicId de query para autorização

  // ...
}) as any // 'as any' é tipagem, não segurança — não reportar só por isso
```

Sinais de problema:

- `export async function GET` sem `auth` em rota que retorna dados privados
- `req.nextUrl.searchParams.get('clinicId')` usado em `where` sem igualar à sessão
- Aceitar `POST` em rota que deveria ser só leitura

### Proxy / Middleware na borda (opcional)

Convenção depende do **major do `next` instalado** — ver `refs/proxy-middleware.md`.

```ts
// Next < 16 — middleware.ts
export { auth as middleware } from '@/lib/auth'
export const config = { matcher: ['/dashboard/:path*'] }

// Next ≥ 16 — proxy.ts (middleware.ts deprecated)
export { auth as proxy } from '@/lib/auth'
export const config = { matcher: ['/dashboard/:path*'] }
```

- Ausência de **`middleware.ts`** em Next **≥ 16** → procurar **`proxy.ts`** antes de concluir “sem borda”
- Ausência de ambos **não** implica vulnerabilidade se auth está em handlers/actions/layouts
- Proxy **não** substitui auth em Server Actions (checks otimistas / redirect apenas)

### Rotas públicas vs painel

- `app/(public)/**` — dados expostos intencionalmente; revisar **o que** vaza, não “falta login”
- `app/(panel)/**` — exigir sessão no layout **e** revalidar na API/action (defesa em profundidade)

### RSC e cache

- Não confundir `export const dynamic = 'force-dynamic'` com falha de segurança
- Dados sensíveis em props de Client Component — minimizar campos serializados (ver AGENTS.md do projeto)

---

## Auth.js (NextAuth v5)

```ts
export const { handlers, signIn, signOut, auth } = NextAuth({
  adapter: PrismaAdapter(prisma),
  providers: [GitHub, Google],
  // AUTH_SECRET obrigatório em produção (env)
})
```

| Verificar | Notas |
|-----------|--------|
| `AUTH_SECRET` / `NEXTAUTH_SECRET` | Forte, só env |
| `trustHost: true` | Comum em Vercel; não é achado isolado |
| Session em Server Component | `const session = await auth()` + redirect se null |
| API | Wrapper `auth(handler)` ou checagem manual |

**IDOR típico:** `prisma.appointment.findMany({ where: { userId: params.id } })` com `params.id` da URL em rota autenticada — corrigir para `session.user.id`.

---

## Prisma 7

- Preferir queries tipadas; validar UUIDs/strings com Zod antes do `where`
- Segundo ordem: dados maliciosos **armazenados** e exibidos depois (stored XSS), não SQLi
- `src/generated/prisma` — **não** auditar como código manual

---

## Stripe (webhooks)

```ts
import Stripe from 'stripe'

const event = stripe.webhooks.constructEvent(
  body,           // raw string/Buffer — não JSON parseado antes
  signature,
  process.env.STRIPE_WEBHOOK_SECRET!
)
// só após sucesso: atualizar subscription, etc.
```

Sem `constructEvent` → **HIGH**.  
Confiar só em `metadata.userId` sem reconciliar com Stripe → **MEDIUM/HIGH** conforme impacto.

---

## Zod + react-hook-form

- Server Actions devem usar `schema.parse` / `safeParse` no servidor — validação só no cliente não conta
- `z.coerce.number()` em IDs — garantir inteiros positivos e ownership depois

---

## `next.config` — headers (CSP, HSTS)

Não tratar ausência de `headers()` como falha de segurança grave. Ver **`refs/security-headers.md`**:

- Severidade máxima **INFO** (confiança **LOW**) se só faltar CSP/HSTS no config
- HSTS pode estar no CDN (Vercel, Cloudflare) — não visível no repo
- Não propor snippet de outra major do Next; CSP quebra Auth.js, Stripe.js, Tailwind e scripts do Next na versão instalada

---

## Express (só se existir `server.js` / API legada)

Não é o padrão deste monorepo; se aparecer:

- `helmet()`, limite de body, CORS restrito
- Nunca `cors({ origin: '*' })` com credenciais

---

## Arquivos sensíveis e `.gitignore`

Rodar verificação de presença **e** rastreamento Git (ver `refs/secrets.md`).

Reportar se `.env` ou chaves aparecem em `git ls-files` mesmo com `.gitignore` (commit acidental).

---

## Integração com outras refs

| Tema | Arquivo |
|------|---------|
| Versões instaladas / gates | `refs/project-stack.md` |
| O que não reportar | `refs/false-positives.md` |
| Roteiro Next | `refs/nextjs-checklist.md` |
| Segredos | `refs/secrets.md` |
| CSP / HSTS | `refs/security-headers.md` |
| Proxy vs middleware | `refs/proxy-middleware.md` |
| Relatório | `refs/report.md` |
