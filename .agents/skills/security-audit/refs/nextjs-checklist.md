# Checklist de vulnerabilidades — Next.js / React / TypeScript

Referência para **Step 4** e **Step 5**. Versões e pacotes: **`refs/project-stack.md`** (lockfile do projeto auditado).

Priorizar App Router se existir `app/` ou `src/app/`; Pages Router só se existir `pages/`.

Fontes (ajustar à major instalada): [Authentication](https://nextjs.org/docs/app/guides/authentication), [Data security](https://nextjs.org/docs/app/guides/data-security), OWASP ASVS.

---

## 1. Mapa de superfície (Step 1)

Localizar e listar no relatório:

| Tipo | Glob / padrão |
|------|----------------|
| Route Handlers | `src/app/api/**/route.ts` |
| Server Actions | arquivos com `'use server'` ou `*_actions/*.ts` |
| Server Components com dados sensíveis | `app/(panel)/**`, `dashboard/**` |
| Rotas públicas | `app/(public)/**` |
| Auth | `lib/auth.ts`, `api/auth/[...nextauth]/route.ts` |
| Webhooks | `api/webhook/**` |
| Uploads | `api/image/**`, integrações Cloudinary/S3 |
| Proxy / Middleware | Next ≥ 16: `proxy.ts`; Next &lt; 16: `middleware.ts` — `refs/proxy-middleware.md` |
| ORM | `lib/prisma.ts`, `prisma/schema.prisma` |

**Inventário dinâmico:** listar no relatório só dependências presentes (`next-auth`, `prisma`, `stripe`, `zod`, etc.) com versão do lockfile.

---

## 2. Autenticação e autorização

### Server Actions (`'use server'`)

- [ ] Auth **dentro da action**, mesmo que a página já tenha checado sessão (entry point separado — Next 14+)
- [ ] Toda mutation sensível chama `auth()` (ou helper) **no início**; `unauthorized()` se Next ≥ 16 instalado
- [ ] `userId` / `clinicId` usado em `where` vem de `session.user.id`, **não** de `formData` ou params sem validar ownership
- [ ] Inputs validados com **Zod** (ou similar) antes do Prisma
- [ ] Erros não vazam stack trace ao cliente em produção

### Route Handlers (`route.ts`)

- [ ] Método HTTP restrito quando aplicável (`GET` vs `POST`)
- [ ] Padrão Auth.js: `export const GET = auth(async function GET(req) { if (!req.auth) ... })`
- [ ] IDs de recurso na URL não substituem checagem de dono (BOLA/IDOR)

### Layouts e páginas

- [ ] Rotas `(panel)` redirecionam ou bloqueiam sem sessão
- [ ] Dados de outro tenant não retornados em `findMany` por ID vindo do cliente

### Auth.js

- [ ] `AUTH_SECRET` definido e forte (env)
- [ ] Providers OAuth com redirect URIs corretos no painel GitHub/Google
- [ ] `trustHost` justificado pelo ambiente de deploy

---

## 3. Injeção

### Prisma

- [ ] Proibir `$queryRawUnsafe` / SQL concatenado
- [ ] Preferir `findMany`, `update`, `where` tipado
- [ ] Raw queries só com `` Prisma.sql`...${param}` ``

### XSS

- [ ] `dangerouslySetInnerHTML` — ver `refs/false-positives.md`
- [ ] Conteúdo rich text: sanitizar no servidor antes de armazenar ou renderizar

### Command / path

- [ ] `child_process` com input do usuário
- [ ] `fs.readFile`/`writeFile` com path de query/body
- [ ] `fetch(userSuppliedUrl)` sem allowlist → SSRF

---

## 4. Webhooks e pagamentos (se `stripe` no package.json)

- [ ] `stripe.webhooks.constructEvent(body, signature, webhookSecret)` antes de processar
- [ ] Raw body preservado para verificação (não `JSON.parse` antes da assinatura)
- [ ] Idempotência em eventos duplicados
- [ ] Nenhuma operação financeira só por confiar em metadata sem validar customer/subscription no Stripe

---

## 5. Upload e arquivos

- [ ] Autenticação no endpoint de upload
- [ ] Validação de MIME/tamanho/extensão
- [ ] URLs de Cloudinary não permitem overwrite de pasta de outro usuário
- [ ] Sem path traversal em nomes de arquivo

---

## 6. Dados e privacidade

- [ ] Respostas JSON não expõem campos desnecessários (senha, tokens, `subscription` interna)
- [ ] `console.log` em catch não loga PII ou session inteira
- [ ] Páginas públicas (`/clinica/[id]`) só expõem dados realmente públicos

---

## 7. Configuração Next.js (versão instalada)

- [ ] `serverActions.allowedOrigins` se Next ≥15 e app atrás de proxy/CDN ou [multi-zones](https://nextjs.org/docs/app/guides/multi-zones)
- [ ] `npm audit` sem HIGH/CRITICAL ignorado; opcional: comparar com `npm view next version` → INFO se sem CVE
- [ ] Imagens remotas: `images.remotePatterns` restritivo
- [ ] Variáveis sensíveis **sem** prefixo `NEXT_PUBLIC_`
- [ ] Headers de segurança — **`refs/security-headers.md`** (`next.config`, `proxy.ts`/`middleware.ts`, host)
- [ ] Borda Next ≥ 16: não exigir `middleware.ts`; auth na borda opcional via **`proxy.ts`** — `refs/proxy-middleware.md`

---

## 8. Cliente (React)

- [ ] Segredos nunca em bundle cliente
- [ ] React Query: endpoints já autenticados no servidor; não confiar só em UI para esconder botões
- [ ] Links externos com `rel="noopener noreferrer"` quando `target="_blank"`

---

## 9. Fluxo de dados (Step 5)

Desenhar mentalmente:

```
Entrada (searchParams, params, body, headers, cookies, formData)
  → validação (Zod?)
  → auth (auth() / req.auth?)
  → autorização (ownership, plan, role)
  → sink (Prisma, fetch, HTML, fs, Stripe, Cloudinary)
```

Vulnerabilidades cross-file aparecem quando **auth** está só no layout mas a **action** é importada de outro módulo sem checagem.

---

## 10. Comandos pós-scan sugeridos no relatório

```bash
npm audit --omit=dev
npm run build
npm run lint
```

Opcional: `npx @better-auth/cli@latest` não se aplica aqui; para Auth.js revisar config em [authjs.dev](https://authjs.dev).
