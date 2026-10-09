# Stack do projeto — versões instaladas (multi-repo)

**Regra:** cada auditoria usa o **projeto aberto**, não uma versão fixa global. A skill serve qualquer app Next.js + React.

Carregar no **Step 1** antes de `language.md` e `nextjs-checklist.md`.

---

## 1. Onde ler versões (ordem de prioridade)

| Fonte                                                | Uso                                                         |
| ---------------------------------------------------- | ----------------------------------------------------------- |
| `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` | Versão **efetivamente instalada** (preferir para auditoria) |
| `package.json` → `dependencies` / `devDependencies`  | Intervalo semver (`^`, `~`) — só se lockfile ausente        |
| `node_modules/next/package.json` → `version`         | Confirmação local (opcional)                                |

Registrar no relatório como **Stack detectado (instalado)**, não “versão que a skill espera”.

Comandos úteis:

```bash
# Versões instaladas (npm)
npm ls next react react-dom next-auth prisma @prisma/client stripe --depth=0

# Última publicada no registry (apenas comparação INFO — opcional)
npm view next version
npm view react version
```

**Foco da auditoria:** comportamento e CVEs da versão **instalada**.  
**Última lançada:** só **INFO** (“há patch mais novo”), nunca CRITICAL/HIGH só por estar desatualizado sem advisory.

---

## 2. Pacotes a inventariar sempre

Extrair versão instalada quando presente:

| Pacote                                   | Impacto na auditoria                                     |
| ---------------------------------------- | -------------------------------------------------------- |
| `next`                                   | App Router, Server Actions, `proxy`/`middleware`, config |
| `react`, `react-dom`                     | XSS, RSC, Client Components                              |
| `next-auth` / `@auth/*`                  | Auth.js v5                                               |
| `prisma`, `@prisma/client`               | SQLi, raw queries                                        |
| `stripe`                                 | Webhooks                                                 |
| `@supabase/*`, `drizzle-orm`, `mongoose` | ORM alternativo                                          |
| `zod`, `yup`, `valibot`                  | Validação server-side                                    |
| `@tanstack/react-query`                  | Não substitui auth no servidor                           |
| `cloudinary`, `@aws-sdk/*`               | Upload / storage                                         |
| `express`, `fastify`                     | API legada no mesmo monorepo                             |

Listar no relatório apenas o que existir no `package.json`.

---

## 3. Detectar “formato” do Next (filesystem)

Não assumir `src/app/` — adaptar paths:

```
app/ ou src/app/     → App Router
pages/ ou src/pages/ → Pages Router (checklist legado)
middleware.ts (Next &lt; 16) ou proxy.ts (Next ≥ 16) → raiz ou src/ — ver refs/proxy-middleware.md
next.config.ts/js/mjs
```

**App Router** se existir `app/**/page.tsx` ou `src/app/**/page.tsx`.  
**Pages Router** adicional se existir `pages/**` — auditar rotas `pages/api` separadamente.

---

## 4. Regras por major do Next (instalado)

Usar `semver` mental: major de `next` no lockfile.

| Next (major) | Checklist extra                                                                                                                                                                                                                                         |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|              |
| **14+**      | Server Actions estáveis; partial prerender — não confundir com falha de auth                                                                                                                                                                            |
| **15+**      | Reforço CSRF/origem em Server Actions; revisar `next.config` do projeto                                                                                                                                                                                 |
| **16+**      | `unauthorized()` / `forbidden()`; [data security](https://nextjs.org/docs/app/guides/data-security); **`middleware` → `proxy`** ([Proxy](https://nextjs.org/docs/app/getting-started/proxy)) — não reportar “falta middleware.ts” sem buscar `proxy.ts` |

Links de documentação: usar major instalado quando consultar Context7, ex. `/vercel/next.js/v16.2.2` ou doc genérica `/vercel/next.js` se versão exata não existir.

---

## 5. Regras por major do React (instalado)

| React (major) | Notas                                                       |
| ------------- | ----------------------------------------------------------- |
| **18+**       | RSC, `use server` boundaries                                |
| **19+**       | Mesmos sinks XSS; React Compiler opcional — não altera auth |

Peer do Next: se `npm ls` mostrar mismatch react/next (warn de peer), registrar **INFO** — risco de build/runtime, não vulnerabilidade automática.

---

## 6. Auth.js / NextAuth

| Pacote                           | Padrão                                                   |
| -------------------------------- | -------------------------------------------------------- |
| `next-auth@5` / `next-auth@beta` | Auth.js: `auth()`, `handlers`, `auth(handler)`           |
| `next-auth@4`                    | `getServerSession`, `[...nextauth]` Pages — checklist v4 |

Detectar por import: `from "next-auth"` vs `from "@/lib/auth"` — seguir implementação do repo.

---

## 7. Dependências (Step 2) — escopo do projeto atual

```bash
npm audit --omit=dev
# ou: pnpm audit / yarn npm audit
```

- CVEs só para pacotes **no lockfile deste repo**
- Correlacionar advisory com **versão instalada**, não com “latest”
- Upgrade sugerido: mesma major quando possível; major bump = nota de breaking no patch proposal

Pacotes críticos frequentes (auditar se instalados):

`next`, `react`, `react-dom`, `next-auth`, `jsonwebtoken`, `cookie`, `sharp`, `ws`, `path-to-regexp`, `prisma`, `stripe`, `postcss`, `esbuild` (via toolchain)

---

## 8. Bloco obrigatório no relatório (copiar valores reais)

```
Stack detectado (instalado):
  next@<lockfile>
  react@<lockfile> / react-dom@<lockfile>
  <outras deps relevantes>

Router: App Router | Pages | híbrido
Auth: Auth.js v5 | NextAuth v4 | outro | ausente
ORM: Prisma <n> | Drizzle | …

Última versão registry (opcional, INFO):
  next@<npm view>  react@<npm view>
  Δ: <behind/ahead> — sem CVE → não elevar severidade
```

---

## 8b. Headers (CSP / HSTS)

Não auditar como gap crítico só porque `next.config` não define `headers()`. Seguir **`refs/security-headers.md`**: severidade máxima INFO/LOW, patches de CSP condicionados à **versão instalada** de `next` e às integrações do `package.json`.

---

## 9. O que NÃO fazer

- Não auditar como se o projeto fosse Next 16 se o lockfile diz 14.x
- Não exigir `unauthorized()` se Next &lt; 16
- Não reportar HIGH por “Next desatualizado” sem CVE/advisory
- Não propor `headers()` / CSP de exemplo de outra major do Next sem validar compatibilidade
- Não hardcodar Stripe/Prisma/Cloudinary se o projeto não usa
- Não misturar `package.json` de um monorepo workspace sem escopo (`/security-audit apps/web`)

---

## 10. Monorepos

Se o usuário passar path (`apps/web`):

- Ler `package.json` **desse** workspace
- `npm audit` na raiz do workspace ou do monorepo conforme onde está o lockfile
- Mapear `app/` relativo ao package escolhido
