---
name: security-audit
description: 'Auditoria de segurança multi-projeto para Next.js e React — usa versões instaladas (package.json + lockfile), npm audit, Auth.js, Prisma, Stripe quando presentes. Anti-falso-positivo. Use em "auditar segurança", XSS, IDOR, Server Actions, ou "/security-audit [path]".'
---

# Security Audit (React / Next.js / TypeScript)

Scanner orientado a **pesquisador de segurança**: contexto, fluxo de dados e mitigações do **framework na versão que o projeto realmente usa** — não uma versão fixa global.

**Idioma do relatório:** português (termos OWASP/CVE podem ficar em inglês).

**Multi-repo:** cada execução começa lendo o `package.json` e lockfile **do repositório (ou subpath) auditado**. Funciona em Next 14–16+, React 18–19+, com ou sem Prisma/Stripe/Auth.js.

## Princípios

1. **Versão instalada > última lançada** — auditar CVEs e APIs na versão do lockfile; “há versão mais nova” é só **INFO** sem advisory
2. **Evidência > padrão** — não reportar só por `dangerouslySetInnerHTML`, ausência de `middleware.ts` **em Next 16+** (usar `proxy.ts` — `refs/proxy-middleware.md`), ou CSP/HSTS ausente em `next.config`
3. **Rastrear imports** — auth em helpers (`auth()`, wrappers, `canPermission`)
4. **Auto-verificação** — `refs/false-positives.md` em todo achado
5. **Patches só como proposta** — nunca aplicar no repo automaticamente

## Fluxo de execução (ordem fixa)

### Step 1 — Escopo, stack e versões

1. Path informado → só esse escopo; senão → raiz do projeto (respeitar monorepo)
2. **Obrigatório:** `refs/project-stack.md` — versões instaladas, router, deps presentes
3. Comandos recomendados:
   ```bash
   npm ls next react react-dom --depth=0
   ```
   Lockfile: `package-lock.json` | `pnpm-lock.yaml` | `yarn.lock`
4. Opcional (INFO no relatório):
   ```bash
   npm view next version && npm view react version
   ```
5. Aplicar gates de major (Next 14/15/16, React 18/19) de `project-stack.md` §4–5; se Next ≥ 16 → `refs/proxy-middleware.md`
6. Carregar `refs/language.md` + mapear superfície em `refs/nextjs-checklist.md` §1

### Step 2 — Dependências do projeto atual

```bash
npm audit --omit=dev
```

- CVE/GHSA apenas para pacotes **deste** lockfile
- Versão citada = **instalada**, não range do `package.json`
- Sem CVE → no máximo **INFO** (upgrade opcional)
- Não reportar devDependencies sem uso em runtime

### Step 3 — Segredos e exposição

- `refs/secrets.md`
- `git ls-files` para arquivos sensíveis **tracked**
- CI/CD, `next.config`, Docker

### Step 4 — Scan profundo (código)

`refs/nextjs-checklist.md` — marcar itens conforme deps detectadas (ex.: sem Stripe → pular webhook).

| Categoria   | Foco                                                  |
| ----------- | ----------------------------------------------------- |
| Injeção     | Prisma/Drizzle raw, XSS real, SSRF                    |
| AuthZ/AuthN | Server Actions, `route.ts`, BOLA/IDOR, sessão         |
| Dados       | PII em logs/API, rotas públicas                       |
| Crypto      | tokens fracos, hash obsoleto                          |
| Lógica      | webhooks, race, rate limit                            |
| Config      | `NEXT_PUBLIC_*`, `allowedOrigins` (proxy); CSP/HSTS só via `refs/security-headers.md` |

**Não** auditar Python/Java/Go salvo pedido explícito.

### Step 5 — Fluxo entre arquivos

Entrada → validação → auth → autorização → sink (DB, fetch, HTML, fs, pagamentos).

Next ≥15: página protegida **não** substitui auth na Server Action.

### Step 6 — Anti-falso-positivo

`refs/false-positives.md` — descartar ou rebaixar; listar descartes no relatório.

### Step 7 — Relatório

`refs/report.md` — incluir bloco **Stack detectado** de `project-stack.md` §8.

### Step 8 — Patches (CRITICAL e HIGH)

Before/after; frase: **"Revise cada patch antes de aplicar. Nada foi alterado no repositório."**

**Não** incluir patches de CSP/HSTS genéricos em `next.config` (hardening opcional → texto INFO em `refs/security-headers.md` §7, não Patch Proposals).

## Guia de severidade

| Nível    | Significado                                                      |
| -------- | ---------------------------------------------------------------- |
| CRITICAL | Exploração imediata (SQLi, RCE, bypass auth, secret live no Git) |
| HIGH     | Exploit claro (IDOR, XSS stored, webhook sem assinatura)         |
| MEDIUM   | Condições ou encadeamento (CSRF em proxy mal configurado)        |
| LOW      | Boas práticas pontuais                                           |
| INFO     | Sem CVE; versão atrás da latest; CSP/HSTS não custom no Next config |

## Regras de saída

- Tabela resumo primeiro
- Achados por **categoria**
- Path + linha + snippet
- **Stack detectado (instalado)** sempre no cabeçalho
- Comparar com latest só em INFO
- Falsos positivos descartados quando houver

## Referências

| Arquivo                    | Uso                                    |
| -------------------------- | -------------------------------------- |
| `refs/project-stack.md`    | Step 1 — versões e gates (obrigatório) |
| `refs/language.md`         | Padrões JS/TS/React/Next por major     |
| `refs/nextjs-checklist.md` | Steps 4–5                              |
| `refs/secrets.md`          | Step 3                                 |
| `refs/false-positives.md`  | Step 6                                 |
| `refs/security-headers.md` | CSP/HSTS — não patch genérico cross-version |
| `refs/proxy-middleware.md` | Next ≥ 16: `proxy.ts`; Next &lt; 16: `middleware.ts` |
| `refs/report.md`           | Step 7                                 |

## Documentação externa (por versão instalada)

Se precisar confirmar comportamento de segurança, consultar docs da **versão do projeto** (Context7: `/vercel/next.js` ou `/vercel/next.js/v<major>.<minor>.<patch>` mais próxima).

## Atalhos grep (pistas, não achados)

```
dangerouslySetInnerHTML
$queryRawUnsafe
Prisma.sql
'use server'
export const GET = auth
proxy.ts
middleware.ts
constructEvent
sk_live_
```

Confirmar contexto antes de reportar.
