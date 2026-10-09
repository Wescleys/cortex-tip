# Falsos positivos — não reportar sem evidência

Carregar este arquivo no **Step 6 (Self-Verification)**. Um achado só entra no relatório se passar por estas regras.

---

## Regra geral

Antes de reportar, responder **sim** a todas:

1. Existe **caminho de exploit** plausível (não só “padrão suspeito”)?
2. A entrada é **controlada pelo atacante** (request, upload, header, query param, body)?
3. Não há **sanitização/validação/auth** no mesmo request ou em proxy/middleware upstream?
4. O código está em **caminho de produção** (não storybook, mock, teste, `.agents/`, `node_modules/`)?

Se qualquer resposta for “não” ou “incerto” → **descartar** ou marcar **LOW + confiança LOW** como “revisão manual”.

---

## React / JSX

| Padrão | Por que NÃO é achado automático |
|--------|----------------------------------|
| `dangerouslySetInnerHTML` com HTML de **constantes**, tema, ou CSS gerado de `config` interno (ex.: shadcn `chart.tsx`) | Sem input do usuário no `__html` |
| `dangerouslySetInnerHTML` com conteúdo de CMS **já sanitizado** (DOMPurify, `sanitize-html`) documentado na mesma função | Verificar import e uso na cadeia |
| Texto `{user.name}` em JSX | React escapa por padrão — **não é XSS** |
| `href={userUrl}` | Só reportar se `userUrl` vem de input **sem** validação de protocolo (`javascript:`, `data:`) |
| `target="_blank"` sem `rel="noopener noreferrer"` | **LOW** (tabnabbing), não HIGH |

**Reportar XSS** apenas quando: HTML/raw markup de fonte não confiável chega ao DOM sem escape (innerHTML, dangerouslySetInnerHTML com user/CMS, `document.write`, templates não escapados).

---

## Next.js App Router

| Padrão | Por que NÃO é achado automático |
|--------|----------------------------------|
| Server Action / Route Handler **sem** `auth()` visível no mesmo arquivo | Pode estar em wrapper, `layout.tsx`, ou helper importado — **rastrear imports** |
| `export const dynamic = 'force-dynamic'` | Preferência de cache, não vulnerabilidade |
| Uso de `cookies()` / `headers()` em Server Component | API normal do App Router |
| `revalidatePath` / `revalidateTag` após mutation | Cache invalidation esperado |
| Arquivo em `app/(public)/` | Rotas públicas **por design** — validar dados expostos, não “falta auth” |
| `middleware.ts` ausente | Next **≥ 16:** procurar **`proxy.ts`** — ver `refs/proxy-middleware.md`. Nem todo app exige borda; auth pode estar só em handlers/actions |
| “Falta middleware” em Next 16+ com `proxy.ts` presente | Descartar — convenção renomeada, não ausência de proteção |
| Sugerir criar `middleware.ts` em projeto **next ≥ 16** | Descartar patch — usar `proxy.ts` + export `proxy` |
| `next.config` sem `headers()` custom | Ver `refs/security-headers.md` — no máximo **INFO**; HSTS pode estar no CDN (Vercel, etc.) |
| Sugerir CSP/HSTS copiado de tutorial de **outra major** do Next | **Descartar** como patch — incompatível com versão instalada / quebra Stripe-OAuth-Tailwind |
| “Falta helmet” em app **só** App Router | `helmet` é padrão Express; não exigir pacote extra sem API Express no projeto |

**Reportar auth bypass** quando: mutation sensível (delete, pagamento, alteração de outro usuário) executa **sem** checagem de sessão **e** sem layout/route group protegido verificável.

---

## Auth.js (NextAuth v5)

| Padrão | Por que NÃO é achado automático |
|--------|----------------------------------|
| `trustHost: true` em produção com Vercel/host conhecido | Necessário em muitos deploys Auth.js — contexto de hosting importa |
| Session JWT vs database | Ambos válidos; checar **expiração** e **segredo** (`AUTH_SECRET`), não o adapter |
| `GET` em `/api/auth/[...nextauth]` | Handler oficial do framework |
| Página mostra `session.user.email` para usuário logado | Comportamento esperado no painel |

**Reportar** quando: `auth()` nunca é chamado em rota sensível; `session.user.id` de param/body usado em query **sem** comparar com `session.user.id`; role/plan checado só no cliente.

---

## Prisma / SQL

| Padrão | Por que NÃO é achado automático |
|--------|----------------------------------|
| `prisma.user.findMany({ where: { id } })` com `id` validado por Zod/uuid | ORM parametrizado |
| Template string em **log** ou mensagem de erro, não na query | Não é SQLi |
| `$queryRaw` / `$executeRaw` com **tagged template** `` Prisma.sql`...` `` e parâmetros | API segura do Prisma |
| `findFirst` com `userId: session.user.id` | BOLA mitigado se `userId` vem da sessão, não do cliente |

**Reportar SQLi** quando: `$queryRawUnsafe`, concatenação de string em SQL, ou `where` montado com input não validado.

---

## Segredos

| Padrão | Por que NÃO é achado automático |
|--------|----------------------------------|
| `process.env.STRIPE_SECRET_KEY` sem valor literal | Correto |
| `NEXT_PUBLIC_*` com chave **publishable** Stripe (`pk_`) | Propositalmente pública |
| Placeholders: `your-api-key`, `changeme`, `xxx`, exemplos em README | Documentação |
| `.env.example` com chaves vazias ou fake | Template |
| Arquivo `.env*` listado no Git mas **apenas** no `.gitignore` (não tracked) | OK — reportar só se **tracked** (`git ls-files`) |

**Reportar** apenas literais de alto risco: `sk_live_`, `rk_live_`, `whsec_` real, `BEGIN PRIVATE KEY`, connection strings com senha embutida.

---

## Dependências

| Padrão | Por que NÃO é achado automático |
|--------|----------------------------------|
| Versão “antiga” sem CVE associado | **INFO** no máximo |
| `npm audit` moderate em devDependency não usada em runtime | Avaliar árvore de import |
| Next.js patch atrás do latest | Atualização recomendada, não vulnerabilidade sem advisory |

**Reportar** com CVE/advisory identificado (GHSA, npm audit, OSV). Preferir `npm audit --omit=dev` para runtime.

---

## Arquivos e pastas — excluir do scan profundo

Não gastar achados em:

- `node_modules/`, `.next/`, `out/`, `build/`, `coverage/`
- `src/generated/**` (Prisma client gerado)
- `*.test.ts`, `*.spec.ts`, `__tests__/`, `e2e/` (a menos que o escopo seja só testes)
- `.agents/skills/**` (meta-documentação da skill)
- Lockfiles inteiros linha a linha (usar `npm audit` agregado)

---

## Severidade — quando rebaixar

| Situação inicial | Ajuste após verificação |
|------------------|-------------------------|
| XSS em comentário TODO | Descartar |
| IDOR se recurso é público por regra de negócio | INFO ou descartar |
| Missing CSRF em Server Action (Next 14+) | MEDIUM/INFO — framework mitiga origem; só HIGH se `allowedOrigins` mal configurado em proxy / multi-zones na versão instalada |
| Exigir `unauthorized()` com Next &lt; 16 instalado | Descartar — usar redirect/throw/401 da versão do projeto |
| Projeto “atrás da latest” sem CVE | INFO no máximo — auditoria foca versão instalada |
| `console.log` com objeto de erro em catch | LOW — só HIGH se logar senha/token/session completa |
| CORS `*` em rota **somente** de webhook com assinatura HMAC | Verificar assinatura antes de reportar CORS |
| Ausência de CSP/HSTS no `next.config.ts` isolada | **INFO** + confiança **LOW**; ver `refs/security-headers.md` — não CRITICAL/HIGH |
| `middleware.ts` legado em Next 16+ sem migração | **INFO** (deprecated), não HIGH — codemod opcional |
| Patch proposto com `headers()` não testado na major do `next` instalado | Não incluir em Patch Proposals — só nota de hardening opcional |

Documentar achados descartados na seção **“Falsos positivos descartados”** do relatório (ver `refs/report.md`).
