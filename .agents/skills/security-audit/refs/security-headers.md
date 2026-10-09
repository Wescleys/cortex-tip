# Headers de segurança (CSP, HSTS, etc.) — cautela por versão e deploy

Carregar no **Step 4** ao revisar `next.config.*`, `proxy.ts` / `middleware.ts` (conforme major do Next — `refs/proxy-middleware.md`), `vercel.json`, ou “falta CSP/HSTS”.

**Regra de ouro:** ausência de `headers()` custom em `next.config.ts` **não é vulnerabilidade** por si só. No máximo **INFO**, com ressalvas de versão e hosting.

---

## 1. O que verificar ANTES de sugerir qualquer header

| Ordem | Onde olhar                                                                                                                    |
| ----- | ----------------------------------------------------------------------------------------------------------------------------- |
| 1     | Versão **instalada** de `next` (`refs/project-stack.md`)                                                                      |
| 2     | `next.config.ts` / `.js` / `.mjs` **do projeto** (não template de outra versão)                                               |
| 3     | `proxy.ts` (Next ≥ 16) ou `middleware.ts` (Next &lt; 16) — headers na resposta |
| 4     | `vercel.json`, `netlify.toml`, `nginx.conf`, Cloudflare dashboard (mencionar no relatório se não estiver no repo)             |
| 5     | Dependências que **quebram** com CSP rígido: Stripe.js, OAuth (GitHub/Google), Cloudinary, analytics, Recharts, `next/script` |

Nunca colar bloco `headers()` copiado da documentação de **outra major** do Next sem validar sintaxe e comportamento da versão do lockfile.

---

## 2. Severidade permitida

| Achado                                                                                         | Severidade máxima | Confiança típica                                                 |
| ---------------------------------------------------------------------------------------------- | ----------------- | ---------------------------------------------------------------- |
| Sem `Content-Security-Policy` custom no `next.config`                                          | **INFO**          | LOW                                                              |
| Sem `Strict-Transport-Security` no `next.config`                                               | **INFO** (ver §3) | LOW                                                              |
| Sem `X-Frame-Options` / `frame-ancestors`                                                      | **LOW**           | LOW — salvo app financeiro/admin em iframe                       |
| CSP **permissiva** (`unsafe-inline`, `*`) em app com dados sensíveis                           | **MEDIUM**        | MEDIUM — se XSS real também existir, não inflar só por CSP fraca |
| Header **ativo e errado** (ex.: `Access-Control-Allow-Origin: *` + cookies em API autenticada) | **HIGH**          | HIGH — isso sim é misconfig exploitável                          |

**Proibido:** CRITICAL/HIGH **somente** por “não tem CSP no next.config”.

---

## 3. HSTS — não exigir em `next.config` à cegas

- **Vercel / muitos CDNs** aplicam HSTS na borda em produção HTTPS — ausência no `next.config` é **normal**.
- **Desenvolvimento local** (`next dev`) não deve receber HSTS agressivo sem necessidade.
- Se o relatório mencionar HSTS: indicar **“confirmar no painel do host/CDN”**, não só “adicione ao next.config”.

---

## 4. CSP e Next.js — por que sugestões genéricas falham

CSP estrita costuma quebrar:

- Scripts inline do Next (hydration, RSC payloads em algumas versões)
- `style` inline (Tailwind, libraries UI)
- OAuth redirects (Auth.js / `next-auth` providers)
- `https://js.stripe.com`, `https://hooks.stripe.com` (webhooks são server-side; **Stripe.js** no cliente precisa de domínios na CSP)
- Imagens: `res.cloudinary.com`, `lh3.googleusercontent.com`, `avatars.githubusercontent.com` — alinhar com `images.remotePatterns` já no config
- `next/font`, `next/script` com `strategy`

**Ao sugerir CSP (só se usuário pedir hardening ou INFO detalhado):**

1. Citar **next@&lt;versão instalada&gt;** no texto da recomendação
2. Propor rollout **gradual** (report-only → nonce/hash → enforce)
3. Listar domínios já usados no projeto (grep `https://`, providers em `auth.ts`, Stripe, Cloudinary)
4. Avisar: **testar `npm run build && npm start`** — CSP quebra produção sem aparecer em dev
5. Alternativa mais segura em muitos apps: CSP no **reverse proxy/CDN**, não duplicar mal no `next.config`

---

## 5. API de `headers` no `next.config` — depende da versão

A forma canônica evoluiu entre majors (Pages vs App Router, `async headers()`, tipos `NextConfig`).

**Antes de propor código:**

- Ler [headers config](https://nextjs.org/docs/app/api-reference/config/next-config-js/headers) compatível com a **major instalada** (Context7: `/vercel/next.js` + versão do lockfile)
- Confirmar se o projeto usa **App Router** (`app/`) — exemplo Pages Router de tutoriais antigos **não** aplicar
- `next.config.ts` com `satisfies NextConfig` / `import type { NextConfig }` — manter o estilo do arquivo existente

**Não sugerir** `experimental` ou chaves removidas na versão instalada (ex.: opções que migraram de `experimental` para top-level no Next 15+ — checar o arquivo real e a doc da mesma major).

---

## 6. Onde headers podem já existir (não reportar “ausência”)

| Fonte           | Exemplos                                                                         |
| --------------- | -------------------------------------------------------------------------------- |
| Plataforma      | Vercel security headers, Cloudflare managed rules                                |
| `proxy.ts` / `middleware.ts` | Redirects otimistas, headers na borda (ver versão do Next) |
| Route Handler   | `NextResponse` com headers pontuais                                              |
| Meta / React 19 | Alguns hints de recurso — não substituem CSP completa, mas não é “zero proteção” |

Se não estiver no repositório, escrever no relatório: _“Headers na borda não auditáveis neste scan estático.”_

---

## 7. Texto modelo para relatório (INFO)

Use quando quiser registrar hardening sem alarme:

```
⚪ INFO — Headers de segurança custom (next.config / proxy ou middleware)

  next@<instalado> — next.config.ts sem função headers() para CSP/HSTS.
  HSTS pode estar no CDN/host (Vercel, etc.) — não verificável só pelo repo.
  CSP custom em Next exige allowlist por versão e por integrações (Auth.js, Stripe, …);
  não recomendado copiar snippet de outra versão do Next sem teste de build/prod.

  Próximo passo (opcional): definir política no CDN ou CSP report-only após inventariar scripts externos.
  Confiança: LOW
```

---

## 8. Quando ESCALAR além de INFO

Subir para **MEDIUM+** apenas se houver evidência combinada:

- XSS stored/reflected **confirmado** + CSP ausente ou `unsafe-inline` em páginas autenticadas
- API com cookies de sessão + `Access-Control-Allow-Origin: *` + `credentials` (ver CORS, não só CSP)
- `X-Frame-Options: ALLOWALL` ou equivalente em rotas de pagamento/admin

---

## 9. Integração com falsos positivos

Entradas relacionadas em `refs/false-positives.md` § Next.js e § Severidade — aplicar **ambos** antes de publicar o achado.
