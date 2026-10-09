# Proxy vs Middleware (Next.js por versão instalada)

Carregar no **Step 1** (com `refs/project-stack.md`) e ao auditar auth/headers na borda.

**Fonte:** [Proxy (Next.js 16.2+)](https://nextjs.org/docs/app/getting-started/proxy), [Upgrade v16 — middleware to proxy](https://nextjs.org/docs/app/guides/upgrading/version-16).

---

## 1. Regra por major do `next` (lockfile)

| Next instalado | Arquivo canônico | Export da função | Notas |
|----------------|------------------|------------------|--------|
| **&lt; 16** | `middleware.ts` / `.js` | `middleware` (default ou named) | Doc e exemplos usam `middleware` |
| **≥ 16** | `proxy.ts` / `.js` (preferido) | `proxy` (default ou named) | `middleware.ts` **deprecated** — migrar, não criar novo |
| **≥ 16** + `middleware.ts` ainda no repo | Legado / migração pendente | `middleware` | **INFO** “codemod `middleware-to-proxy`”, não HIGH por “nome errado” sozinho |

**Local:** raiz do projeto ou `src/`, no mesmo nível que `app/` ou `pages/` — **um único arquivo** `proxy.ts` (lógica extra em módulos importados).

---

## 2. O que NÃO reportar

| Situação (Next ≥ 16) | Motivo |
|----------------------|--------|
| “Ausência de `middleware.ts`” | Arquivo correto pode ser **`proxy.ts`** — procurar os dois nomes antes de concluir |
| “Falta middleware de auth” com `proxy.ts` + `auth` reexport | Equivalente funcional |
| Sugerir **criar** `middleware.ts` em projeto Next 16+ | Desatualizado — indicar `proxy.ts` e export `proxy` |
| Exigir Proxy para auth completa | Doc oficial: Proxy é para checks **otimistas** (redirect), não substitui auth em Server Actions / Route Handlers |

---

## 3. O que verificar na auditoria

1. `next` major em `refs/project-stack.md`
2. Existência de **`proxy.ts`** ou **`middleware.ts`** (grep / glob na raiz e `src/`)
3. Conteúdo: headers, `matcher`, redirects, reexport Auth.js (`auth as proxy` vs `auth as middleware`)
4. **Next ≥ 16:** se só existir `middleware.ts` → INFO migração; se não existir nenhum → OK se auth em layouts/handlers/actions
5. **Edge runtime:** em Next 16, `proxy` usa runtime **nodejs** (não configurável). Projetos que **precisam Edge** podem manter `middleware.ts` — **INFO**, não vulnerabilidade

```bash
# Codemod oficial (mencionar só como sugestão INFO, não aplicar automaticamente)
npx @next/codemod@latest middleware-to-proxy .
```

---

## 4. Auth.js / NextAuth

Padrões comuns (adaptar ao major do Next):

```ts
// Next < 16 — middleware.ts
export { auth as middleware } from '@/lib/auth'

// Next ≥ 16 — proxy.ts (quando migrado)
export { auth as proxy } from '@/lib/auth'
```

Se o projeto está em Next 16+ mas ainda usa `export { auth as middleware }` em `middleware.ts` → **INFO** (convenção deprecated), não bypass de auth, desde que o arquivo rode.

**Auth real** continua obrigatória em Server Actions e `route.ts` — Proxy não substitui.

---

## 5. Headers de segurança na borda

Em Next ≥ 16, headers em `proxy.ts` substituem o papel que a skill citava em `middleware.ts`.

Ver também `refs/security-headers.md` — mesma cautela (INFO, versão, CDN).

```ts
// Exemplo conceitual — não colar sem testar na versão instalada
export function proxy(request: NextRequest) {
  const response = NextResponse.next()
  response.headers.set('X-Frame-Options', 'DENY')
  return response
}
```

---

## 6. Texto modelo — falso positivo descartado

```
• “Ausência de middleware.ts”
  Motivo: next@16.x — convenção renomeada para proxy.ts; arquivo não encontrado
  mas auth em route handlers / layouts verificado. Ver refs/proxy-middleware.md.
```

---

## 7. Texto modelo — INFO migração

```
⚪ INFO — middleware.ts em projeto Next 16+

  next@<instalado> — middleware.ts ainda presente; Next 16 depreca em favor de proxy.ts
  e export `proxy`. Funcionalidade equivalente; considerar codemod middleware-to-proxy.
  Confiança: LOW
```

---

## 8. Integração

| Arquivo | Uso |
|---------|-----|
| `refs/project-stack.md` | Major do Next |
| `refs/false-positives.md` | Não exigir middleware.ts em Next 16+ |
| `refs/security-headers.md` | Headers em proxy/middleware |
| `refs/language.md` | Exemplos Auth por versão |
