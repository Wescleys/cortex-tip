# Formato do relatório — Security Audit

Usar no **Step 7**. Idioma principal: **português**. Manter termos OWASP/CVE em inglês quando padrão da indústria.

---

## Cabeçalho

```
╔══════════════════════════════════════════════════════════╗
║           🔐 RELATÓRIO DE AUDITORIA DE SEGURANÇA        ║
║           Skill: security-audit                         ║
╚══════════════════════════════════════════════════════════╝

Projeto:     <nome ou caminho>
Data:        <data da varredura>
Escopo:      <paths analisados>
Stack detectado (instalado — lockfile):
  next@<resolved>  react@<resolved>  react-dom@<resolved>
  <outras deps do projeto: next-auth, prisma, stripe, …>
Router:      App Router | Pages | híbrido
Registry (INFO, opcional): next@<latest> — Δ N patches (sem CVE → não elevar severidade)
Excluídos:   <node_modules, .next, generated, …>
```

---

## 1. Resumo executivo (obrigatório — primeiro bloco)

```
┌────────────────────────────────────────────────┐
│           RESUMO DE ACHADOS                    │
├──────────────┬─────────────────────────────────┤
│ 🔴 CRITICAL  │  <n>                           │
│ 🟠 HIGH      │  <n>                           │
│ 🟡 MEDIUM    │  <n>                           │
│ 🔵 LOW       │  <n>                           │
│ ⚪ INFO      │  <n>                           │
├──────────────┼─────────────────────────────────┤
│ TOTAL        │  <n>                           │
└──────────────┴─────────────────────────────────┘

Auditoria de dependências:  <n> pacotes com CVE / npm audit>
Scan de segredos:          <n> credenciais expostas (tracked)>
Falsos positivos descartados: <n>  (ver seção 6)
```

Se **zero** achados CRITICAL–LOW:

```
✅ Nenhuma vulnerabilidade confirmada nos critérios desta auditoria.
   Escopo: <detalhar>. Limitações: análise estática, sem DAST.
```

---

## 2. Card de achado (por categoria)

Repetir para cada vulnerabilidade **confirmada** após Step 6:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🟠 HIGH — IDOR / BOLA (Autorização)
Confiança: HIGH
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📍 Local:  src/app/api/clinic/appointments/route.ts, linha 39

🔍 Código:
  const clinicId = searchParams.get("clinicId")
  await prisma.appointment.findMany({ where: { userId: clinicId } })

⚠️  Risco:
  Um usuário autenticado pode passar outro clinicId e listar agendamentos
  de outra clínica.

  Exemplo: GET /api/...?clinicId=<uuid-vítima>

✅ Correção:
  Usar apenas request.auth.user.id da sessão, ignorar clinicId do cliente.

📚 Referência: OWASP API1:2023 — Broken Object Level Authorization
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

Campos obrigatórios por card:

- Severidade + tipo
- **Confiança:** HIGH | MEDIUM | LOW
- Local (arquivo + linha)
- Snippet real
- Risco + exemplo de abuso (se aplicável)
- Correção acionável
- Referência OWASP/CWE quando couber

---

## 3. Auditoria de dependências

```
📦 DEPENDÊNCIAS
════════════════

🟠 HIGH — <pacote>@<versão>
  Advisory: <CVE/GHSA>
  Impacto: <resumo>
  Correção: npm install <pacote>@<versão-fixa> ou npm audit fix

⚪ INFO — next@<instalado> (registry: <latest>)
  Sem CVE no npm audit; há versão mais nova — planejar upgrade em janela de manutenção.
```

Regras:

- Sem CVE confirmado → não usar HIGH/CRITICAL
- Citar saída de `npm audit` quando existir

---

## 4. Scan de segredos

```
🔑 SEGREDOS E EXPOSIÇÃO
═══════════════════════

🔴 CRITICAL — Chave Stripe live no repositório
  Arquivo: src/.../config.ts, linha 12
  Trecho: STRIPE_SECRET_KEY = "sk_live_..."

  Ações:
  1. Rotacionar em https://dashboard.stripe.com
  2. Remover do código; usar process.env.STRIPE_SECRET_KEY
  3. Confirmar .gitignore (.env*)
  4. Se já houve push: git log -S 'sk_live_' --all
```

Se nada encontrado:

```
✅ Nenhum segredo de alto risco em arquivos rastreados pelo Git.
   .gitignore: <ok / gaps listados>
```

---

## 5. Propostas de patch (CRITICAL + HIGH)

````
🛠️  PROPOSTAS DE PATCH
══════════════════════
⚠️  Revise cada patch antes de aplicar. Nada foi alterado no repositório.

─────────────────────────────────────────────
Patch 1/N: <título curto>
─────────────────────────────────────────────

ANTES (vulnerável):
```ts
// caminho:linha
...
```

DEPOIS (corrigido):
```ts
// caminho:linha — <motivo do fix>
...
```
─────────────────────────────────────────────
````

Patches devem respeitar estilo do projeto (imports `@/`, Auth.js, Prisma).

---

## 6. Falsos positivos descartados (quando aplicável)

Listar candidatos analisados no Step 6 e **por que não** viraram achado:

```
🧹 FALSOS POSITIVOS DESCARTADOS
═══════════════════════════════

• src/components/ui/chart.tsx — dangerouslySetInnerHTML
  Motivo: CSS gerado de config interna (THEMES), sem input do usuário.

• “Ausência de middleware.ts”
  Motivo: next@16+ — convenção é proxy.ts; ou auth em route handlers/layouts sem borda.
  Ver refs/proxy-middleware.md.
```

Isso aumenta confiança no relatório e evita ruído em PRs.

---

## 7. Cobertura e próximos passos

```
📋 COBERTURA
  Arquivos analisados:  <n> (aprox.)
  Tipos:               Route Handlers, Server Actions, auth, webhooks, …
  Ferramentas:         leitura estática, npm audit, git ls-files

⚡ PRÓXIMOS PASSOS
  1. Corrigir CRITICAL imediatamente
  2. HIGH no sprint atual
  3. MEDIUM/LOW no backlog
  4. Opcional: DAST, rate limiting, CSP (ver refs/security-headers.md — alinhado à versão do Next), SAST no CI

💡 Limitação: auditoria estática — não substitui teste dinâmico nem pentest.
```

---

## Guia de confiança

| Confiança | Quando usar |
|-----------|-------------|
| **HIGH** | Exploit claro; sem sanitização/auth no caminho |
| **MEDIUM** | Provável; depende de deploy, proxy ou chamador não visto |
| **LOW** | Padrão suspeito; exige revisão humana — preferir descartar ou INFO |

Nunca omitir confiança. Se LOW e não for vulnerabilidade clara → mover para **§6 Descartados** em vez de achado.

---

## Ordem das seções no output final

1. Cabeçalho  
2. Resumo executivo (tabela)  
3. Achados por categoria  
4. Dependências  
5. Segredos  
6. Patches (se CRITICAL/HIGH)  
7. Falsos positivos descartados  
8. Cobertura e próximos passos  
