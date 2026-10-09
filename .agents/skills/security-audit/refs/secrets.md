# Padrões de segredos — JavaScript / TypeScript / Next.js

Usar no **Step 3 (Secrets & Exposure Scan)**. Combinar busca textual + julgamento (evitar alarme em placeholders).

---

## Comandos úteis (Node.js)

```bash
# Dependências vulneráveis (runtime)
npm audit --omit=dev

# Arquivos sensíveis rastreados pelo Git
git ls-files | findstr /i "\.env credentials \.pem \.key id_rsa"
# Linux/macOS: git ls-files | grep -E '\.(env|pem|key)$|credentials|id_rsa'
```

---

## Prefixos de alto risco (reportar se literal no código tracked)

| Prefixo / padrão | Serviço |
|------------------|---------|
| `sk_live_`, `rk_live_` | Stripe (secreto) |
| `sk_test_` em repo público | Stripe test (MEDIUM em repo privado pode ser INFO) |
| `whsec_` | Stripe webhook secret |
| `pk_live_` em arquivo **sem** `NEXT_PUBLIC_` | Stripe — possível misconfig |
| `AKIA[0-9A-Z]{16}` | AWS access key |
| `-----BEGIN (RSA \|EC \|OPENSSH )?PRIVATE KEY-----` | Chave privada |
| `xox[baprs]-` | Slack |
| `ghp_`, `gho_`, `github_pat_` | GitHub |
| `AIza[0-9A-Za-z\-_]{35}` | Google API |
| `mongodb(\+srv)?:\/\/[^:]+:[^@]+@` | MongoDB com senha na URL |
| `postgresql:\/\/[^:]+:[^@]+@` | Postgres com senha na URL |

---

## Variáveis de ambiente esperadas (se presentes no projeto)

Verificar que existem **apenas** em `.env*` (gitignored), nunca hardcoded:

- `AUTH_SECRET` / `NEXTAUTH_SECRET`
- `DATABASE_URL`
- `GITHUB_ID`, `GITHUB_SECRET`, `GOOGLE_ID`, `GOOGLE_SECRET`
- `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`
- `CLOUDINARY_*` (API secret, não só cloud name)
- Chaves de upload/imagem

`NEXT_PUBLIC_*` — só chaves **destinadas** ao browser (ex.: `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY`).

---

## Arquivos que nunca devem ser commitados

Confirmar presença no `.gitignore` **e** que não aparecem em `git ls-files`:

```
.env
.env.local
.env.production
.env.staging
*.pem
*.key
*.p12
*.pfx
id_rsa
id_ed25519
credentials.json
service-account.json
gcp-key.json
secrets.yaml
secrets.json
```

Se o padrão **não** estiver no `.gitignore` → achado **MEDIUM** (risco de commit futuro), mesmo que o arquivo não exista hoje.

---

## Onde procurar além de `src/`

- `.github/workflows/` — secrets em `env:` devem usar `${{ secrets.* }}`, não literais
- `docker-compose.yml`, `Dockerfile` — `ENV` com valores reais
- `vercel.json`, `next.config.ts` — env embutido
- Scripts em `package.json` — flags com tokens
- Comentários e strings em testes e fixtures
- Histórico Git (mencionar no relatório se achar literal: `git log -S 'sk_live_' --all`)

---

## Falsos positivos em secrets (não reportar)

- `process.env.VAR` ou `env.VAR` (Next.js `env` schema) sem fallback literal secreto
- `sk_test_...` em arquivos `.env.example` claramente fake (`xxx`, `your_key_here`)
- UUIDs genéricos sem prefixo de provedor
- Hashes bcrypt/argon em seeds de dev documentados
- Tokens em snapshots de teste com nome `mock`, `fake`, `test-token`

---

## Ações no relatório quando achar segredo real

1. Rotacionar no painel do provedor **imediatamente**
2. Remover do código; usar variável de ambiente
3. Confirmar `.gitignore`
4. Auditar histórico (`git log -p`, BFG/git-filter-repo se já foi pushado)
