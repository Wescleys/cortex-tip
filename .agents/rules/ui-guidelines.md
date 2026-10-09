# Diretrizes de Interface e Design System — Cortex TIP

1. **Sem Cores Neon ou Efeitos Brilhantes em Textos:**
   - NUNCA aplicar cores fluorescentes/neon em textos (ex: `#00e5ff`, `#00ffcc`, `#00e676`, `#00ffff`, `cyan`).
   - NUNCA aplicar `text-shadow` com brilho/glow em textos ou títulos.
   - NUNCA usar fontes chamativas com visual "gamer", "cyberpunk" ou "hacker neon".

2. **Estilo Corporativo Clean / SOC Profissional:**
   - Paleta de cores sóbria baseada em dark mode clean (estilo GitHub Dark / Datadog / Sentinel / CrowdStrike):
     - Textos principais: `#e6edf3` / `#f0f6fc`
     - Textos secundários e metadados: `#8b949e` / `#94a3b8`
     - Destaque azul informativo: `#58a6ff`
     - Alertas críticos / perigo: `#ff1744` / `#ff5252` (texto limpo, sem sombras)
     - Avisos / Médio risco: `#ff9100` / `#ffab40`
     - Sucesso / Permitido: `#3fb950` / `#69f0ae`
   - Tipografia limpa: `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif`.
   - Códigos e IPs: `'Consolas', 'Monaco', 'Courier New', monospace`.

3. **Sem Bordas e Caixas Desnecessárias em Textos:**
   - Deixar apenas o texto limpo colorido para severidades, status e tags, sem pílulas ou caixas com bordas ao redor do texto, a menos que seja estritamente um botão interativo clicável.
