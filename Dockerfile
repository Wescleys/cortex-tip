# ==============================================================================
# Cortex TIP - Dockerfile Multi-Stage (Proteção de Código & Produção)
# ==============================================================================

# Estágio 1: Build e Compilação
FROM python:3.13-slim AS builder

WORKDIR /app

# Instala dependências de compilação
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Copia o código da aplicação
COPY . .

# Compila todos os arquivos Python para bytecode binário (.pyc) e remove o código-fonte (.py)
RUN python -m compileall -b -q . && \
    find . -name "*.py" -type f -delete && \
    rm -rf scratch .agents .git tests

# Estágio 2: Imagem Final Leve e Protegida
FROM python:3.13-slim

WORKDIR /app

# Instala tzdata para sincronização nativa de fuso horário
RUN apt-get update && apt-get install -y --no-install-recommends tzdata && rm -rf /var/lib/apt/lists/*

# Copia pacotes instalados do estágio builder
COPY --from=builder /install /usr/local

# Copia aplicação compilada (apenas .pyc, templates e static)
COPY --from=builder /app /app

# Cria usuário não-root para execução segura
RUN useradd -m -u 1000 cortexuser && \
    mkdir -p /app/logs /app/cache && \
    chown -R cortexuser:cortexuser /app

USER cortexuser

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=America/Sao_Paulo \
    PORT=80

EXPOSE 80

# Inicia a aplicação protegida via bytecode
CMD ["python", "cortex.pyc"]
