# SÓ DESENVOLVIMENTO — Postgres 18 + pgaudit (spec 13 §0 L3). Sem outras extensões.
# O repositório PGDG já vem configurado na imagem oficial; versão do pacote fixada.
FROM postgres:18.1
ARG PGAUDIT_VERSION=18.1-1.pgdg13+1
RUN apt-get update \
 && apt-get install -y --no-install-recommends "postgresql-18-pgaudit=${PGAUDIT_VERSION}" \
 && rm -rf /var/lib/apt/lists/*
