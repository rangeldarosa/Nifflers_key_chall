#!/bin/bash
# Script que será executado pelo crontab para remover arquivos de banco de dados
# que não tenham tido interação nos últimos 5 minutos.
# Os bancos de dados são identificados pelo padrão "database_*.db" no diretório corrente.

# Diretório onde os databases estão armazenados (altere se necessário)
DATABASE_DIR="."

# Encontra e deleta os arquivos cujo último acesso foi há mais de 5 minutos (300 segundos)
# O parâmetro -amin verifica o tempo de acesso em minutos.
find "$DATABASE_DIR" -maxdepth 1 -type f -name "database_*.db" -amin +5 -exec rm -f {} \;
