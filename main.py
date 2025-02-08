from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
import sqlite3
import base64
import os
from token_cipher import TokenCipher
from pydantic import BaseModel
from random import randint
import time
import json
app = FastAPI()
DATABASE = "database.db"

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if request.method != "GET":
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return JSONResponse(status_code=401, content={"detail": "Token de autenticação não fornecido"})
        token_parts = auth_header.split()
        if len(token_parts) != 2 or token_parts[0] != "Bearer" or token_parts[1] != "dashheitchforthewin":
            return JSONResponse(status_code=401, content={"detail": "Token de autenticação inválido"})
    response = await call_next(request)
    return response

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS keys (
       id INTEGER PRIMARY KEY,
       encryption_key TEXT NOT NULL
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
       id INTEGER PRIMARY KEY,
       username TEXT NOT NULL,
       info TEXT
    )
    """)
    c.execute("SELECT COUNT(*) as count FROM keys")
    row = c.fetchone()
    if row["count"] == 0:
        import secrets
        key = ''.join(secrets.choice("0123456789abcdef") for _ in range(64))
        c.execute("INSERT INTO keys (encryption_key) VALUES (?)", (key,))
    c.execute("SELECT COUNT(*) as count FROM users")
    row = c.fetchone()
    if row["count"] == 0:
        mock_users = [
            ("demo", "[SUA_FLAG_ESTARA_AQUI]"),
            ("usuario_mock1", "Informação de teste 1"),
            ("usuario_mock2", "Informação de teste 2"),
            ("usuario_mock3", "Informação de teste 3")
        ]
        for user in mock_users:
            c.execute("INSERT INTO users (username, info) VALUES (?, ?)", user)
    conn.commit()
    conn.close()

@app.on_event("startup")
def startup():
    init_db()

@app.get("/vulnerable")
def vulnerable(token: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT encryption_key FROM keys where id = 1 limit 1")
    key_row = c.fetchone()
    if not key_row:
        raise HTTPException(status_code=500, detail="Chave de criptografia não encontrada")
    encryption_key = key_row["encryption_key"]
    conn.close()
    cipher = TokenCipher(encryption_key)
    decrypted = None
    try:
        decrypted = cipher.decrypt(token)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Falha na descriptografia do token: " + str(e))
    if decrypted is None:
        raise HTTPException(status_code=400, detail="Falha na recuperação do conteúdo do token")
    if isinstance(decrypted, str):
        decrypted = json.loads(decrypted)
    conn = get_db_connection()
    c = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{decrypted['payload']}'"
    try:
        c.execute(query)
        user = c.fetchone()
        if user:
            return {"user": ""}
        else:
            raise HTTPException(status_code=400, detail="Usuário não encontrado")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Erro na consulta SQL: " + str(e))

class ValidateRequest(BaseModel):
    payload: str

@app.post("/validate")
def validate_token(request: ValidateRequest):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT encryption_key FROM keys where id = 1 limit 1")
    key_row = c.fetchone()
    if not key_row:
        conn.close()
        raise HTTPException(status_code=500, detail="Chave de criptografia não encontrada")
    encryption_key = key_row["encryption_key"]
    payload = request.payload
    conn.close()
    cipher = TokenCipher(encryption_key)
    try:
        content = cipher.decrypt(payload)
        if content["payload"] == "a_forca_bruta_faz_e_bruta_mesmo":
            return {"valid": True, "detail": "Token é válido"}
        else:
            raise HTTPException(status_code=500, detail="Token inválido")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Token inválido: " + str(e))

@app.get("/list-keys")
def listar_chaves():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, encryption_key FROM keys ORDER BY encryption_key ASC")
    rows = c.fetchall()
    chaves_truncadas = [{"id": row["id"], "key": base64.b64encode((row["encryption_key"][32:]).encode()).decode()} for row in rows]
    conn.close()
    return {"keys": chaves_truncadas}

class KeyRequest(BaseModel):
    key: str

@app.post("/add-key")
def adicionar_chave(request: KeyRequest):
    if not set(request.key).issubset("0123456789abcdef") or len(request.key) != 64:
        raise HTTPException(status_code=400, detail="Formato ou tamanho da chave inválido")
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO keys (encryption_key) VALUES (?)", (request.key,))
        conn.commit()
        key_id = c.lastrowid
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail="Erro ao inserir chave: " + str(e))
    conn.close()
    return {"detail": "Chave inserida com sucesso", "id": key_id}