# Desafio de Segurança: Niffler's Key

## Como Executar

### Executando Localmente

1. **Clone o repositório:**

   ```bash
   git clone <URL_DO_REPOSITÓRIO>
   cd <NOME_DO_DIRETÓRIO>
   ```

2. **Instale as dependências:**

   ```bash
   pip install -r requirements.txt
   ```

3. **Execute a aplicação:**

   ```bash
   uvicorn main:app --reload
   ```

4. **Acesse a aplicação:**

   Abra o navegador e vá até: [http://127.0.0.1:8000](http://127.0.0.1:8000)

### Executando com Docker

1. **Construa a imagem Docker:**

   ```bash
   docker build -t vulnerable-app .
   ```

2. **Execute o container:**

   ```bash
   docker run -d -p 8000:8000 vulnerable-app
   ```

3. **Acesse a aplicação:**

   Abra o navegador e vá até: [http://localhost:8000](http://localhost:8000)