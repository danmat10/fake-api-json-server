# Fake-API Usando JSON Server

Este repositório está configurado com uma fake-API personalizada usando o JSON Server. Ele apresenta autenticação de usuário por meio de JSON Web Tokens (JWT) e operações CRUD básicas nos dados armazenados em um arquivo `db.json`.

## Requisitos:

- [Node.js](https://nodejs.org/)
- [npm](https://www.npmjs.com/)

## Instruções Iniciais:

1. **Clone o Repositório:**
   ```bash
   git clone https://github.com/danmat10/fake-api-json-server.git
   cd fake-api-json-server
   
2. **Instale as Dependências:**
   ```bash
   npm install

3. **Inicie o Servidor:**
   ```bash
   node server.js

## Endpoints da API:

1. Login:
   * Endpoint: /auth/login
   * Método: POST
   * Dados:
        ```json
         {
         "login": "seu-usuario",
         "password": "sua-senha"
         }
   * Resposta:
        ```json
         {
         "access_token": "jwt-access-token",
         "refresh_token": "jwt-refresh-token"
         }

2. Refresh Token:
   * Endpoint: /auth/refresh
   * Método: POST
   * Dados:
        ```json
        {
        "refresh_token": "seu-refresh-token"
        }
   * Resposta:
        ```json
        {
        "access_token": "novo-jwt-access-token"
        }

3. Acessar Dados:
   * Para acessar os dados armazenados em db.json, você precisará incluir o JWT no cabeçalho de Autorização de sua solicitação. Os endpoints /db e /users são protegidos com a validação JWT.

## Segurança:

A API usa uma chave secreta para JWT (my-secret-key conforme mostrado no código). Certifique-se de usar uma chave secreta mais segura e complexa em produção para aumentar a segurança.

## Métodos da API:

GET    /<object>
GET    /<object>/<id>
POST   /<object>
PUT    /<object>/<id>
PATCH  /<object>/<id>
DELETE /<object>/<id>

**Bom desenvolvimento! 🚀**







