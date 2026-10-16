# 🛡️ SafePass — Zero-Knowledge Password Manager & Chrome Extension

<div align="center">

[![ORCID](https://img.shields.io/badge/ORCID-0009--0004--5936--5060-A6CE39?style=for-the-badge&logo=orcid&logoColor=white)](https://orcid.org/0009-0004-5936-5060)

![SafePass](https://img.shields.io/badge/SafePass-v2.5_Zero--Knowledge-6d4aff?style=for-the-badge&logo=shield&logoColor=white)
![Chrome Extension](https://img.shields.io/badge/Chrome_Extension-Manifest_V3-10b981?style=for-the-badge&logo=google-chrome&logoColor=white)
![PWA](https://img.shields.io/badge/PWA-Offline_Ready-0ea5e9?style=for-the-badge&logo=pwa&logoColor=white)

<br><br>

[**🌐 Acessar Demonstração Online**](https://4u.ia.br/app/safepass/) • [**📦 Extensão do Chrome**](https://4u.ia.br/app/safepass/safepass-extensao.zip) • [**4U.IA.BR**](https://4u.ia.br)

</div>

---

## 🔒 Arquitetura de Segurança Zero-Knowledge

O **SafePass** é construído sob o princípio fundamental de **Zero-Knowledge (Conhecimento Zero)**:
* Todas as senhas, notas e dados confidenciais são **criptografados diretamente no navegador do usuário** antes de serem transmitidos para o servidor ou Google Drive.
* O servidor remoto armazena apenas payloads criptografados ilegíveis. Nem mesmo o administrador do servidor consegue visualizar qualquer credencial.

### 📐 Especificações Criptográficas:
* **Derivação de Chave:** PBKDF2 (Password-Based Key Derivation Function 2) com `SHA-256`, salt criptográfico de 128 bits e **100.000 iterações**.
* **Criptografia Simétrica:** `AES-GCM` de 256 bits com Vetores de Inicialização (IV) criptograficamente seguros de 96 bits (`crypto.getRandomValues`).
* **Verificação de Chave:** Bloco de verificação cifrado para validar senhas mestras localmente sem expor hashes de senha ao servidor.
* **Autenticador 2FA:** Motor TOTP (Time-Based One-Time Password, RFC 6238) em tempo real com contador de 30 segundos.

---

## 🧩 Recursos da Extensão do Chrome (Manifest V3)

* ⚡ **Captura Universal:** Detecção inteligente de digitação, cliques em formulários e envios de login.
* 🔑 **In-Field Helper:** Botão flutuante estilizado integrado aos campos de formulário para preenchimento com 1 clique e salvamento instantâneo.
* 🔄 **Smart Merge Engine:** Fusão bidirecional de dados entre abas web, extensão e nuvem sem perda de credenciais ou sobrescritas.
* ☁️ **Sincronização Dupla:** Backup automático em banco de dados seguro da Hostinger e na pasta pessoal do usuário no Google Drive v3 via REST API.

---

## 💻 Stack Tecnológica

* **Linguagens:** JavaScript (ES6+ Moderno), PHP 8+, HTML5 Semântico, CSS3 Moderno
* **APIs Web:** `Web Crypto API`, `Chrome Extensions API (MV3)`, `Service Workers`, `Google Identity Services`
* **Armazenamento:** SQLite3 (WAL Mode), LocalStorage Criptografado, Chrome Storage API

---

## 📄 Licença & Termos de Uso / License

Este projeto é distribuído sob o modelo **Source-Available** (código disponível publicamente para consulta, aprendizado e auditoria técnica).

* ✅ **Permitido:** Estudo pessoal, aprendizado, testes locais e auditoria de código.
* ❌ **Proibido:** Uso comercial (direto ou indireto), redistribuição, revenda ou criação de produtos derivados sem autorização prévia por escrito.

Todos os direitos autorais e patrimoniais pertencem à **4U** (4u.ia.br). Para detalhes completos e condições legais, consulte o arquivo [LICENSE](LICENSE).

Para parcerias ou licenciamento de uso comercial do motor do 4uPass / SafePass, entre em contato através de [4u.ia.br](https://4u.ia.br).