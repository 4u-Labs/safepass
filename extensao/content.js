// SafePass Content Script - AutoFill Engine

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function isExtensionValid() {
  try {
    return !!(typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id);
  } catch (e) {
    return false;
  }
}

if (isExtensionValid()) {
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'autofill') {
      const success = performAutoFill(request.username, request.password);
      sendResponse({ success });
    } else if (request.action === 'get_vault') {
      const vault = localStorage.getItem('safepass_encrypted_vault');
      const token = localStorage.getItem('safepass_cloud_token');
      const user = localStorage.getItem('safepass_cloud_user');
      sendResponse({ success: true, vault, token, user });
    } else if (request.action === 'direct_inject_pending') {
      if (request.item) {
        window.dispatchEvent(new CustomEvent('safepass_inject_pending', { detail: [request.item] }));
        sendResponse({ success: true });
      }
    } else if (request.action === 'direct_inject_full_vault') {
      if (request.vault_data) {
        window.dispatchEvent(new CustomEvent('safepass_inject_full_vault', { detail: { vault_data: request.vault_data } }));
        sendResponse({ success: true });
      }
    } else if (request.action === 'query_matches') {
      const domain = (request.domain || '').toLowerCase();
      const onReply = (e) => {
        window.removeEventListener('safepass_query_matches_reply', onReply);
        sendResponse({ logins: (e.detail && e.detail.logins) ? e.detail.logins : [] });
      };
      window.addEventListener('safepass_query_matches_reply', onReply);
      window.dispatchEvent(new CustomEvent('safepass_query_matches', { detail: { domain } }));
      setTimeout(() => {
        window.removeEventListener('safepass_query_matches_reply', onReply);
      }, 400);
      return true;
    }
    return true;
  });

  // Ponte em tempo real entre a página web do SafePass e a extensão
  if (window.location.href.includes('4u.ia.br/app/safepass') || window.location.href.includes('localhost:8080/app/safepass')) {
    window.addEventListener('safepass_vault_updated', () => {
      try {
        const rawVault = localStorage.getItem('safepass_encrypted_vault');
        const rawUser = localStorage.getItem('safepass_cloud_user');
        const rawToken = localStorage.getItem('safepass_cloud_token');
        if (rawVault && isExtensionValid()) {
          const parsed = JSON.parse(rawVault);
          chrome.storage.local.set({
            'safepass_encrypted_vault': rawVault,
            ...(rawUser ? { 'safepass_cloud_user': rawUser } : {}),
            ...(rawToken ? { 'safepass_cloud_token': rawToken } : {})
          });
          chrome.runtime.sendMessage({ action: 'sync_vault_from_web', vault_data: parsed });
        }
      } catch(e){}
    });
  }
}

function performAutoFill(username, password) {
  let filledPass = false;
  let filledUser = false;

  // Remove qualquer dropdown aberto na hora do preenchimento
  document.querySelectorAll('#__safepass_inline_dropdown').forEach(el => el.remove());

  // 1. Preencher campo de senha
  let passInput = document.querySelector('input#pass, input[name="pass"], input[data-testid="royal_pass"]');
  if (!passInput) {
    const passwordInputs = Array.from(document.querySelectorAll('input[type="password"]')).filter(el => {
      return el.offsetParent !== null && !el.disabled && !el.readOnly;
    });
    if (passwordInputs.length > 0) passInput = passwordInputs[0];
  }

  if (passInput && password) {
    setNativeValue(passInput, password);
    filledPass = true;
  }

  // 2. Preencher campo de usuário / email
  if (username) {
    let userInput = document.querySelector('input#email, input[name="email"], input[data-testid="royal_email"]');
    if (!userInput) {
      const allInputs = Array.from(document.querySelectorAll('input:not([type="hidden"]):not([type="password"]):not([type="submit"]):not([type="button"]):not([type="checkbox"]):not([type="radio"])')).filter(el => el.offsetParent !== null && !el.disabled && !el.readOnly);

      userInput = allInputs.find(i => {
        const attr = ((i.name || '') + ' ' + (i.id || '') + ' ' + (i.placeholder || '') + ' ' + (i.getAttribute('aria-label') || '') + ' ' + (i.getAttribute('autocomplete') || '')).toLowerCase();
        return attr.includes('email') || attr.includes('user') || attr.includes('login') || attr.includes('usuario') || attr.includes('ident') || attr.includes('phone') || attr.includes('tel') || i.type === 'email' || i.type === 'tel';
      });

      if (!userInput && allInputs.length > 0) {
        userInput = allInputs[0];
      }
    }

    if (userInput) {
      setNativeValue(userInput, username);
      filledUser = true;
    }
  }

  return filledPass || filledUser;
}

// Disparar eventos nativos para que React, Vue e Angular detectem a alteração
function setNativeValue(element, value) {
  element.focus();
  const valueSetter = Object.getOwnPropertyDescriptor(element, 'value') ? 
                      Object.getOwnPropertyDescriptor(element, 'value').set : null;
  const prototype = Object.getPrototypeOf(element);
  const prototypeValueSetter = Object.getOwnPropertyDescriptor(prototype, 'value') ? 
                               Object.getOwnPropertyDescriptor(prototype, 'value').set : null;

  if (prototypeValueSetter && valueSetter !== prototypeValueSetter) {
    prototypeValueSetter.call(element, value);
  } else if (valueSetter) {
    valueSetter.call(element, value);
  } else {
    element.value = value;
  }

  element.dispatchEvent(new Event('input', { bubbles: true }));
  element.dispatchEvent(new Event('change', { bubbles: true }));
  element.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: 'a' }));
  element.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: 'a' }));
}

// ── 3. SINCRONIZAÇÃO AUTOMÁTICA COM O WEBAPP (APENAS NA ROTA /SAFEPASS OU /SAFEBOX) ──
const isSafePassWebPage = (window.location.pathname.includes('/safepass') || window.location.pathname.includes('/safebox'));

if (isSafePassWebPage) {
  const syncFromWebApp = () => {
    if (!isExtensionValid()) return;
    try {
      const webVault = localStorage.getItem('safepass_encrypted_vault');
      const cloudToken = localStorage.getItem('safepass_cloud_token');
      const cloudUser = localStorage.getItem('safepass_cloud_user');

      if (webVault && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({
          'safepass_encrypted_vault': webVault,
          'safepass_cloud_token': cloudToken || '',
          'safepass_cloud_user': cloudUser || ''
        });
      }
    } catch(e) {}
  };

  const checkAndInjectPending = () => {
    if (!isExtensionValid()) return;
    try {
      chrome.storage.local.get(['safepass_pending_vault_items'], (res) => {
        if (chrome.runtime.lastError || !isExtensionValid()) return;
        const pending = res['safepass_pending_vault_items'] || [];
        if (pending.length > 0) {
          window.dispatchEvent(new CustomEvent('safepass_inject_pending', { detail: pending }));
          chrome.storage.local.set({ 'safepass_pending_vault_items': [] });
        }
      });
    } catch(e) {}
  };

  // Sincroniza ao carregar a página e em qualquer alteração de dados
  syncFromWebApp();
  checkAndInjectPending();
  const pollInterval = setInterval(() => {
    if (!isExtensionValid()) {
      clearInterval(pollInterval);
      return;
    }
    checkAndInjectPending();
  }, 2000);

  window.addEventListener('storage', syncFromWebApp);
  window.addEventListener('safepass_vault_updated', syncFromWebApp);
  window.addEventListener('safepass_sync_cache', (e) => {
    if (!isExtensionValid()) return;
    try {
      if (e.detail && Array.isArray(e.detail.vault) && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ 'safepass_unlocked_vault_cache': e.detail.vault });
      }
    } catch(e) {}
  });
}

// ── 4. DETECTOR AUTOMÁTICO DE LOGIN & PROMPT PARA SALVAR SENHA ──
(function setupPasswordCapture() {
  // Ignora se estiver no próprio SafePass Web
  if (isSafePassWebPage) {
    return;
  }

  let sessionUsername = '';
  let sessionPassword = '';
  let userExplicitlyTypedPassword = false;
  let lastCaptured = null;
  let typeTimeout = null;
  const dismissedSet = new Set();

  function isValidUsernameString(str) {
    if (!str || typeof str !== 'string') return false;
    const s = str.trim();
    if (s.length < 3 || s.length > 60) return false;
    // Rejeita datas (ex: 2026-07-30, 29/08/2026), valores monetários e números puros curtos
    if (/^\d{4}-\d{2}-\d{2}$/.test(s) || /^\d{2}\/\d{2}\/\d{4}$/.test(s)) return false;
    if (/^(r\$|usd|\$|€)\s*[\d.,]+/i.test(s)) return false;
    return true;
  }

  function findUsernameField(form, passwordInput) {
    if (sessionUsername && isValidUsernameString(sessionUsername)) {
      return sessionUsername;
    }

    const root = form || (passwordInput ? passwordInput.closest('form') : null) || document;
    const inputs = Array.from(root.querySelectorAll('input:not([type="hidden"]):not([type="password"]):not([type="submit"]):not([type="button"]):not([type="checkbox"]):not([type="radio"])')).filter(el => el.offsetParent !== null && !el.disabled);
    
    // 1. Busca por campos explícitos de login / e-mail / usuário
    let userInput = inputs.find(i => {
      const name = ((i.name || '') + ' ' + (i.id || '') + ' ' + (i.placeholder || '') + ' ' + (i.getAttribute('autocomplete') || '') + ' ' + (i.getAttribute('data-qa') || '')).toLowerCase();
      return name.includes('user') || name.includes('login') || name.includes('email') || name.includes('usuario') || name.includes('ident') || name.includes('cpf') || i.type === 'email';
    });

    if (userInput && userInput.value && isValidUsernameString(userInput.value)) {
      return userInput.value.trim();
    }

    // 2. Busca por qualquer input que contenha um e-mail válido
    let emailInput = inputs.find(i => i.value && i.value.includes('@') && isValidUsernameString(i.value));
    if (emailInput) {
      return emailInput.value.trim();
    }

    // 3. Busca por identificadores de perfil na página
    const userBadge = document.querySelector('[data-user], .user-name, .username, #username, .admin-user');
    if (userBadge && userBadge.textContent && isValidUsernameString(userBadge.textContent)) {
      return userBadge.textContent.trim();
    }

    return (sessionUsername && isValidUsernameString(sessionUsername)) ? sessionUsername : 'admin';
  }

  function extractCleanServiceName(urlStr, rawTitle) {
    try {
      const u = new URL(urlStr || window.location.href);
      const host = u.hostname.replace(/^www\./i, '').toLowerCase();

      const brandMap = {
        '4u.ia.br': '4u.ia.br',
        'paramountplus.com': 'Paramount+',
        'proton.me': 'Proton Mail',
        'protonmail.com': 'Proton Mail',
        'disneyplus.com': 'Disney+',
        'max.com': 'Max (HBO)',
        'hbomax.com': 'Max (HBO)',
        'primevideo.com': 'Prime Video',
        'globoplay.globo.com': 'Globoplay',
        'starplus.com': 'Star+',
        'facebook.com': 'Facebook',
        'instagram.com': 'Instagram',
        'google.com': 'Google',
        'accounts.google.com': 'Google',
        'github.com': 'GitHub',
        'gitlab.com': 'GitLab',
        'netflix.com': 'Netflix',
        'twitter.com': 'X (Twitter)',
        'x.com': 'X (Twitter)',
        'amazon.com': 'Amazon',
        'amazon.com.br': 'Amazon',
        'mercadolivre.com.br': 'Mercado Livre',
        'mercadolibre.com': 'Mercado Libre',
        'hostinger.com': 'Hostinger',
        'hostinger.com.br': 'Hostinger',
        'youtube.com': 'YouTube',
        'linkedin.com': 'LinkedIn',
        'microsoft.com': 'Microsoft',
        'live.com': 'Microsoft',
        'outlook.com': 'Outlook',
        'spotify.com': 'Spotify',
        'apple.com': 'Apple',
        'icloud.com': 'iCloud',
        'nubank.com.br': 'Nubank',
        'inter.co': 'Banco Inter',
        'itau.com.br': 'Itaú',
        'bradesco.com.br': 'Bradesco',
        'santander.com.br': 'Santander',
        'caixa.gov.br': 'Caixa',
        'gov.br': 'Gov.br',
        'globo.com': 'Globo',
        'discord.com': 'Discord',
        'tiktok.com': 'TikTok',
        'twitch.tv': 'Twitch',
        'reddit.com': 'Reddit',
        'chatgpt.com': 'ChatGPT',
        'openai.com': 'OpenAI',
        'notion.so': 'Notion',
        'slack.com': 'Slack',
        'trello.com': 'Trello',
        'dropbox.com': 'Dropbox',
        '4u.ia.br': '4u.ia.br'
      };

      for (const [domain, brand] of Object.entries(brandMap)) {
        if (host === domain || host.endsWith('.' + domain)) {
          return brand;
        }
      }

      if (rawTitle && rawTitle.trim()) {
        const parts = rawTitle.split(/[|\-—•:]/).map(p => p.trim()).filter(Boolean);
        for (const part of [...parts.slice(-1), ...parts.slice(0, 1)]) {
          const lower = part.toLowerCase();
          if (part.length >= 3 && part.length <= 30 && 
              !lower.includes('login') && !lower.includes('entrar') && 
              !lower.includes('sign in') && !lower.includes('iniciar sessão') &&
              !lower.includes('acesso')) {
            return part;
          }
        }
      }

      // Descarta subdomínios genéricos como account, auth, login, id, etc.
      const genericSubs = new Set(['account', 'accounts', 'auth', 'login', 'sso', 'id', 'my', 'myaccount', 'secure', 'app', 'portal', 'web', 'mail', 'admin', 'api', 'identity', 'connect', 'signin', 'oauth', 'm']);
      let parts = host.split('.');
      while (parts.length > 2 && genericSubs.has(parts[0])) {
        parts.shift();
      }
      const baseName = parts[0] || host.split('.')[0];
      return baseName.charAt(0).toUpperCase() + baseName.slice(1);
    } catch(e) {
      return 'Login Web';
    }
  }

  function isCurrentSiteDismissed() {
    return false; // Permite sempre que uma nova senha seja capturada
  }

  // 1. Monitora digitação, colagem e alterações em campos de formulário
  ['input', 'change', 'paste', 'keyup'].forEach(evt => {
    document.addEventListener(evt, (e) => {
      const target = e.target;
      if (!target) return;

      const isPassField = target.type === 'password' || 
                          (target.getAttribute('name') || '').toLowerCase().includes('pass') || 
                          (target.getAttribute('id') || '').toLowerCase().includes('pass');

      if (isPassField) {
        if (target.value && target.value.length >= 2) {
          userExplicitlyTypedPassword = true;
          sessionPassword = target.value;
          dismissedSet.clear();
          try {
            sessionStorage.removeItem('safepass_dismissed_' + window.location.hostname);
          } catch(e) {}
        }
      } else if (target.type === 'email' || target.type === 'text' || target.type === 'tel') {
        const val = (target.value || '').trim();
        if (val.includes('@') || (val.length >= 2 && isValidUsernameString(val))) {
          sessionUsername = val;
        }
      }
    }, true);
  });

  // 2. Ao sair do campo de senha (blur), garante os valores na sessão
  document.addEventListener('blur', (e) => {
    const target = e.target;
    if (target && target.type === 'password' && target.value) {
      sessionPassword = target.value;
    }
  }, true);

  function showInlineSuccessToast(msg) {
    const existing = document.getElementById('__safepass_toast_badge');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.id = '__safepass_toast_badge';
    toast.style.cssText = `
      position: fixed !important;
      top: 24px !important;
      left: 50% !important;
      transform: translateX(-50%) translateY(-20px) !important;
      background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%) !important;
      border: 1.5px solid #10b981 !important;
      box-shadow: 0 10px 30px rgba(0,0,0,0.8), 0 0 20px rgba(16, 185, 129, 0.4) !important;
      border-radius: 30px !important;
      padding: 10px 22px !important;
      color: #ffffff !important;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
      font-size: 13.5px !important;
      font-weight: 700 !important;
      z-index: 2147483647 !important;
      display: flex !important;
      align-items: center !important;
      gap: 10px !important;
      pointer-events: none !important;
      opacity: 0 !important;
      transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1) !important;
    `;
    toast.innerHTML = `<span>🛡️</span> <span>${escapeHtml(msg)}</span>`;
    document.body.appendChild(toast);

    requestAnimationFrame(() => {
      toast.style.opacity = '1';
      toast.style.transform = 'translateX(-50%) translateY(0)';
    });

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(-50%) translateY(-20px)';
      setTimeout(() => toast.remove(), 350);
    }, 4000);
  }

  function saveCredentialDirectly(toSave, showToastMsg = true) {
    if (!toSave || !toSave.password) return;
    if (!isExtensionValid()) return;

    const domain = (toSave.domain || window.location.hostname).replace(/^www\./i, '').toLowerCase();

    chrome.storage.local.get(['safepass_pending_vault_items', 'safepass_unlocked_vault_cache'], (res) => {
      if (chrome.runtime.lastError || !isExtensionValid()) return;
      let pending = res['safepass_pending_vault_items'] || [];
      let cache = res['safepass_unlocked_vault_cache'] || [];

      pending = pending.filter(p => !(isDomainMatch(p, domain) && (p.username || '').trim().toLowerCase() === (toSave.username || '').trim().toLowerCase()));
      cache = cache.filter(p => !(isDomainMatch(p, domain) && (p.username || '').trim().toLowerCase() === (toSave.username || '').trim().toLowerCase()));

      pending.unshift(toSave);
      cache.unshift(toSave);

      chrome.storage.local.set({
        'safepass_pending_vault_items': pending,
        'safepass_unlocked_vault_cache': cache,
        'safepass_pending_prompt': null
      }, () => {
        try {
          chrome.runtime.sendMessage({ action: 'save_credential', data: toSave });
        } catch(e) {}
        if (showToastMsg) {
          showInlineSuccessToast(`SafePass: Login para ${toSave.title || domain} salvo com sucesso!`);
        }
      });
    });
  }

  function triggerCapture(form, passwordInput) {
    let passVal = (passwordInput && passwordInput.value) ? passwordInput.value : sessionPassword;
    if (!passVal || passVal.length < 1) return;

    const username = findUsernameField(form, passwordInput) || sessionUsername;
    const cleanTitle = extractCleanServiceName(window.location.href, document.title);
    const domain = window.location.hostname.replace(/^www\./i, '').toLowerCase();

    const cred = {
      id: 'item_' + Date.now(),
      type: 'login',
      title: cleanTitle || domain,
      url: window.location.href,
      domain: domain,
      username: username || 'admin',
      password: passVal,
      notes: 'Salvo via extensão SafePass.',
      favorite: false,
      createdAt: Date.now()
    };

    lastCaptured = cred;

    if (!isExtensionValid()) return;

    // Salva imediatamente para garantir 100% que a senha não seja perdida
    saveCredentialDirectly(cred, true);

    chrome.storage.local.get(['safepass_unlocked_vault_cache'], (res) => {
      if (chrome.runtime.lastError || !isExtensionValid()) return;
      const cache = res['safepass_unlocked_vault_cache'] || [];

      // Verifica se é atualização de senha
      const existingUserMatch = cache.find(item => {
        const uMatch = (item.username || '').trim().toLowerCase() === (cred.username || '').trim().toLowerCase();
        return uMatch && isDomainMatch(item, cred.domain);
      });

      cred.isUpdate = !!existingUserMatch;
      showSavePasswordPrompt(cred);
    });
  }

  // 3. Escuta submit de formulários com campo de senha
  document.addEventListener('submit', (e) => {
    const form = e.target;
    const pass = (form && form.querySelector) ? form.querySelector('input[type="password"]') : null;
    triggerCapture(form, pass);
  }, true);

  // 4. Escuta cliques em botões de ação/login (Ignora botões de Logout / Sair)
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('button, input[type="submit"], input[type="button"], a, [role="button"]');
    if (!btn) return;

    const btnText = ((btn.innerText || '') + ' ' + (btn.id || '') + ' ' + (btn.className || '') + ' ' + (btn.getAttribute('type') || '')).toLowerCase();
    
    // Se for botão de Logout / Sair / Deslogar, limpa qualquer prompt e nunca captura
    const isLogoutButton = /sair|logout|log out|sign ?out|desconectar|encerrar sess[aã]o|deslogar/i.test(btnText);
    if (isLogoutButton) {
      userExplicitlyTypedPassword = false;
      sessionPassword = '';
      if (isExtensionValid()) {
        chrome.storage.local.remove('safepass_pending_prompt');
      }
      return;
    }

    const form = btn.closest('form');
    const pass = (form && form.querySelector('input[type="password"]')) || document.querySelector('input[type="password"]');
    const passVal = (pass && pass.value) ? pass.value : sessionPassword;
    if (!passVal || passVal.length < 3) return;

    const isSameForm = form && pass && pass.closest('form') === form;
    const isLoginButton = /entrar|login|log in|sign ?in|sign ?up|acessar|logar|autenticar|cadastrar|cadastro|salvar|conectar|submit|continuar|prosseguir|iniciar|iniciar sess[aã]o|criar|avançar|confirmar|next|começar|ok|enviar/i.test(btnText);
    const isSubmitType = btn.getAttribute('type') === 'submit' || btn.tagName === 'BUTTON';

    if (isSameForm || isLoginButton || isSubmitType || userExplicitlyTypedPassword) {
      triggerCapture(form, pass);
    }
  }, true);

  // 5. Escuta tecla Enter nos inputs de login
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const pass = document.querySelector('input[type="password"]');
      if ((pass && pass.value && pass.value.length >= 3) || (sessionPassword && sessionPassword.length >= 3)) {
        triggerCapture(e.target.closest('form'), pass);
      }
    }
  }, true);

  // 6. Salva antes de descarregar a página caso haja redirecionamento
  window.addEventListener('beforeunload', () => {
    if (sessionPassword && sessionPassword.length >= 3 && isExtensionValid()) {
      const username = sessionUsername || 'admin';
      const cleanTitle = extractCleanServiceName(window.location.href, document.title);
      chrome.storage.local.set({
        'safepass_pending_prompt': {
          username,
          password: sessionPassword,
          url: window.location.href,
          domain: window.location.hostname.replace(/^www\./i, '').toLowerCase(),
          title: cleanTitle,
          timestamp: Date.now()
        }
      });
    }
  });

  // 7. Monitora transições em Single Page Apps (SPA)
  window.addEventListener('hashchange', () => {
    if (sessionPassword && lastCaptured && lastCaptured.password && !dismissedSet.has(lastCaptured.password)) {
      setTimeout(() => showSavePasswordPrompt(lastCaptured), 400);
    }
  });

  // 7. Verifica se há prompt pendente após redirecionamento de login
  if (isExtensionValid()) {
    chrome.storage.local.get(['safepass_pending_prompt', 'safepass_unlocked_vault_cache'], (res) => {
      if (chrome.runtime.lastError || !isExtensionValid()) return;
      const p = res['safepass_pending_prompt'];
      const cache = res['safepass_unlocked_vault_cache'] || [];

      if (p && p.password && (Date.now() - p.timestamp < 30000)) {
        const curDomain = window.location.hostname.replace(/^www\./i, '').toLowerCase();
        if (p.domain && (curDomain.includes(p.domain) || p.domain.includes(curDomain))) {
          chrome.storage.local.remove('safepass_pending_prompt');

          // Verifica no cache se o item já está 100% salvo e idêntico
          const exactMatch = cache.find(item => {
            const uMatch = (item.username || '').trim().toLowerCase() === (p.username || '').trim().toLowerCase();
            const pMatch = item.password === p.password;
            return uMatch && pMatch && isDomainMatch(item, p.domain || curDomain);
          });

          if (exactMatch) {
            // Já está salvo e a senha é idêntica! Não exibe nada
            return;
          }

          // Verifica se é atualização
          const existingUserMatch = cache.find(item => {
            const uMatch = (item.username || '').trim().toLowerCase() === (p.username || '').trim().toLowerCase();
            return uMatch && isDomainMatch(item, p.domain || curDomain);
          });

          p.isUpdate = !!existingUserMatch;

          if (!dismissedSet.has(p.password)) {
            setTimeout(() => showSavePasswordPrompt(p), 600);
          }
        }
      }
    });
  }

  // Renderiza o Banner Flutuante de Salvar Senha
  function showSavePasswordPrompt(data) {
    if (!data || !data.password || isCurrentSiteDismissed()) return;

    // Remove qualquer prompt anterior para atualizar com dados novos
    const existing = document.getElementById('__safepass_save_container');
    if (existing) existing.remove();

    const host = document.createElement('div');
    host.id = '__safepass_save_container';
    host.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 2147483647; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; pointer-events: auto;';
    
    const shadow = host.attachShadow({ mode: 'open' });
    
    shadow.innerHTML = `
      <style>
        .safepass-prompt-box {
          background: #0d1322;
          border: 1px solid rgba(109, 74, 255, 0.5);
          border-radius: 14px;
          padding: 16px 18px;
          width: 310px;
          box-shadow: 0 12px 40px rgba(0,0,0,0.85), 0 0 25px rgba(109, 74, 255, 0.35);
          color: #f8fafc;
          box-sizing: border-box;
          animation: slideIn 0.3s cubic-bezier(0.16, 1, 0.3, 1);
        }
        @keyframes slideIn {
          from { transform: translateY(-30px); opacity: 0; }
          to { transform: translateY(0); opacity: 1; }
        }
        .header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 8px;
        }
        .brand {
          display: flex;
          align-items: center;
          gap: 6px;
          font-size: 14px;
          font-weight: 800;
          color: #fff;
        }
        .brand span { color: #6d4aff; }
        .close-btn {
          background: none;
          border: none;
          color: #64748b;
          font-size: 20px;
          cursor: pointer;
          line-height: 1;
          padding: 2px;
          transition: color 0.15s;
        }
        .close-btn:hover { color: #f43f5e; }
        .desc {
          font-size: 12px;
          color: #94a3b8;
          margin-bottom: 12px;
          line-height: 1.4;
        }
        .info-card {
          background: rgba(255,255,255,0.05);
          border: 1px solid rgba(255,255,255,0.08);
          border-radius: 8px;
          padding: 8px 12px;
          margin-bottom: 14px;
          font-size: 12px;
        }
        .info-row {
          display: flex;
          justify-content: space-between;
          margin-bottom: 4px;
        }
        .info-row:last-child { margin-bottom: 0; }
        .info-label { color: #64748b; }
        .info-val { color: #fff; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 170px; }
        .actions {
          display: flex;
          gap: 8px;
        }
        .btn {
          flex: 1;
          height: 36px;
          border-radius: 8px;
          font-size: 12px;
          font-weight: 700;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: all 0.2s;
        }
        .btn-save {
          background: linear-gradient(135deg, #6d4aff 0%, #4f2ce0 100%);
          border: none;
          color: #fff;
          box-shadow: 0 4px 14px rgba(109, 74, 255, 0.4);
        }
        .btn-save:hover {
          filter: brightness(1.15);
          transform: translateY(-1px);
        }
        .btn-cancel {
          background: rgba(255,255,255,0.06);
          border: 1px solid rgba(255,255,255,0.12);
          color: #94a3b8;
        }
        .btn-cancel:hover {
          background: rgba(255,255,255,0.12);
          color: #fff;
        }
        .input-group {
          margin-bottom: 8px;
          text-align: left;
        }
        .input-group:last-child {
          margin-bottom: 0;
        }
        .input-label {
          display: block;
          font-size: 10px;
          font-weight: 700;
          color: #94a3b8;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          margin-bottom: 3px;
        }
        .prompt-input {
          width: 100%;
          background: rgba(0, 0, 0, 0.4);
          border: 1px solid rgba(255, 255, 255, 0.12);
          border-radius: 6px;
          color: #fff;
          padding: 6px 8px;
          font-size: 12px;
          box-sizing: border-box;
          outline: none;
          transition: border-color 0.2s;
        }
        .prompt-input:focus {
          border-color: #6d4aff;
        }
      </style>
      <div class="safepass-prompt-box">
        <div class="header">
          <div class="brand">
            <span>🛡️</span> Safe<span>Pass</span>
          </div>
          <button class="close-btn" id="sp-close">×</button>
        </div>
        <div class="desc">${data.isUpdate ? 'Detectamos uma nova senha para esta conta. Deseja atualizar no SafePass?' : 'Deseja salvar esta senha no seu cofre seguro?'}</div>
        <div class="info-card">
          <div class="input-group">
            <label class="input-label">Nome do Serviço / Site</label>
            <input type="text" id="sp-edit-title" class="prompt-input" value="${escapeHtml(data.title || data.domain)}">
          </div>
          <div class="input-group">
            <label class="input-label">Usuário / E-mail</label>
            <input type="text" id="sp-edit-user" class="prompt-input" value="${escapeHtml(data.username || '')}">
          </div>
          <div class="input-group">
            <label class="input-label">Senha</label>
            <div style="display:flex; gap:4px;">
              <input type="password" id="sp-edit-pass" class="prompt-input" value="${escapeHtml(data.password || '')}">
              <button type="button" id="sp-toggle-pass" style="background:rgba(255,255,255,0.06); border:1px solid rgba(255,255,255,0.12); border-radius:6px; color:#fff; cursor:pointer; padding:0 8px;">👁️</button>
            </div>
          </div>
        </div>
        <div class="actions">
          <button class="btn btn-cancel" id="sp-cancel">Agora Não</button>
          <button class="btn btn-save" id="sp-save">${data.isUpdate ? '🔄 Atualizar Senha' : '💾 Salvar Senha'}</button>
        </div>
      </div>
    `;

    const mountRoot = document.documentElement || document.body;
    if (mountRoot) {
      mountRoot.appendChild(host);
    }

    const closePrompt = () => {
      try {
        sessionStorage.setItem('safepass_dismissed_' + window.location.hostname, 'true');
      } catch(e) {}
      if (data && data.password) dismissedSet.add(data.password);
      dismissedSet.add(window.location.hostname);
      userExplicitlyTypedPassword = false;
      sessionPassword = '';
      sessionUsername = '';
      lastCaptured = null;
      try {
        if (isExtensionValid()) {
          chrome.storage.local.remove('safepass_pending_prompt');
        }
      } catch(e) {}
      host.style.transition = 'opacity 0.2s, transform 0.2s';
      host.style.opacity = '0';
      host.style.transform = 'translateY(-20px)';
      setTimeout(() => {
        if (host && host.parentNode) host.parentNode.removeChild(host);
      }, 250);
    };

    const bindAction = (id, fn) => {
      const el = shadow.getElementById(id);
      if (!el) return;
      el.onclick = (e) => {
        e.preventDefault();
        e.stopPropagation();
        fn(e);
      };
    };

    bindAction('sp-close', closePrompt);
    bindAction('sp-cancel', closePrompt);

    bindAction('sp-toggle-pass', () => {
      const passInp = shadow.getElementById('sp-edit-pass');
      if (passInp) {
        passInp.type = passInp.type === 'password' ? 'text' : 'password';
      }
    });

    bindAction('sp-save', () => {
      const saveBtn = shadow.getElementById('sp-save');
      if (saveBtn) {
        saveBtn.disabled = true;
        saveBtn.innerText = 'Salvando...';
        saveBtn.style.opacity = '0.7';
      }

      const editedTitle = (shadow.getElementById('sp-edit-title') ? shadow.getElementById('sp-edit-title').value.trim() : '') || data.domain || 'Login Web';
      const editedUser = shadow.getElementById('sp-edit-user') ? shadow.getElementById('sp-edit-user').value.trim() : (data.username || '');
      const editedPass = shadow.getElementById('sp-edit-pass') ? shadow.getElementById('sp-edit-pass').value : (data.password || '');

      const toSave = {
        id: 'item_' + Date.now(),
        type: 'login',
        title: editedTitle,
        url: data.url || window.location.href,
        domain: data.domain || window.location.hostname.replace(/^www\./i, ''),
        username: editedUser,
        password: editedPass,
        notes: 'Salvo via extensão SafePass.',
        createdAt: Date.now()
      };

      try {
        sessionStorage.setItem('safepass_dismissed_' + window.location.hostname, 'true');
      } catch(e) {}
      if (editedPass) dismissedSet.add(editedPass);
      dismissedSet.add(window.location.hostname);

      try {
        if (isExtensionValid()) {
          chrome.storage.local.get(['safepass_pending_vault_items', 'safepass_unlocked_vault_cache'], (res) => {
            if (chrome.runtime.lastError) return;
            let pending = res['safepass_pending_vault_items'] || [];
            let cache = res['safepass_unlocked_vault_cache'] || [];

            pending = pending.filter(p => !(p.url === toSave.url && p.username === toSave.username));
            cache = cache.filter(p => !(p.url === toSave.url && p.username === toSave.username));

            pending.unshift(toSave);
            cache.unshift(toSave);

            chrome.storage.local.set({
              'safepass_pending_vault_items': pending,
              'safepass_unlocked_vault_cache': cache,
              'safepass_pending_prompt': null
            }, () => {
              try {
                chrome.runtime.sendMessage({ action: 'save_credential', data: toSave });
              } catch(e) {}
            });
          });
        }
      } catch(e) {}

      const box = shadow.querySelector('.safepass-prompt-box');
      if (box) {
        box.innerHTML = `
          <div style="text-align: center; padding: 14px 0; color: #10b981; font-weight: 700; font-size: 13.5px; display:flex; align-items:center; justify-content:center; gap:8px;">
            <span>✅</span> Senha salva com sucesso!
          </div>
        `;
      }
      setTimeout(closePrompt, 1200);
    });
  }
})();

// ── 5. AUTO-SUGESTÃO INTELIGENTE NOS CAMPOS DE LOGIN (COM ÍCONE INTERATIVO & AUTO-FILL) ──
(function setupInFieldAutoSuggest() {
  if (window.location.hostname.includes('4u.ia.br') && window.location.pathname.includes('safepass')) {
    return;
  }

  const attachedInputs = new WeakSet();

  function scanAndAttachInputs() {
    const inputs = Array.from(document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="checkbox"]):not([type="radio"])')).filter(el => {
      if (el.offsetParent === null || el.disabled || el.readOnly) return false;
      if (el.type === 'password') return true;
      if (el.type === 'email') return true;
      const name = ((el.name || '') + ' ' + (el.id || '') + ' ' + (el.placeholder || '') + ' ' + (el.getAttribute('autocomplete') || '')).toLowerCase();
      return name.includes('user') || name.includes('login') || name.includes('email') || name.includes('usuario');
    });

    inputs.forEach(input => {
      if (attachedInputs.has(input)) return;
      attachedInputs.add(input);
      bindInputAutoSuggest(input);
      attachFieldIcon(input);
    });

    // Auto-preenchimento inteligente se houver credencial salva e campo de senha vazio
    tryAutoFillOnLoad();
  }

  function tryAutoFillOnLoad() {
    if (!isExtensionValid()) return;
    const domain = window.location.hostname.replace(/^www\./i, '').toLowerCase();

    chrome.storage.local.get(['safepass_unlocked_vault_cache'], (res) => {
      if (chrome.runtime.lastError || !isExtensionValid()) return;
      const cache = res['safepass_unlocked_vault_cache'] || [];
      const matches = cache.filter(item => isDomainMatch(item, domain));

      if (matches.length === 1) {
        const item = matches[0];
        const passInput = document.querySelector('input[type="password"]');
        if (passInput && (!passInput.value || passInput.value.length === 0)) {
          performAutoFill(item.username, item.password);
        }
      }
    });
  }

  function attachFieldIcon(input) {
    if (!input || input.type !== 'password' || input.dataset.safepassIconAttached) return;
    input.dataset.safepassIconAttached = 'true';

    // Cria wrapper ou anexa ícone posicionado
    const parent = input.parentElement;
    if (!parent) return;

    const iconBtn = document.createElement('div');
    iconBtn.className = '__safepass_field_icon_btn';
    iconBtn.title = 'SafePass: Ver Senhas Salvas';
    iconBtn.style.cssText = `
      position: absolute;
      right: 12px;
      top: 50%;
      transform: translateY(-50%);
      width: 24px;
      height: 24px;
      border-radius: 6px;
      background: linear-gradient(135deg, #6d4aff 0%, #a855f7 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      z-index: 2147483640;
      box-shadow: 0 2px 8px rgba(109, 74, 255, 0.45);
      font-size: 12px;
      user-select: none;
      transition: transform 0.15s, filter 0.15s;
    `;
    iconBtn.innerHTML = '🔑';

    iconBtn.onmouseover = () => { iconBtn.style.transform = 'translateY(-50%) scale(1.1)'; iconBtn.style.filter = 'brightness(1.2)'; };
    iconBtn.onmouseout = () => { iconBtn.style.transform = 'translateY(-50%) scale(1)'; iconBtn.style.filter = 'none'; };

    iconBtn.onclick = (e) => {
      e.stopPropagation();
      e.preventDefault();
      showInlineDropdown(input);
    };

    // Garante que o container pai tenha posição relativa se não tiver
    const parentPos = window.getComputedStyle(parent).position;
    if (parentPos === 'static') {
      parent.style.position = 'relative';
    }

    parent.appendChild(iconBtn);
  }

  function bindInputAutoSuggest(input) {
    const onFocusOrClick = (e) => {
      if (!document.getElementById('__safepass_inline_dropdown')) {
        showInlineDropdown(input);
      }
    };

    input.addEventListener('focus', onFocusOrClick);
    input.addEventListener('click', onFocusOrClick);
  }

  // Remove qualquer dropdown residual em mudanças de rota no SPA (Single Page App)
  window.addEventListener('hashchange', () => {
    document.querySelectorAll('#__safepass_inline_dropdown, .__safepass_field_icon_btn').forEach(el => el.remove());
    setTimeout(scanAndAttachInputs, 300);
  });
  window.addEventListener('popstate', () => {
    document.querySelectorAll('#__safepass_inline_dropdown, .__safepass_field_icon_btn').forEach(el => el.remove());
    setTimeout(scanAndAttachInputs, 300);
  });

  function isDomainMatch(item, targetDomain) {
    if (!item) return false;
    const target = (targetDomain || '').replace(/^www\./i, '').toLowerCase();
    const curPath = (window.location.pathname || '').toLowerCase();

    // Se o item for a Conta SafePass Cloud / Cofre SafePass:
    const isSafePassAccount = (item.title || '').toLowerCase().includes('safepass') || (item.url || '').toLowerCase().includes('safepass');
    if (isSafePassAccount) {
      // Só sugere a Conta SafePass se a página atual for do próprio SafePass
      return curPath.includes('safepass') || curPath.includes('safebox');
    }

    // 1. Testa URL com path matching inteligente para sub-aplicações
    if (item.url) {
      try {
        const itemUrl = item.url.startsWith('http') ? item.url : 'https://' + item.url;
        const parsed = new URL(itemUrl);
        const itemHost = parsed.hostname.replace(/^www\./i, '').toLowerCase();
        
        if (itemHost === target || itemHost.endsWith('.' + target) || target.endsWith('.' + itemHost)) {
          // Se o item tem um path específico (ex: /loja/ ou /blog/) e a página atual também:
          const itemPath = parsed.pathname.replace(/\/$/, '').toLowerCase();
          if (itemPath && itemPath !== '/' && itemPath.length > 2) {
            const firstSeg = itemPath.split('/').filter(Boolean)[0]; // 'loja', 'blog'
            if (firstSeg && !curPath.includes(firstSeg)) {
              return false; // Pertence a outro app no mesmo domínio
            }
          }
          return true;
        }
      } catch(e) {
        if (item.url.toLowerCase().includes(target)) return true;
      }
    }

    // 2. Testa Título
    if (item.title) {
      const t = item.title.toLowerCase();
      if (t === target || t.includes(target)) return true;
    }

    // 3. Testa Domínio do Item
    if (item.domain) {
      const d = item.domain.toLowerCase();
      if (d === target || target.includes(d)) return true;
    }

    return false;
  }

  function showInlineDropdown(input) {
    if (!input || !input.isConnected || !input.offsetParent) return;

    const existing = document.getElementById('__safepass_inline_dropdown');
    if (existing) {
      existing.remove();
    }

    const rect = input.getBoundingClientRect();
    const dropdownWidth = Math.min(320, Math.max(260, rect.width));
    
    // Posicionamento fixo infalível (abaixo ou acima se estiver perto da borda inferior)
    let top = rect.bottom + 6;
    if (top + 200 > window.innerHeight && rect.top > 200) {
      top = Math.max(10, rect.top - 180);
    }
    const left = Math.max(10, Math.min(rect.left, window.innerWidth - dropdownWidth - 15));

    const dropdown = document.createElement('div');
    dropdown.id = '__safepass_inline_dropdown';

    dropdown.style.cssText = `
      position: fixed;
      top: ${top}px;
      left: ${left}px;
      width: ${dropdownWidth}px;
      background: #0d1322;
      border: 1px solid rgba(109, 74, 255, 0.45);
      box-shadow: 0 12px 35px rgba(0,0,0,0.85), 0 0 20px rgba(109, 74, 255, 0.25);
      border-radius: 10px;
      padding: 8px;
      z-index: 2147483647;
      color: #f8fafc;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 12px;
      animation: __spFadeIn 0.15s ease;
    `;

    dropdown.innerHTML = `
      <style>
        @keyframes __spFadeIn { from { opacity: 0; transform: translateY(-6px); } to { opacity: 1; transform: translateY(0); } }
        .__sp_drop_btn {
          width: 100%;
          padding: 7px 10px;
          border-radius: 6px;
          border: none;
          background: transparent;
          color: #e2e8f0;
          font-size: 11.5px;
          font-weight: 500;
          text-align: left;
          cursor: pointer;
          display: flex;
          align-items: center;
          gap: 8px;
          transition: background 0.15s;
          box-sizing: border-box;
        }
        .__sp_drop_btn:hover {
          background: rgba(109, 74, 255, 0.25);
          color: #fff;
        }
        .__sp_match_card {
          background: rgba(109, 74, 255, 0.16);
          border: 1px solid rgba(109, 74, 255, 0.35);
          border-radius: 8px;
          padding: 8px 10px;
          margin-bottom: 6px;
          cursor: pointer;
          transition: all 0.15s;
        }
        .__sp_match_card:hover {
          background: rgba(109, 74, 255, 0.35);
          border-color: #6d4aff;
          transform: translateY(-1px);
        }
      </style>
      <div style="padding: 4px 6px 6px; font-size: 10px; font-weight: 700; color: #94a3b8; border-bottom: 1px solid rgba(255,255,255,0.08); margin-bottom: 6px; display: flex; align-items: center; justify-content: space-between;">
        <span>🛡️ SafePass Sugestão</span>
        <span style="color: #10b981; font-weight: 700;">● Cofre Ativo</span>
      </div>
      <div id="__sp_matches_box">
        <div style="font-size: 11px; color: #94a3b8; padding: 6px 0; text-align: center;">
          🔍 Buscando credenciais...
        </div>
      </div>
      <div style="border-top: 1px solid rgba(255,255,255,0.08); margin-top: 4px; padding-top: 4px;">
        <button class="__sp_drop_btn" id="__sp_gen_fill">
          <span>⚡</span> Gerar Senha Forte
        </button>
        <button class="__sp_drop_btn" id="__sp_open_ext">
          <span>🔑</span> Abrir SafePass Web
        </button>
      </div>
    `;

    function renderDropdownLogins(logins) {
      if (!dropdown.parentNode) {
        const dialogParent = input.closest('dialog, [role="dialog"], .modal, .popup');
        if (dialogParent) {
          dialogParent.appendChild(dropdown);
        } else {
          document.body.appendChild(dropdown);
        }
      }

      const matchBox = dropdown.querySelector('#__sp_matches_box');
      if (!matchBox) return;

      if (logins && logins.length > 0) {
        matchBox.innerHTML = '';
        logins.forEach(item => {
          const card = document.createElement('div');
          card.className = '__sp_match_card';
          card.innerHTML = `
            <div style="display: flex; align-items: center; justify-content: space-between;">
              <span style="font-weight: 700; color: #fff; font-size: 12.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 170px;">
                👤 ${escapeHtml(item.username || 'Sem usuário')}
              </span>
              <span style="font-size: 10.5px; background: linear-gradient(135deg, #6d4aff, #10b981); color: #fff; padding: 3px 8px; border-radius: 4px; font-weight: 700; display: inline-flex; align-items: center; gap: 3px;">
                ⚡ Preencher
              </span>
            </div>
            <div style="font-size: 10.5px; color: #94a3b8; margin-top: 2px;">
              ${escapeHtml(item.title || item.domain || window.location.hostname)}
            </div>
          `;

          const executeFill = (ev) => {
            if (ev) {
              ev.stopPropagation();
              ev.preventDefault();
            }
            performAutoFill(item.username, item.password);
            dropdown.remove();
          };

          card.addEventListener('click', executeFill);
          card.addEventListener('pointerup', executeFill);
          matchBox.appendChild(card);
        });
      } else {
        const currentPassVal = input.value || sessionPassword || '';
        matchBox.innerHTML = `
          <div style="padding: 4px 6px 8px; font-size: 11px; color: #94a3b8; text-align: center; line-height: 1.3;">
            Nenhum login salvo para <strong style="color: #fff;">${escapeHtml(domain)}</strong>
          </div>
          ${currentPassVal ? `
            <button class="__sp_drop_btn" id="__sp_save_field_btn" style="background: rgba(109, 74, 255, 0.25); color: #a78bfa; font-weight: 700; border: 1px solid rgba(109, 74, 255, 0.4); margin-bottom: 6px;">
              <span>💾</span> Salvar Senha Digitada
            </button>
          ` : ''}
        `;

        const saveFieldBtn = matchBox.querySelector('#__sp_save_field_btn');
        if (saveFieldBtn) {
          saveFieldBtn.onclick = (e) => {
            e.stopPropagation();
            e.preventDefault();
            dropdown.remove();
            const passVal = input.value || sessionPassword || '';
            const cred = {
              id: 'item_' + Date.now(),
              type: 'login',
              title: extractCleanServiceName(window.location.href, document.title) || domain,
              url: window.location.href,
              domain: domain,
              username: sessionUsername || 'admin',
              password: passVal,
              notes: 'Salvo via extensão SafePass.',
              favorite: false,
              createdAt: Date.now()
            };
            saveCredentialDirectly(cred, true);
          };
        }
      }
    }

    // Consulta senhas correspondentes ao domínio atual
    const domain = window.location.hostname.replace(/^www\./i, '').toLowerCase();
    if (isExtensionValid()) {
      chrome.storage.local.get(['safepass_unlocked_vault_cache', 'safepass_pending_vault_items'], (res) => {
        if (chrome.runtime.lastError || !isExtensionValid()) return;
        const cache = res['safepass_unlocked_vault_cache'] || [];
        const pending = res['safepass_pending_vault_items'] || [];
        const combined = [...cache, ...pending];
        const localMatches = [];
        const added = new Set();

        combined.forEach(item => {
          if (isDomainMatch(item, domain)) {
            const key = (item.username || '') + '|' + (item.password || '');
            if (!added.has(key)) {
              added.add(key);
              localMatches.push(item);
            }
          }
        });

        if (localMatches.length > 0) {
          renderDropdownLogins(localMatches);
        } else {
          // Consulta background
          chrome.runtime.sendMessage({ action: 'get_matched_logins', domain }, (bRes) => {
            if (chrome.runtime.lastError || !isExtensionValid()) return;
            const logins = (bRes && bRes.logins) ? bRes.logins : [];
            renderDropdownLogins(logins);
          });
        }
      });
    }

    // Fechar ao clicar fora (sem sofrer com eventos de blur causados pelo Chrome)
    const onDocClick = (ev) => {
      if (!dropdown.contains(ev.target) && ev.target !== input) {
        dropdown.remove();
        document.removeEventListener('pointerdown', onDocClick);
      }
    };
    setTimeout(() => document.addEventListener('pointerdown', onDocClick), 50);

    // Gerar senha forte na hora
    const genBtn = dropdown.querySelector('#__sp_gen_fill');
    if (genBtn) {
      genBtn.onclick = () => {
        const strongPass = generateQuickPassword(20);
        setNativeValue(input, strongPass);
        dropdown.remove();
      };
    }

    const openExtBtn = dropdown.querySelector('#__sp_open_ext');
    if (openExtBtn) {
      openExtBtn.onclick = () => {
        window.open('https://4u.ia.br/app/safepass/', '_blank');
        dropdown.remove();
      };
    }
  }

  function generateQuickPassword(len = 20) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}';
    const array = new Uint32Array(len);
    crypto.getRandomValues(array);
    let pass = '';
    for (let i = 0; i < len; i++) {
      pass += chars[array[i] % chars.length];
    }
    return pass;
  }

  // Monitora a página para novos inputs dinâmicos
  const scanInterval = setInterval(() => {
    if (!isExtensionValid()) {
      clearInterval(scanInterval);
      return;
    }
    scanAndAttachInputs();
  }, 1500);
  scanAndAttachInputs();
  const observer = new MutationObserver(() => {
    if (isExtensionValid()) scanAndAttachInputs();
  });
  observer.observe(document.body || document.documentElement, { childList: true, subtree: true });
})();
