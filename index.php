<?php
declare(strict_types=1);

// ── 1. EMBEDDED API HANDLER (ZERO-KNOWLEDGE CLOUD SYNC) ───────────
if (isset($_GET['action'])) {
    header("Access-Control-Allow-Origin: *");
    header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
    header("Access-Control-Allow-Headers: Content-Type, Authorization");
    header("Content-Type: application/json; charset=utf-8");
    header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");

    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(200);
        exit;
    }

    $dbDir = __DIR__ . '/database';
    if (!is_dir($dbDir)) {
        @mkdir($dbDir, 0755, true);
        @file_put_contents($dbDir . '/.htaccess', "Deny from all\n");
    }
    $dbPath = is_dir($dbDir) ? $dbDir . '/safepass.db' : __DIR__ . '/safepass.db';

    try {
        $pdo = new PDO('sqlite:' . $dbPath);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $pdo->exec('PRAGMA journal_mode=WAL');
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS vaults (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                google_id TEXT UNIQUE,
                email TEXT UNIQUE NOT NULL,
                display_name TEXT,
                photo_url TEXT,
                vault_data TEXT,
                token TEXT UNIQUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_vaults_token ON vaults(token);
            CREATE INDEX IF NOT EXISTS idx_vaults_email ON vaults(email);
        ");

        $action = $_GET['action'];

        if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'google_auth') {
            $body = json_decode(file_get_contents('php://input'), true) ?? [];
            $credential = trim($body['credential'] ?? '');
            $email = trim($body['email'] ?? '');
            $name = trim($body['name'] ?? '');
            $picture = trim($body['picture'] ?? '');
            $googleId = trim($body['google_id'] ?? '');

            if ($credential) {
                $parts = explode('.', $credential);
                if (count($parts) === 3) {
                    $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
                    if ($payload && !empty($payload['email'])) {
                        $email = $payload['email'];
                        $name = $payload['name'] ?? $name;
                        $picture = $payload['picture'] ?? $picture;
                        $googleId = $payload['sub'] ?? $googleId;
                    }
                }
            }

            if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                http_response_code(400);
                echo json_encode(['success' => false, 'error' => 'E-mail inválido']);
                exit;
            }

            $stmt = $pdo->prepare('SELECT * FROM vaults WHERE email = ?');
            $stmt->execute([$email]);
            $user = $stmt->fetch();

            if ($user) {
                $token = !empty($user['token']) ? $user['token'] : bin2hex(random_bytes(32));
                $pdo->prepare('UPDATE vaults SET token = ?, display_name = ?, photo_url = ?, google_id = COALESCE(google_id, ?), updated_at = datetime("now") WHERE id = ?')
                    ->execute([$token, $name ?: $user['display_name'], $picture ?: $user['photo_url'], $googleId, $user['id']]);
                $vaultData = $user['vault_data'];
            } else {
                $token = bin2hex(random_bytes(32));
                $stmt = $pdo->prepare('INSERT INTO vaults (google_id, email, display_name, photo_url, token, vault_data) VALUES (?, ?, ?, ?, ?, NULL)');
                $stmt->execute([$googleId, $email, $name, $picture, $token]);
                $vaultData = null;
            }

            echo json_encode([
                'success' => true,
                'token' => $token,
                'user' => [
                    'email' => $email,
                    'name' => $name,
                    'picture' => $picture
                ],
                'vault_data' => $vaultData ? json_decode($vaultData, true) : null
            ]);
            exit;
        }

        if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($action === 'email_auth' || $action === 'extension_login')) {
            $body = json_decode(file_get_contents('php://input'), true) ?? [];
            $email = trim(strtolower($body['email'] ?? ''));

            if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                http_response_code(400);
                echo json_encode(['success' => false, 'error' => 'Informe um e-mail válido']);
                exit;
            }

            $stmt = $pdo->prepare('SELECT * FROM vaults WHERE LOWER(email) = ?');
            $stmt->execute([$email]);
            $user = $stmt->fetch();

            if ($user) {
                $token = !empty($user['token']) ? $user['token'] : bin2hex(random_bytes(32));
                $pdo->prepare('UPDATE vaults SET token = ?, updated_at = datetime("now") WHERE id = ?')
                    ->execute([$token, $user['id']]);
                $vaultData = $user['vault_data'];
                $displayName = $user['display_name'] ?: explode('@', $email)[0];
                $photoUrl = $user['photo_url'];
            } else {
                $token = bin2hex(random_bytes(32));
                $displayName = explode('@', $email)[0];
                $photoUrl = '';
                $stmt = $pdo->prepare('INSERT INTO vaults (google_id, email, display_name, photo_url, token, vault_data) VALUES (NULL, ?, ?, ?, ?, NULL)');
                $stmt->execute([$email, $displayName, $photoUrl, $token]);
                $vaultData = null;
            }

            echo json_encode([
                'success' => true,
                'token' => $token,
                'user' => [
                    'email' => $email,
                    'name' => $displayName,
                    'picture' => $photoUrl
                ],
                'vault_data' => $vaultData ? json_decode($vaultData, true) : null
            ]);
            exit;
        }

        // Token or Email Auth
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        $token = null;
        if (preg_match('/Bearer\s+(\S+)/i', $authHeader, $m)) {
            $token = $m[1];
        }
        if (!$token && isset($_GET['token'])) {
            $token = $_GET['token'];
        }
        
        $body = [];
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $body = json_decode(file_get_contents('php://input'), true) ?? [];
        }
        $emailParam = trim(strtolower($_GET['email'] ?? ($body['email'] ?? '')));

        $user = null;
        if ($token) {
            $stmt = $pdo->prepare('SELECT * FROM vaults WHERE token = ?');
            $stmt->execute([$token]);
            $user = $stmt->fetch();
        }
        if (!$user && $emailParam && filter_var($emailParam, FILTER_VALIDATE_EMAIL)) {
            $stmt = $pdo->prepare('SELECT * FROM vaults WHERE LOWER(email) = ?');
            $stmt->execute([$emailParam]);
            $user = $stmt->fetch();

            if (!$user) {
                // Auto-cria registro para o e-mail no primeiro salvamento
                $newToken = bin2hex(random_bytes(32));
                $displayName = explode('@', $emailParam)[0];
                $pdo->prepare('INSERT INTO vaults (email, display_name, token, vault_data) VALUES (?, ?, ?, NULL)')
                    ->execute([$emailParam, $displayName, $newToken]);
                $stmt = $pdo->prepare('SELECT * FROM vaults WHERE LOWER(email) = ?');
                $stmt->execute([$emailParam]);
                $user = $stmt->fetch();
            }
        }

        if (!$user) {
            http_response_code(401);
            echo json_encode(['success' => false, 'error' => 'Sessão não autorizada ou e-mail inválido.']);
            exit;
        }

        if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'push') {
            $body = json_decode(file_get_contents('php://input'), true) ?? [];
            $vaultData = $body['vault_data'] ?? null;

            if (!$vaultData) {
                http_response_code(400);
                echo json_encode(['success' => false, 'error' => 'Dados do cofre ausentes']);
                exit;
            }

            $pdo->prepare('UPDATE vaults SET vault_data = ?, updated_at = datetime("now") WHERE id = ?')
                ->execute([json_encode($vaultData), $user['id']]);

            echo json_encode([
                'success' => true,
                'email' => $user['email'],
                'updated_at' => time()
            ]);
            exit;
        }

        if ($_SERVER['REQUEST_METHOD'] === 'GET' && $action === 'pull') {
            $vaultData = $user['vault_data'] ? json_decode($user['vault_data'], true) : null;
            echo json_encode([
                'success' => true,
                'vault_data' => $vaultData,
                'user' => [
                    'email' => $user['email'],
                    'name' => $user['display_name'],
                    'picture' => $user['photo_url']
                ],
                'updated_at' => strtotime($user['updated_at'] ?? 'now')
            ]);
            exit;
        }

        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Ação desconhecida']);
        exit;

    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
        exit;
    }
}

// ── 2. PAGE RENDER HEADERS ─────────────────────────────────────────
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
header("Expires: Mon, 26 Jul 1997 05:00:00 GMT");
header("Cross-Origin-Opener-Policy: same-origin-allow-popups");

$v = time();
$googleClientId = '86183940183-qegicgt1h8biud5vagdhuuug6i68q5km.apps.googleusercontent.com';
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>SafePass - Cofre & Gerenciador de Senhas com Nuvem Zero-Knowledge</title>
  
  <link rel="icon" type="image/png" sizes="192x192" href="icon-192x192.png?v=<?= $v ?>">
  <link rel="apple-touch-icon" href="icon-192x192.png?v=<?= $v ?>">
  <link rel="manifest" href="manifest.json?v=<?= $v ?>">
  <meta name="theme-color" content="#0d111c">

  <!-- Configuração Dinâmica e Handler Global Google Identity -->
  <script>
    window.GOOGLE_CLIENT_ID = '<?= $googleClientId ?>';
    window._pendingGoogleResponse = null;
    window.handleGoogleAuthCallback = function(response) {
      if (typeof window._realGoogleAuthHandler === 'function') {
        window._realGoogleAuthHandler(response);
      } else {
        window._pendingGoogleResponse = response;
      }
    };
  </script>

  <!-- Google Identity Services -->
  <script src="https://accounts.google.com/gsi/client" async defer></script>

  <!-- Fonts -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Fira+Code:wght@400;500;600&family=Orbitron:wght@600;800&display=swap" rel="stylesheet">

  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
      -webkit-tap-highlight-color: transparent;
    }

    :root {
      --bg-base: #090c14;
      --bg-surface: #0f1523;
      --bg-elevated: #161e31;
      --bg-glass: rgba(22, 30, 49, 0.75);
      --border-color: rgba(255, 255, 255, 0.08);
      --border-focus: #6d4aff;
      
      --accent-primary: #6d4aff;
      --accent-hover: #7c5cff;
      --accent-glow: rgba(109, 74, 255, 0.35);
      --accent-cyan: #00e5ff;
      --accent-emerald: #10b981;
      --accent-amber: #f59e0b;
      --accent-rose: #f43f5e;
      --accent-google: #4285f4;

      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;

      --radius-sm: 8px;
      --radius-md: 14px;
      --radius-lg: 20px;
      --radius-full: 9999px;
    }

    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background-color: var(--bg-base);
      color: var(--text-main);
      min-height: 100vh;
      overflow-x: hidden;
      display: flex;
      flex-direction: column;
    }

    /* Ambient Glow Background */
    body::before {
      content: '';
      position: fixed;
      top: -20%;
      left: 10%;
      width: 80vw;
      height: 60vh;
      background: radial-gradient(circle, rgba(109, 74, 255, 0.12) 0%, rgba(0, 229, 255, 0.04) 50%, transparent 70%);
      pointer-events: none;
      z-index: 0;
    }

    /* ── LOCK / SETUP SCREEN ───────────────────────────────────── */
    #auth-screen {
      position: fixed;
      inset: 0;
      background: radial-gradient(circle at 50% 25%, #151e36 0%, #080b12 100%);
      z-index: 100;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }

    .auth-card {
      width: 100%;
      max-width: 440px;
      background: rgba(18, 25, 42, 0.85);
      backdrop-filter: blur(24px);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-lg);
      padding: 36px 30px;
      box-shadow: 0 24px 60px rgba(0, 0, 0, 0.6), 0 0 40px rgba(109, 74, 255, 0.15);
      text-align: center;
      animation: zoomIn 0.3s ease;
      position: relative;
    }

    .auth-logo-wrap {
      width: 76px;
      height: 76px;
      margin: 0 auto 16px;
      border-radius: 20px;
      background: linear-gradient(135deg, rgba(109, 74, 255, 0.25), rgba(0, 229, 255, 0.1));
      border: 1px solid rgba(255, 255, 255, 0.15);
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 8px 25px var(--accent-glow);
    }
    .auth-logo-wrap img {
      width: 52px;
      height: 52px;
      object-fit: contain;
    }

    .auth-title {
      font-family: 'Orbitron', sans-serif;
      font-size: 24px;
      font-weight: 800;
      letter-spacing: 1px;
      margin-bottom: 6px;
    }
    .auth-title span {
      color: var(--accent-primary);
    }

    .auth-desc {
      font-size: 13px;
      color: var(--text-muted);
      margin-bottom: 20px;
      line-height: 1.5;
    }

    .form-group {
      text-align: left;
      margin-bottom: 16px;
    }
    .form-label {
      display: block;
      font-size: 12px;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 6px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .input-wrap {
      position: relative;
      display: flex;
      align-items: center;
    }
    .input-field {
      width: 100%;
      height: 46px;
      background: rgba(10, 14, 24, 0.9);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-sm);
      padding: 0 42px 0 14px;
      color: var(--text-main);
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
    }
    .input-field:focus {
      border-color: var(--accent-primary);
      box-shadow: 0 0 16px var(--accent-glow);
    }
    .input-toggle-eye {
      position: absolute;
      right: 12px;
      background: none;
      border: none;
      color: var(--text-dim);
      cursor: pointer;
      font-size: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: color 0.2s;
    }
    .input-toggle-eye:hover {
      color: var(--text-main);
    }

    .btn-primary {
      width: 100%;
      height: 48px;
      background: linear-gradient(135deg, var(--accent-primary) 0%, #4f2ce0 100%);
      color: #fff;
      border: none;
      border-radius: var(--radius-sm);
      font-size: 14px;
      font-weight: 700;
      cursor: pointer;
      box-shadow: 0 6px 20px var(--accent-glow);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      transition: all 0.2s ease;
      margin-top: 8px;
    }
    .btn-primary:hover {
      transform: translateY(-1px);
      box-shadow: 0 8px 25px rgba(109, 74, 255, 0.5);
      filter: brightness(1.1);
    }
    .btn-primary:active {
      transform: translateY(0);
    }

    .btn-google-sync {
      width: 100%;
      height: 44px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.12);
      color: #fff;
      border-radius: var(--radius-sm);
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      margin-top: 12px;
      transition: all 0.2s;
    }
    .btn-google-sync:hover {
      background: rgba(66, 133, 244, 0.15);
      border-color: var(--accent-google);
      color: #fff;
    }

    .badge-secure {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.3);
      color: var(--accent-emerald);
      padding: 4px 10px;
      border-radius: var(--radius-full);
      font-size: 11px;
      font-weight: 600;
      margin-top: 18px;
    }

    /* ── APP LAYOUT (3 COLUMNS) ────────────────────────────────── */
    #app-container {
      display: none;
      height: 100vh;
      width: 100vw;
      overflow: hidden;
      position: relative;
      z-index: 1;
    }
    #app-container.active {
      display: flex;
    }

    /* 1. Sidebar (Navigation) */
    .sidebar {
      width: 270px;
      background: var(--bg-surface);
      border-right: 1px solid var(--border-color);
      display: flex;
      flex-direction: column;
      flex-shrink: 0;
      z-index: 10;
    }

    .sidebar-header {
      padding: 18px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid var(--border-color);
    }
    .brand-logo {
      display: flex;
      align-items: center;
      gap: 10px;
      text-decoration: none;
      color: #fff;
    }
    .brand-logo img {
      width: 32px;
      height: 32px;
    }
    .brand-logo h1 {
      font-family: 'Orbitron', sans-serif;
      font-size: 16px;
      font-weight: 800;
      letter-spacing: 0.5px;
    }
    .brand-logo h1 span {
      color: var(--accent-primary);
    }

    .sidebar-nav {
      padding: 14px 12px;
      flex: 1;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .nav-section-title {
      font-size: 11px;
      font-weight: 700;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 1px;
      padding: 10px 10px 4px;
    }

    .nav-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 9px 12px;
      border-radius: var(--radius-sm);
      color: var(--text-muted);
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s ease;
      user-select: none;
    }
    .nav-item-left {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .nav-item-icon {
      font-size: 16px;
      width: 20px;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .nav-item:hover {
      background: rgba(255, 255, 255, 0.04);
      color: var(--text-main);
    }
    .nav-item.active {
      background: rgba(109, 74, 255, 0.15);
      color: #fff;
      font-weight: 600;
    }
    .nav-item.active .nav-item-icon {
      color: var(--accent-primary);
    }
    .nav-badge {
      font-size: 11px;
      font-family: 'Fira Code', monospace;
      padding: 2px 7px;
      background: rgba(255, 255, 255, 0.06);
      border-radius: var(--radius-full);
      color: var(--text-dim);
    }
    .nav-item.active .nav-badge {
      background: var(--accent-primary);
      color: #fff;
    }

    /* Nuvem Segura Sidebar Card (Cyber-Glass Design) */
    .cloud-sync-card {
      background: linear-gradient(145deg, rgba(26, 36, 60, 0.75), rgba(13, 17, 28, 0.95));
      border: 1px solid rgba(99, 102, 241, 0.22);
      border-radius: var(--radius-md);
      padding: 12px 14px;
      margin: 8px 4px 6px 4px;
      display: flex;
      flex-direction: column;
      gap: 10px;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.35);
      position: relative;
      overflow: hidden;
      transition: all 0.25s ease;
    }
    .cloud-sync-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 2px;
      background: linear-gradient(90deg, #6366f1, #10b981, #06b6d4);
      opacity: 0.85;
    }
    .cloud-sync-card:hover {
      border-color: rgba(99, 102, 241, 0.45);
      box-shadow: 0 6px 20px rgba(99, 102, 241, 0.18);
      transform: translateY(-1px);
    }
    .cloud-sync-header {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .cloud-avatar {
      width: 36px;
      height: 36px;
      min-width: 36px;
      border-radius: 50%;
      background: linear-gradient(135deg, #6366f1, #8b5cf6);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 14px;
      font-weight: 700;
      color: #fff;
      overflow: hidden;
      border: 1.5px solid rgba(255, 255, 255, 0.2);
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
    }
    .cloud-avatar img {
      width: 100%;
      height: 100%;
      object-fit: cover;
      display: block;
      border-radius: 50%;
    }
    .cloud-info {
      display: flex;
      flex-direction: column;
      gap: 2px;
      overflow: hidden;
      flex: 1;
    }
    .cloud-title {
      font-size: 13px;
      font-weight: 700;
      color: #ffffff;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      line-height: 1.2;
    }
    .cloud-sub {
      font-size: 11px;
      font-weight: 500;
      color: var(--accent-emerald);
      display: flex;
      align-items: center;
      gap: 4px;
      line-height: 1.2;
    }
    .btn-cloud-action {
      background: rgba(99, 102, 241, 0.12);
      border: 1px solid rgba(99, 102, 241, 0.3);
      color: #e0e7ff;
      padding: 8px 12px;
      border-radius: var(--radius-sm);
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      transition: all 0.2s ease;
      width: 100%;
    }
    .btn-cloud-action:hover {
      background: rgba(99, 102, 241, 0.28);
      border-color: var(--accent-primary);
      color: #ffffff;
      box-shadow: 0 2px 12px rgba(99, 102, 241, 0.3);
    }

    .sidebar-footer {
      padding: 14px 16px;
      border-top: 1px solid var(--border-color);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }
    .btn-icon-action {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-color);
      color: var(--text-muted);
      width: 36px;
      height: 36px;
      border-radius: var(--radius-sm);
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      font-size: 15px;
      transition: all 0.2s ease;
    }
    .btn-icon-action:hover {
      background: rgba(255, 255, 255, 0.1);
      color: #fff;
      border-color: rgba(255, 255, 255, 0.2);
    }

    /* 2. Middle Column (Items List) */
    .items-column {
      width: 380px;
      background: rgba(11, 15, 25, 0.95);
      border-right: 1px solid var(--border-color);
      display: flex;
      flex-direction: column;
      flex-shrink: 0;
    }

    .items-header {
      padding: 16px;
      border-bottom: 1px solid var(--border-color);
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .items-header-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .items-header-title {
      font-size: 16px;
      font-weight: 700;
      color: #fff;
    }

    .btn-new-item {
      background: var(--accent-primary);
      color: #fff;
      border: none;
      padding: 7px 14px;
      border-radius: var(--radius-sm);
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 6px;
      transition: all 0.2s ease;
      box-shadow: 0 4px 12px var(--accent-glow);
    }
    .btn-new-item:hover {
      background: var(--accent-hover);
      transform: translateY(-1px);
    }

    .search-box {
      position: relative;
      display: flex;
      align-items: center;
    }
    .search-box-icon {
      position: absolute;
      left: 12px;
      color: var(--text-dim);
      font-size: 13px;
      pointer-events: none;
    }
    .search-box input {
      width: 100%;
      height: 38px;
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-sm);
      padding: 0 12px 0 34px;
      color: #fff;
      font-size: 13px;
      outline: none;
      transition: all 0.2s;
    }
    .search-box input:focus {
      border-color: var(--accent-primary);
      box-shadow: 0 0 10px var(--accent-glow);
    }

    .items-list {
      flex: 1;
      overflow-y: auto;
      padding: 8px;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .vault-item-card {
      padding: 12px 14px;
      border-radius: var(--radius-sm);
      border: 1px solid transparent;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 12px;
      transition: all 0.15s ease;
    }
    .vault-item-card:hover {
      background: rgba(255, 255, 255, 0.03);
      border-color: rgba(255, 255, 255, 0.05);
    }
    .vault-item-card.active {
      background: rgba(109, 74, 255, 0.12);
      border-color: rgba(109, 74, 255, 0.4);
    }

    .vault-item-icon {
      width: 38px;
      height: 38px;
      border-radius: 10px;
      background: var(--bg-elevated);
      border: 1px solid var(--border-color);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 18px;
      flex-shrink: 0;
    }
    .vault-item-icon.login { color: var(--accent-primary); background: rgba(109, 74, 255, 0.15); }
    .vault-item-icon.card { color: var(--accent-emerald); background: rgba(16, 185, 129, 0.15); }
    .vault-item-icon.note { color: var(--accent-amber); background: rgba(245, 158, 11, 0.15); }
    .vault-item-icon.alias { color: var(--accent-cyan); background: rgba(0, 229, 255, 0.15); }

    .vault-item-info {
      flex: 1;
      min-width: 0;
    }
    .vault-item-title {
      font-size: 13px;
      font-weight: 600;
      color: #fff;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      margin-bottom: 2px;
    }
    .vault-item-sub {
      font-size: 11px;
      color: var(--text-dim);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 40px 20px;
      text-align: center;
      color: var(--text-dim);
      gap: 10px;
      font-size: 13px;
    }
    .empty-state-icon {
      font-size: 36px;
      opacity: 0.6;
    }

    /* 3. Right Column (Item Details & Editor) */
    .details-column {
      flex: 1;
      background: var(--bg-base);
      display: flex;
      flex-direction: column;
      overflow-y: auto;
      position: relative;
    }

    .details-header {
      padding: 16px 24px;
      border-bottom: 1px solid var(--border-color);
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: var(--bg-surface);
    }
    .details-actions {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .details-body {
      padding: 28px 32px;
      max-width: 760px;
      width: 100%;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      gap: 20px;
    }

    .item-hero {
      display: flex;
      align-items: center;
      gap: 16px;
      margin-bottom: 10px;
    }
    .item-hero-icon {
      width: 56px;
      height: 56px;
      border-radius: 16px;
      background: var(--bg-elevated);
      border: 1px solid var(--border-color);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 26px;
    }
    .item-hero-text h2 {
      font-size: 20px;
      font-weight: 700;
      color: #fff;
    }
    .item-hero-text span {
      font-size: 12px;
      color: var(--text-muted);
    }

    .field-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-md);
      padding: 14px 18px;
      display: flex;
      flex-direction: column;
      gap: 6px;
      position: relative;
    }
    .field-card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .field-label {
      font-size: 11px;
      font-weight: 700;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .field-value {
      font-size: 15px;
      font-weight: 500;
      color: #fff;
      word-break: break-all;
      font-family: 'Fira Code', monospace;
    }
    .field-value.masked {
      letter-spacing: 3px;
    }

    .field-actions-row {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .btn-field-action {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-color);
      color: var(--text-muted);
      padding: 5px 10px;
      border-radius: var(--radius-sm);
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 4px;
      transition: all 0.15s;
    }
    .btn-field-action:hover {
      background: rgba(255, 255, 255, 0.1);
      color: #fff;
    }

    /* TOTP Live Counter */
    .totp-box {
      background: linear-gradient(135deg, rgba(109, 74, 255, 0.15), rgba(0, 229, 255, 0.05));
      border: 1px solid rgba(109, 74, 255, 0.3);
      border-radius: var(--radius-md);
      padding: 16px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .totp-code-wrap {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .totp-code {
      font-family: 'Fira Code', monospace;
      font-size: 28px;
      font-weight: 700;
      color: var(--accent-cyan);
      letter-spacing: 4px;
    }
    .totp-timer {
      font-size: 11px;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .totp-progress-ring {
      width: 22px;
      height: 22px;
      transform: rotate(-90deg);
    }
    .totp-progress-ring circle {
      fill: none;
      stroke-width: 3;
    }

    /* ── MODALS (GERADOR / EDITOR / AUDITORIA / IMPORT / GDRIVE) ─ */
    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.75);
      backdrop-filter: blur(16px);
      z-index: 1000;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      opacity: 0;
      pointer-events: none;
      transition: all 0.2s ease;
    }
    .modal-overlay.active {
      opacity: 1;
      pointer-events: auto;
    }

    .modal-box {
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-lg);
      width: 100%;
      max-width: 540px;
      max-height: 90vh;
      display: flex;
      flex-direction: column;
      box-shadow: 0 24px 60px rgba(0, 0, 0, 0.7), 0 0 30px var(--accent-glow);
      overflow: hidden;
      transform: scale(0.95);
      transition: transform 0.2s ease;
    }
    .modal-box form {
      display: flex;
      flex-direction: column;
      flex: 1;
      min-height: 0;
      overflow: hidden;
    }
    .modal-overlay.active .modal-box {
      transform: scale(1);
    }

    .modal-header {
      padding: 18px 24px;
      border-bottom: 1px solid var(--border-color);
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-shrink: 0;
    }
    .modal-header h3 {
      font-size: 16px;
      font-weight: 700;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .modal-close-btn {
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid rgba(255, 255, 255, 0.1);
      color: var(--text-muted);
      font-size: 16px;
      width: 32px;
      height: 32px;
      border-radius: 50%;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.2s ease;
      line-height: 1;
    }
    .modal-close-btn:hover {
      background: rgba(239, 68, 68, 0.18);
      border-color: rgba(239, 68, 68, 0.4);
      color: var(--accent-rose);
      transform: rotate(90deg);
    }

    .modal-body {
      padding: 20px 24px;
      overflow-y: auto;
      -webkit-overflow-scrolling: touch;
      display: flex;
      flex-direction: column;
      gap: 16px;
      flex: 1;
      min-height: 0;
    }

    .modal-footer {
      padding: 16px 24px;
      border-top: 1px solid var(--border-color);
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: 12px;
      background: rgba(11, 15, 25, 0.6);
      flex-shrink: 0;
    }
    .modal-footer .btn-primary,
    .modal-footer .btn-secondary {
      height: 38px;
      padding: 0 20px;
      font-size: 13px;
      font-weight: 600;
      border-radius: var(--radius-sm);
      margin: 0;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }

    .btn-secondary {
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid rgba(255, 255, 255, 0.14);
      color: #e2e8f0;
      padding: 10px 18px;
      border-radius: var(--radius-sm);
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.12);
      border-color: rgba(255, 255, 255, 0.28);
      color: #ffffff;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
    }

    /* Password Generator Box */
    .generator-display {
      background: rgba(0, 0, 0, 0.5);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-md);
      padding: 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
    }
    .generated-pass-text {
      font-family: 'Fira Code', monospace;
      font-size: 16px;
      font-weight: 600;
      color: var(--accent-cyan);
      word-break: break-all;
    }

    .slider-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-top: 8px;
    }
    .range-slider {
      flex: 1;
      accent-color: var(--accent-primary);
    }

    .checkbox-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
      margin-top: 8px;
    }
    .checkbox-item {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 13px;
      color: var(--text-muted);
      cursor: pointer;
    }
    .checkbox-item input {
      accent-color: var(--accent-primary);
    }

    /* Health Auditor Cards */
    .health-score-card {
      background: linear-gradient(135deg, rgba(16, 185, 129, 0.15), rgba(109, 74, 255, 0.1));
      border: 1px solid rgba(16, 185, 129, 0.3);
      border-radius: var(--radius-md);
      padding: 18px 22px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    /* Toast Notification */
    #toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: rgba(18, 25, 42, 0.95);
      border: 1px solid var(--accent-primary);
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.8), 0 0 20px var(--accent-glow);
      color: #fff;
      padding: 12px 20px;
      border-radius: var(--radius-md);
      font-size: 13px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
      z-index: 9999;
      transform: translateY(100px);
      opacity: 0;
      transition: all 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
    }
    #toast.show {
      transform: translateY(0);
      opacity: 1;
    }

    @keyframes zoomIn {
      from { opacity: 0; transform: scale(0.92); }
      to { opacity: 1; transform: scale(1); }
    }

    /* Responsive adjustments */
    @media (max-width: 900px) {
      .sidebar {
        width: 68px;
        min-width: 68px;
      }
      .sidebar-header {
        padding: 14px 10px;
        justify-content: center;
      }
      .brand-logo {
        gap: 0;
        justify-content: center;
      }
      .brand-logo h1, .nav-item-text, .nav-badge, .nav-section-title, .gdrive-card {
        display: none !important;
      }
      .nav-item {
        justify-content: center;
        padding: 12px 6px;
        border-radius: var(--radius-md);
      }
      .nav-item-left {
        gap: 0;
        justify-content: center;
      }
      .nav-item-icon {
        font-size: 18px;
        width: auto;
      }

      /* Rodapé da Barra Lateral em Mobile (Botões Empilhados e Centralizados) */
      .sidebar-footer {
        flex-direction: column;
        align-items: center;
        justify-content: center;
        gap: 10px;
        padding: 10px 4px 14px 4px;
        border-top: 1px solid var(--border-color);
      }
      .sidebar-footer .btn-icon-action {
        width: 42px;
        height: 42px;
        min-width: 42px;
        border-radius: 12px;
        font-size: 17px;
        background: rgba(255, 255, 255, 0.06);
        border: 1px solid rgba(255, 255, 255, 0.12);
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .sidebar-footer .btn-icon-action:hover, .sidebar-footer .btn-icon-action:active {
        background: rgba(109, 74, 255, 0.25);
        border-color: var(--accent-primary);
        color: #fff;
      }

      /* Header e Botão Novo Item */
      .items-column {
        width: 100%;
        flex: 1;
        min-width: 0;
      }
      .items-header {
        padding: 12px 14px;
        gap: 10px;
      }
      .items-header-top {
        gap: 8px;
        min-width: 0;
      }
      .items-header-title {
        font-size: 16px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        min-width: 0;
      }
      .btn-new-item {
        padding: 6px 12px;
        font-size: 12px;
        white-space: nowrap;
        flex-shrink: 0;
        gap: 4px;
      }

      .details-column {
        display: none;
        position: fixed;
        inset: 0;
        z-index: 50;
        background: var(--bg-base);
      }
      .details-column.mobile-open {
        display: flex;
      }

      /* Modais no Mobile (Centralizados e Fluidos) */
      .modal-overlay {
        padding: 12px;
        align-items: center;
        justify-content: center;
      }
      .modal-box {
        max-width: 100% !important;
        width: 100% !important;
        max-height: 92vh !important;
        border-radius: var(--radius-md);
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.85);
        display: flex;
        flex-direction: column;
        overflow: hidden;
      }
      .modal-box form {
        display: flex;
        flex-direction: column;
        flex: 1;
        min-height: 0;
        overflow: hidden;
      }
      .modal-header {
        padding: 14px 16px;
        flex-shrink: 0;
      }
      .modal-header h3 {
        font-size: 14px;
        line-height: 1.3;
      }
      .modal-body {
        padding: 16px 14px;
        gap: 12px;
        flex: 1;
        min-height: 0;
        overflow-y: auto !important;
        -webkit-overflow-scrolling: touch !important;
      }
      .modal-footer {
        padding: 12px 14px;
        justify-content: stretch;
        flex-shrink: 0;
      }
      .modal-footer .btn-secondary,
      .modal-footer .btn-primary {
        flex: 1;
        width: 100%;
      }
    }

    @media (max-width: 420px) {
      .sidebar {
        width: 62px;
        min-width: 62px;
      }
      .items-header {
        padding: 10px 12px;
      }
      .items-header-title {
        font-size: 15px;
      }
      .btn-new-item {
        padding: 6px 10px;
        font-size: 11px;
      }
      .modal-header h3 {
        font-size: 13px;
      }
    }
  </style>
</head>
<body>

  <!-- ── 1. AUTH SCREEN (LOGIN / INITIAL SETUP) ────────────────── -->
  <div id="auth-screen">
    <div class="auth-card">
      <div class="auth-logo-wrap">
        <img src="icon-192x192.png?v=<?= $v ?>" alt="SafePass Logo">
      </div>
      <h2 class="auth-title">Safe<span>Pass</span></h2>
      <p class="auth-desc" id="auth-desc">Cofre de senhas pessoal criptografado ponta a ponta (Zero-Knowledge).</p>

      <!-- Badge de Usuário Conectado com opção de trocar -->
      <div id="auth-user-connected" style="display:none; align-items:center; justify-content:space-between; background:rgba(66,133,244,0.1); border:1px solid rgba(66,133,244,0.3); border-radius:12px; padding:10px 14px; margin-bottom:16px;">
        <div style="display:flex; align-items:center; gap:10px;">
          <img id="auth-connected-avatar" src="" alt="Avatar" style="width:36px; height:36px; border-radius:50%; display:none; border:2px solid #4285f4;">
          <div style="font-size:13px; text-align:left;">
            <div id="auth-connected-name" style="font-weight:700; color:#fff;"></div>
            <div id="auth-connected-email" style="font-size:11.5px; color:var(--text-muted);"></div>
          </div>
        </div>
        <div style="display:flex; flex-direction:column; align-items:flex-end; gap:4px;">
          <span style="font-size:10px; background:#4285f4; color:#fff; padding:2px 8px; border-radius:20px; font-weight:700;">📁 Drive SafePass</span>
          <a href="javascript:void(0)" onclick="disconnectCloud()" style="font-size:10.5px; color:var(--accent-rose); text-decoration:underline;">Trocar Conta</a>
        </div>
      </div>

      <!-- Botão Rápido de Login com Google -->
      <div id="auth-google-quick-btn" style="margin-bottom: 14px;">
        <button type="button" class="btn-primary" style="background:#ffffff; color:#1f2937; border:1px solid rgba(0,0,0,0.15); font-weight:600; font-size:13.5px; width:100%; display:flex; align-items:center; justify-content:center; gap:10px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);" onclick="triggerGoogleOAuth()">
          <svg width="20" height="20" viewBox="0 0 48 48">
            <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
            <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
            <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
            <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
          </svg>
          <span>Entrar com Conta Google</span>
        </button>
        <div style="display:flex; align-items:center; gap:10px; margin: 12px 0 6px 0;">
          <div style="flex:1; height:1px; background:rgba(255,255,255,0.1);"></div>
          <span style="font-size:11px; color:var(--text-dim); text-transform:uppercase; letter-spacing:0.5px;">ou com E-mail</span>
          <div style="flex:1; height:1px; background:rgba(255,255,255,0.1);"></div>
        </div>
      </div>

      <form id="auth-form" onsubmit="handleAuthSubmit(event)">
        <!-- Campo E-mail / Usuário -->
        <div class="form-group" id="auth-email-group">
          <label class="form-label" for="auth-email">E-mail / Conta</label>
          <div class="input-wrap">
            <input type="email" id="auth-email" class="input-field" placeholder="seuemail@gmail.com" required>
          </div>
        </div>

        <div class="form-group">
          <label class="form-label" for="master-pass">Senha Mestra</label>
          <div class="input-wrap">
            <input type="password" id="master-pass" class="input-field" placeholder="Digite sua senha mestra..." required autofocus>
            <button type="button" class="input-toggle-eye" onclick="togglePasswordVisibility('master-pass')">👁️</button>
          </div>
        </div>

        <div class="form-group" id="confirm-pass-group" style="display: none;">
          <label class="form-label" for="confirm-pass">Confirmar Senha Mestra</label>
          <div class="input-wrap">
            <input type="password" id="confirm-pass" class="input-field" placeholder="Confirme sua senha mestra...">
            <button type="button" class="input-toggle-eye" onclick="togglePasswordVisibility('confirm-pass')">👁️</button>
          </div>
        </div>

        <button type="submit" class="btn-primary" id="btn-auth-submit">
          <span>🔓</span> Desbloquear Cofre
        </button>

        <!-- Botão Desbloqueio por Biometria / Digital -->
        <div id="biometric-auth-box" style="display: none; margin-top: 10px;">
          <button type="button" class="btn-primary" id="btn-biometric-auth" onclick="handleBiometricUnlock()" style="background: linear-gradient(135deg, rgba(16, 185, 129, 0.25), rgba(6, 182, 212, 0.25)); border: 1.5px solid var(--accent-emerald); color: #fff; margin-top: 0; gap: 8px; width: 100%; font-weight: 700; box-shadow: 0 4px 16px rgba(16, 185, 129, 0.2);">
            <span style="font-size: 18px;">👆</span> <span>Desbloquear com Digital</span>
          </button>
        </div>
      </form>

      <div class="badge-secure">
        <span>🛡️</span> Criptografia Militar AES-256-GCM
      </div>
    </div>
  </div>

  <!-- ── 2. MAIN APP INTERFACE ─────────────────────────────────── -->
  <div id="app-container">
    
    <!-- COLUNA 1: SIDEBAR -->
    <aside class="sidebar">
      <div class="sidebar-header">
        <a href="javascript:void(0)" onclick="location.reload()" class="brand-logo" title="Recarregar SafePass (F5)" style="cursor: pointer;">
          <img src="icon-192x192.png?v=<?= $v ?>" alt="Logo">
          <h1>Safe<span>Pass</span></h1>
        </a>
      </div>

      <nav class="sidebar-nav">
        <div class="nav-section-title">Cofre</div>
        <div class="nav-item active" data-filter="all" onclick="setCategoryFilter('all')">
          <div class="nav-item-left">
            <span class="nav-item-icon">🗄️</span>
            <span class="nav-item-text">Todos os Itens</span>
          </div>
          <span class="nav-badge" id="count-all">0</span>
        </div>
        <div class="nav-item" data-filter="favorite" onclick="setCategoryFilter('favorite')">
          <div class="nav-item-left">
            <span class="nav-item-icon">⭐</span>
            <span class="nav-item-text">Favoritos</span>
          </div>
          <span class="nav-badge" id="count-fav">0</span>
        </div>

        <div class="nav-section-title">Categorias</div>
        <div class="nav-item" data-filter="login" onclick="setCategoryFilter('login')">
          <div class="nav-item-left">
            <span class="nav-item-icon">🔑</span>
            <span class="nav-item-text">Logins</span>
          </div>
          <span class="nav-badge" id="count-login">0</span>
        </div>
        <div class="nav-item" data-filter="card" onclick="setCategoryFilter('card')">
          <div class="nav-item-left">
            <span class="nav-item-icon">💳</span>
            <span class="nav-item-text">Cartões</span>
          </div>
          <span class="nav-badge" id="count-card">0</span>
        </div>
        <div class="nav-item" data-filter="note" onclick="setCategoryFilter('note')">
          <div class="nav-item-left">
            <span class="nav-item-icon">📝</span>
            <span class="nav-item-text">Notas Seguras</span>
          </div>
          <span class="nav-badge" id="count-note">0</span>
        </div>
        <div class="nav-item" data-filter="alias" onclick="setCategoryFilter('alias')">
          <div class="nav-item-left">
            <span class="nav-item-icon">📧</span>
            <span class="nav-item-text">Aliases de E-mail</span>
          </div>
          <span class="nav-badge" id="count-alias">0</span>
        </div>

        <div class="nav-section-title">Ferramentas</div>
        <div class="nav-item" onclick="openGeneratorModal()" title="Gerador de Senha">
          <div class="nav-item-left">
            <span class="nav-item-icon">⚡</span>
            <span class="nav-item-text">Gerador de Senha</span>
          </div>
        </div>
        <div class="nav-item" onclick="openHealthModal()" title="Auditoria de Saúde">
          <div class="nav-item-left">
            <span class="nav-item-icon">🛡️</span>
            <span class="nav-item-text">Auditoria de Saúde</span>
          </div>
        </div>
        <div class="nav-item" id="nav-btn-install" onclick="triggerPwaInstall()" title="Instalar SafePass no Celular" style="color: var(--accent-cyan);">
          <div class="nav-item-left">
            <span class="nav-item-icon">📲</span>
            <span class="nav-item-text">Instalar App</span>
          </div>
          <span class="nav-badge" style="background: rgba(6, 182, 212, 0.18); color: var(--accent-cyan); font-weight: 700;">PWA</span>
        </div>

        <div class="nav-section-title">Nuvem Segura</div>
        <div class="nav-item" id="nav-btn-cloud" onclick="openCloudModal()" title="Sincronização em Nuvem (4U)" style="color: var(--accent-emerald);">
          <div class="nav-item-left">
            <span class="nav-item-icon" id="sidebar-cloud-avatar">☁️</span>
            <span class="nav-item-text" id="sidebar-cloud-title">Nuvem 4U</span>
          </div>
          <span class="nav-badge" id="sidebar-cloud-status" style="background: rgba(16, 185, 129, 0.15); color: var(--accent-emerald); font-weight: 700;">🟢</span>
        </div>
      </nav>

      <div class="sidebar-footer">
        <button class="btn-icon-action" onclick="openSettingsModal()" title="Configurações / Backup">⚙️</button>
        <button class="btn-icon-action" onclick="lockVault()" title="Bloquear Cofre (Ctrl+L)">🔒</button>
      </div>
    </aside>

    <!-- COLUNA 2: LISTA DE ITENS -->
    <section class="items-column">
      <div class="items-header">
        <div class="items-header-top">
          <h2 class="items-header-title" id="current-view-title">Todos os Itens</h2>
          <button class="btn-new-item" onclick="openNewItemModal()">
            <span>+</span> Novo Item
          </button>
        </div>
        <div class="search-box">
          <span class="search-box-icon">🔍</span>
          <input type="text" id="search-input" placeholder="Pesquisar no cofre..." oninput="handleSearch(this.value)">
        </div>
      </div>

      <div class="items-list" id="items-list-container">
        <!-- Rendered dynamically -->
      </div>
    </section>

    <!-- COLUNA 3: DETALHES DO ITEM -->
    <main class="details-column" id="details-column">
      <div class="details-header" id="details-header" style="display: none;">
        <button class="btn-secondary" onclick="closeMobileDetails()" style="display: none;" id="btn-back-mobile">← Voltar</button>
        <div class="details-actions">
          <button class="btn-icon-action" id="btn-toggle-favorite" onclick="toggleItemFavorite()" title="Favoritar">⭐</button>
          <button class="btn-icon-action" onclick="editCurrentItem()" title="Editar">✏️</button>
          <button class="btn-icon-action" onclick="deleteCurrentItem()" title="Excluir" style="color: var(--accent-rose);">🗑️</button>
        </div>
      </div>

      <div class="details-body" id="details-body">
        <div class="empty-state" style="margin-top: 100px;">
          <span class="empty-state-icon">🛡️</span>
          <p>Selecione um item na lista para ver seus detalhes criptografados.</p>
        </div>
      </div>
    </main>

  </div>

  <!-- ── MODAL: NOVO / EDITAR ITEM ─────────────────────────────── -->
  <div class="modal-overlay" id="modal-item">
    <div class="modal-box">
      <div class="modal-header">
        <h3 id="modal-item-title"><span>🔑</span> Novo Login</h3>
        <button class="modal-close-btn" onclick="closeItemModal()">×</button>
      </div>
      <form id="item-form" onsubmit="saveItem(event)">
        <div class="modal-body">
          <div class="form-group">
            <label class="form-label">Tipo de Item</label>
            <select id="item-type" class="input-field" onchange="handleTypeChange(this.value)">
              <option value="login">🔑 Login (Conta de Usuário)</option>
              <option value="card">💳 Cartão de Crédito</option>
              <option value="note">📝 Nota Segura</option>
              <option value="alias">📧 Alias de E-mail (Hide-my-email)</option>
            </select>
          </div>

          <div class="form-group">
            <label class="form-label">Título / Nome do Serviço</label>
            <input type="text" id="item-title" class="input-field" placeholder="Ex: Google, Netflix, Banco..." required>
          </div>

          <!-- Fields for Login -->
          <div id="fields-login">
            <div class="form-group">
              <label class="form-label">URL do Site</label>
              <input type="url" id="item-url" class="input-field" placeholder="https://exemplo.com">
            </div>
            <div class="form-group">
              <label class="form-label">Usuário / E-mail</label>
              <input type="text" id="item-username" class="input-field" placeholder="seuemail@gmail.com">
            </div>
            <div class="form-group">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                <label class="form-label" style="margin:0;">Senha</label>
                <button type="button" class="btn-field-action" onclick="generatePasswordIntoInput('item-password')">⚡ Gerar Forte</button>
              </div>
              <div class="input-wrap">
                <input type="password" id="item-password" class="input-field" placeholder="Sua senha secreta...">
                <button type="button" class="input-toggle-eye" onclick="togglePasswordVisibility('item-password')">👁️</button>
              </div>
            </div>
            <div class="form-group">
              <label class="form-label">Chave 2FA / TOTP (Opcional)</label>
              <input type="text" id="item-totp" class="input-field" placeholder="Segredo Base32 (ex: JBSWY3DPEHPK3PXP)">
            </div>
          </div>

          <!-- Fields for Card -->
          <div id="fields-card" style="display: none;">
            <div class="form-group">
              <label class="form-label">Nome no Cartão</label>
              <input type="text" id="item-cardholder" class="input-field" placeholder="NOME COMO NO CARTAO">
            </div>
            <div class="form-group">
              <label class="form-label">Número do Cartão</label>
              <input type="text" id="item-cardnumber" class="input-field" placeholder="0000 0000 0000 0000" maxlength="19">
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
              <div class="form-group">
                <label class="form-label">Validade (MM/AA)</label>
                <input type="text" id="item-cardexp" class="input-field" placeholder="12/28" maxlength="5">
              </div>
              <div class="form-group">
                <label class="form-label">Código CVV</label>
                <input type="password" id="item-cardcvv" class="input-field" placeholder="123" maxlength="4">
              </div>
            </div>
          </div>

          <!-- Fields for Alias -->
          <div id="fields-alias" style="display: none;">
            <div class="form-group">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                <label class="form-label" style="margin:0;">Alias Gerado</label>
                <button type="button" class="btn-field-action" onclick="generateNewAlias()">🎲 Gerar Novo</button>
              </div>
              <input type="email" id="item-alias-email" class="input-field" placeholder="alias.aleatorio@4u.ia.br">
            </div>
            <div class="form-group">
              <label class="form-label">Encaminhar Para (Seu E-mail Real)</label>
              <input type="email" id="item-alias-target" class="input-field" placeholder="fbr4g4@gmail.com">
            </div>
          </div>

          <!-- Notes Field (All Types) -->
          <div class="form-group">
            <label class="form-label">Notas Adicionais</label>
            <textarea id="item-notes" class="input-field" style="height: 80px; padding-top: 10px;" placeholder="Anotações confidenciais..."></textarea>
          </div>
        </div>

        <div class="modal-footer">
          <button type="button" class="btn-secondary" onclick="closeItemModal()">Cancelar</button>
          <button type="submit" class="btn-primary" style="width: auto; margin:0;">Salvar no Cofre</button>
        </div>
      </form>
    </div>
  </div>

  <!-- ── MODAL: NUVEM ZERO-KNOWLEDGE ───────────────────────────── -->
  <div class="modal-overlay" id="modal-cloud">
    <div class="modal-box">
      <div class="modal-header">
        <h3><span>☁️</span> Nuvem Zero-Knowledge</h3>
        <button class="modal-close-btn" onclick="closeCloudModal()">×</button>
      </div>
      <div class="modal-body">
        <div style="background:rgba(109,74,255,0.12); border:1px solid rgba(109,74,255,0.3); border-radius:12px; padding:14px;">
          <h4 style="font-size:13.5px; font-weight:700; color:#fff; margin-bottom:4px;">🛡️ Privacidade Militar Garantida:</h4>
          <p style="font-size:12px; color:var(--text-muted); line-height:1.5;">
            Suas senhas são criptografadas com <strong>AES-256-GCM</strong> no seu próprio navegador antes de serem enviadas. O servidor guarda apenas bytes embaralhados e <strong>não tem acesso à sua Senha Mestra</strong>.
          </p>
        </div>

        <div id="cloud-connected-view" style="display: none; flex-direction: column; gap: 10px;">
          <div class="field-card">
            <span class="field-label">Conta Conectada</span>
            <div class="field-value" id="cloud-modal-email" style="font-family:'Inter'; font-size:13px;">...</div>
          </div>
          <div class="field-card" style="background:rgba(66, 133, 244, 0.08); border-color:rgba(66, 133, 244, 0.3);">
            <span class="field-label" style="color:#4285F4; font-weight:700;">📁 Pasta Google Drive</span>
            <div class="field-value" style="font-family:'Inter'; font-size:13px; font-weight:600; color:var(--text-main); display:flex; align-items:center; gap:6px;">
              <span>SafePass / safepass_vault.json</span>
              <span class="badge badge-success" style="font-size:10px; padding:2px 6px;">Sincronizado</span>
            </div>
          </div>
          <div class="field-card">
            <span class="field-label">Última Sincronização</span>
            <div class="field-value" id="cloud-modal-last-sync" style="font-family:'Inter'; font-size:13px;">Agora mesmo</div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 8px;">
            <button class="btn-primary" style="margin:0;" onclick="pushToCloud(true)">📤 Enviar Agora</button>
            <button class="btn-secondary" onclick="pullFromCloud(true)">📥 Puxar do Drive</button>
          </div>
          <button class="btn-secondary" style="color:var(--accent-rose); border-color:var(--accent-rose); margin-top:6px;" onclick="disconnectCloud()">Desconectar Desta Conta</button>
        </div>

        <div id="cloud-disconnected-view" style="display: flex; flex-direction: column; gap: 10px;">
          <p style="font-size:12px; color:var(--text-muted); text-align:center; margin-top:4px;">Conecte sua conta Google para sincronizar seu cofre com a Nuvem 4U e a Extensão do navegador.</p>
          <button type="button" class="btn-primary" style="background:#ffffff; color:#1f2937; border:1px solid rgba(0,0,0,0.12); margin-top:4px; font-weight:600; font-size:13.5px; width:100%; display:flex; align-items:center; justify-content:center; gap:10px;" onclick="triggerGoogleOAuth()">
            <svg width="20" height="20" viewBox="0 0 48 48">
              <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
              <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
              <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
              <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
            </svg>
            <span>Conectar Conta Google</span>
          </button>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn-secondary" onclick="closeCloudModal()">Fechar</button>
      </div>
    </div>
  </div>

  <!-- ── MODAL: GERADOR DE SENHAS ──────────────────────────────── -->
  <div class="modal-overlay" id="modal-generator">
    <div class="modal-box">
      <div class="modal-header">
        <h3><span>⚡</span> Gerador de Senhas Seguras</h3>
        <button class="modal-close-btn" onclick="closeGeneratorModal()">×</button>
      </div>
      <div class="modal-body">
        <div class="generator-display">
          <span class="generated-pass-text" id="gen-output">...</span>
          <button class="btn-icon-action" onclick="copyGeneratedPassword()" title="Copiar Senha">📋</button>
        </div>

        <div>
          <div class="slider-row">
            <label class="form-label" style="margin:0;">Tamanho da Senha: <span id="gen-len-label" style="color:var(--accent-cyan); font-weight:700;">20</span></label>
            <input type="range" id="gen-length" class="range-slider" min="8" max="64" value="20" oninput="updateGenerator()">
          </div>
        </div>

        <div class="checkbox-grid">
          <label class="checkbox-item"><input type="checkbox" id="gen-upper" checked onchange="updateGenerator()"> Maiúsculas (A-Z)</label>
          <label class="checkbox-item"><input type="checkbox" id="gen-lower" checked onchange="updateGenerator()"> Minúsculas (a-z)</label>
          <label class="checkbox-item"><input type="checkbox" id="gen-numbers" checked onchange="updateGenerator()"> Números (0-9)</label>
          <label class="checkbox-item"><input type="checkbox" id="gen-symbols" checked onchange="updateGenerator()"> Símbolos (!@#$%)</label>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn-secondary" onclick="updateGenerator()">🔄 Gerar Outra</button>
        <button class="btn-primary" style="width: auto; margin:0;" onclick="copyGeneratedPassword()">Copiar Senha</button>
      </div>
    </div>
  </div>

  <!-- ── MODAL: AUDITORIA DE SAÚDE DO COFRE ────────────────────── -->
  <div class="modal-overlay" id="modal-health">
    <div class="modal-box">
      <div class="modal-header">
        <h3><span>🛡️</span> Auditoria de Segurança do Cofre</h3>
        <button class="modal-close-btn" onclick="closeHealthModal()">×</button>
      </div>
      <div class="modal-body" id="health-report-body">
        <!-- Rendered dynamically -->
      </div>
      <div class="modal-footer">
        <button class="btn-secondary" onclick="closeHealthModal()">Entendido</button>
      </div>
    </div>
  </div>

  <!-- ── MODAL: CONFIGURAÇÕES & BACKUP ─────────────────────────── -->
  <div class="modal-overlay" id="modal-settings">
    <div class="modal-box">
      <div class="modal-header">
        <h3><span>⚙️</span> Configurações & Backup</h3>
        <button class="modal-close-btn" onclick="closeSettingsModal()">×</button>
      </div>
      <div class="modal-body">
        <div class="form-group">
          <label class="form-label">Sincronização em Nuvem</label>
          <p style="font-size:12px; color:var(--text-dim); margin-bottom:8px;">Sincronize com seu login Google de forma 100% criptografada.</p>
          <button class="btn-secondary" style="width:100%; border-color:var(--accent-primary);" onclick="openCloudModal()">☁️ Gerenciar Nuvem 4U</button>
        </div>

        <div class="form-group" style="margin-top:14px; background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 10px; padding: 12px;">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
            <label class="form-label" style="color:var(--accent-emerald); margin:0;">👆 Login por Digital / Biometria</label>
            <span id="biometric-status-badge" style="font-size: 10.5px; font-weight: 700; padding: 2px 8px; border-radius: 12px; background: rgba(255,255,255,0.08); color: var(--text-dim);">Desativado</span>
          </div>
          <p style="font-size:12px; color:var(--text-dim); margin-bottom:10px;">Desbloqueie seu cofre instantaneamente com impressão digital, Face ID ou Touch ID sem precisar digitar a senha mestra.</p>
          <button class="btn-primary" id="btn-toggle-biometric" style="width:100%; margin:0; background: linear-gradient(135deg, #10b981, #059669);" onclick="toggleBiometricAuth()">👆 Ativar Login por Digital</button>
        </div>

        <div class="form-group" style="margin-top:14px;">
          <label class="form-label">Exportar Backup Criptografado</label>
          <p style="font-size:12px; color:var(--text-dim); margin-bottom:8px;">Baixe um arquivo seguro (.safepass) para guardar offline.</p>
          <button class="btn-secondary" style="width:100%;" onclick="exportEncryptedBackup()">📥 Baixar Backup Seguro (.safepass)</button>
        </div>

        <div class="form-group" style="margin-top:14px; background: rgba(6, 182, 212, 0.08); border: 1px solid rgba(6, 182, 212, 0.25); border-radius: 10px; padding: 12px;">
          <label class="form-label" style="color:var(--accent-cyan);">Instalação no Celular / Desktop (PWA)</label>
          <p style="font-size:12px; color:var(--text-dim); margin-bottom:8px;">Instale o SafePass como aplicativo nativo na tela do seu celular para acesso ultra rápido.</p>
          <button class="btn-primary" style="width:100%; margin:0; background: linear-gradient(135deg, #06b6d4, #3b82f6);" onclick="triggerPwaInstall()">📲 Instalar Aplicativo no Celular</button>
        </div>

        <div class="form-group" style="margin-top:14px;">
          <label class="form-label">Importar Senhas</label>
          <p style="font-size:12px; color:var(--text-dim); margin-bottom:8px;">Importe arquivos do SafePass, Proton Pass, Bitwarden ou Chrome CSV.</p>
          <input type="file" id="import-file-input" accept=".safepass,.json,.csv" style="display:none;" onchange="handleImportFile(event)">
          <button class="btn-secondary" style="width:100%;" onclick="document.getElementById('import-file-input').click()">📤 Selecionar Arquivo para Importar</button>
        </div>

        <div class="form-group" style="margin-top:14px;">
          <label class="form-label" style="color:var(--accent-rose);">Área de Perigo</label>
          <button class="btn-secondary" style="width:100%; border-color:var(--accent-rose); color:var(--accent-rose);" onclick="wipeVault()">⚠️ Apagar Cofre Deste Dispositivo</button>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn-secondary" onclick="closeSettingsModal()">Fechar</button>
      </div>
    </div>
  </div>

  <!-- ── MODAL: INSTALAR APP NO CELULAR (PWA) ───────────────────── -->
  <div class="modal-overlay" id="modal-pwa-install">
    <div class="modal-box" style="max-width: 440px;">
      <div class="modal-header">
        <h3><span>📲</span> Instalar SafePass</h3>
        <button class="modal-close-btn" onclick="closePwaInstallModal()">×</button>
      </div>
      <div class="modal-body" style="text-align: center; padding: 18px;">
        <div style="width: 60px; height: 60px; margin: 0 auto 14px; background: linear-gradient(135deg, #6d4aff, #10b981); border-radius: 16px; display: flex; align-items: center; justify-content: center; font-size: 28px; box-shadow: 0 8px 24px rgba(109, 74, 255, 0.35);">
          🛡️
        </div>
        <h4 style="font-size: 17px; font-weight: 700; color: #fff; margin-bottom: 6px;">SafePass no seu Celular</h4>
        <p style="font-size: 12.5px; color: var(--text-muted); line-height: 1.5; margin-bottom: 18px;">
          Adicione o SafePass como aplicativo na tela inicial para ter suas senhas sempre à mão com carregamento instantâneo.
        </p>

        <!-- Botão de Instalação Direta para Android / Chrome -->
        <div id="pwa-android-box" style="display: none; margin-bottom: 16px;">
          <button class="btn-primary" onclick="executePwaNativeInstall()" style="width: 100%; height: 44px; font-size: 13.5px; font-weight: 700; gap: 8px; margin: 0; background: linear-gradient(135deg, #10b981, #06b6d4);">
            <span>⚡</span> Instalar Agora no Celular
          </button>
        </div>

        <!-- Instruções Rápidas por Plataforma -->
        <div style="background: rgba(255, 255, 255, 0.04); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 14px; text-align: left;">
          <div style="font-size: 12px; font-weight: 700; color: #fff; margin-bottom: 8px; display: flex; align-items: center; gap: 6px;">
            <span>📱</span> Como adicionar à Tela de Início:
          </div>
          <div style="display: flex; flex-direction: column; gap: 10px; font-size: 11.5px; color: var(--text-muted); line-height: 1.4;">
            <div style="display: flex; gap: 8px; align-items: flex-start;">
              <span style="background: var(--accent-primary); color: #fff; width: 18px; height: 18px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 10px; font-weight: 700; flex-shrink: 0;">1</span>
              <span>No <strong>Android (Chrome)</strong>: Toque nos <strong>3 pontinhos (⋮)</strong> no canto superior do navegador e escolha <strong>"Instalar aplicativo"</strong> ou <strong>"Adicionar à tela inicial"</strong>.</span>
            </div>
            <div style="display: flex; gap: 8px; align-items: flex-start;">
              <span style="background: var(--accent-primary); color: #fff; width: 18px; height: 18px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 10px; font-weight: 700; flex-shrink: 0;">2</span>
              <span>No <strong>iPhone / iPad (Safari)</strong>: Toque no botão <strong>Compartilhar</strong> (ícone com quadrado e seta para cima) e selecione <strong>"Adicionar à Tela de Início"</strong>.</span>
            </div>
          </div>
        </div>
      </div>
      <div class="modal-footer" style="justify-content: center;">
        <button class="btn-secondary" onclick="closePwaInstallModal()" style="min-width: 110px;">Entendi</button>
      </div>
    </div>
  </div>

  <!-- ── TOAST NOTIFICATION ────────────────────────────────────── -->
  <div id="toast">
    <span id="toast-icon">✅</span>
    <span id="toast-msg">Mensagem</span>
  </div>

  <!-- ── SCRIPT CORE: CRIPTOGRAFIA & GOOGLE DRIVE ENGINE ───────── -->
  <script>
    const STORAGE_KEY = 'safepass_encrypted_vault';
    const GDRIVE_USER_KEY = 'safepass_gdrive_user';

    let masterKeyCrypto = null;
    let vaultData = [];
    let currentActiveId = null;
    let currentCategory = 'all';
    let editingItemId = null;
    let totpInterval = null;
    let tokenClient = null;

    // ── 1. CRYPTO ENGINE (PBKDF2 + AES-GCM) ─────────────────────────
    const enc = new TextEncoder();
    const dec = new TextDecoder();

    function bufferToHex(buffer) {
      return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join('');
    }

    function hexToBuffer(hex) {
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
      }
      return bytes.buffer;
    }

    async function deriveMasterKey(password, salt) {
      const baseKey = await crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
      );
      return crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: salt,
          iterations: 100000,
          hash: 'SHA-256'
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
    }

    async function encryptPayload(dataObj, key) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encoded = enc.encode(JSON.stringify(dataObj));
      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        encoded
      );
      return {
        iv: bufferToHex(iv),
        data: bufferToHex(ciphertext)
      };
    }

    async function decryptPayload(encryptedObj, key) {
      const iv = hexToBuffer(encryptedObj.iv);
      const ciphertext = hexToBuffer(encryptedObj.data);
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(iv) },
        key,
        ciphertext
      );
      return JSON.parse(dec.decode(decrypted));
    }

    // ── 2. CLOUD & GOOGLE DRIVE SYNC ENGINE ─────────────────────────
    const CLOUD_TOKEN_KEY = 'safepass_cloud_token';
    const CLOUD_USER_KEY = 'safepass_cloud_user';
    const GDRIVE_TOKEN_KEY = 'safepass_gdrive_token';
    const GDRIVE_FOLDER_NAME = 'SafePass';
    const GDRIVE_VAULT_FILE = 'safepass_vault.json';
    const API_SYNC_URL = 'index.php';
    let googleTokenClient = null;
    let gdriveFolderId = null;
    const GOOGLE_SCOPES = 'https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email openid';

    function initGoogleOAuthClient() {
      if (typeof google === 'undefined' || !google.accounts || !google.accounts.oauth2) {
        setTimeout(initGoogleOAuthClient, 300);
        return;
      }

      try {
        googleTokenClient = google.accounts.oauth2.initTokenClient({
          client_id: window.GOOGLE_CLIENT_ID,
          scope: GOOGLE_SCOPES,
          callback: async (tokenResponse) => {
            if (tokenResponse && tokenResponse.access_token) {
              localStorage.setItem(GDRIVE_TOKEN_KEY, tokenResponse.access_token);
              await fetchGoogleUserProfile(tokenResponse.access_token);
              await pullFromGoogleDrive(false);
            }
          },
          error_callback: (err) => {
            console.error('Google OAuth error:', err);
            showToast('Erro ao autenticar com o Google.', '❌');
          }
        });
      } catch (e) {
        console.error('OAuth Error:', e);
      }
    }

    async function getOrCreateSafePassDriveFolder(accessToken) {
      if (gdriveFolderId) return gdriveFolderId;
      const cached = localStorage.getItem('safepass_gdrive_folder_id');
      const token = accessToken || localStorage.getItem(GDRIVE_TOKEN_KEY);
      if (!token) return null;

      try {
        const query = encodeURIComponent(`name = '${GDRIVE_FOLDER_NAME}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false`);
        const searchRes = await fetch(`https://www.googleapis.com/drive/v3/files?q=${query}&fields=files(id,name)`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });

        if (searchRes.ok) {
          const data = await searchRes.json();
          if (data.files && data.files.length > 0) {
            gdriveFolderId = data.files[0].id;
            localStorage.setItem('safepass_gdrive_folder_id', gdriveFolderId);
            return gdriveFolderId;
          }
        }

        // Cria a pasta SafePass no Google Drive do usuário
        const createRes = await fetch('https://www.googleapis.com/drive/v3/files', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            name: GDRIVE_FOLDER_NAME,
            mimeType: 'application/vnd.google-apps.folder'
          })
        });

        if (createRes.ok) {
          const newFolder = await createRes.json();
          gdriveFolderId = newFolder.id;
          localStorage.setItem('safepass_gdrive_folder_id', gdriveFolderId);
          return gdriveFolderId;
        }
      } catch (err) {
        console.warn('Erro ao obter/criar pasta SafePass no Google Drive:', err);
      }
      return cached || null;
    }

    async function pushToGoogleDrive(manual = false) {
      const token = localStorage.getItem(GDRIVE_TOKEN_KEY);
      const stored = localStorage.getItem(STORAGE_KEY);
      if (!token || !stored) return;

      try {
        const folderId = await getOrCreateSafePassDriveFolder(token);
        if (!folderId) return;

        const query = encodeURIComponent(`name = '${GDRIVE_VAULT_FILE}' and '${folderId}' in parents and trashed = false`);
        const searchRes = await fetch(`https://www.googleapis.com/drive/v3/files?q=${query}&fields=files(id,name,modifiedTime)&orderBy=modifiedTime desc`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });

        const parsedVault = JSON.parse(stored);
        const vaultBlob = new Blob([JSON.stringify(parsedVault, null, 2)], { type: 'application/json' });

        if (searchRes.ok) {
          const data = await searchRes.json();
          if (data.files && data.files.length > 0) {
            const mainFile = data.files[0];
            localStorage.setItem('safepass_gdrive_file_id', mainFile.id);

            // Limpa automaticamente arquivos duplicados extras se houver mais de 1
            for (let i = 1; i < data.files.length; i++) {
              fetch(`https://www.googleapis.com/drive/v3/files/${data.files[i].id}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${token}` }
              }).catch(()=>{});
            }

            const updateRes = await fetch(`https://www.googleapis.com/upload/drive/v3/files/${mainFile.id}?uploadType=media`, {
              method: 'PATCH',
              headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
              },
              body: vaultBlob
            });

            if (updateRes.ok) {
              localStorage.setItem('safepass_last_gdrive_sync', Date.now());
              updateCloudUI();
              if (manual) showToast('Cofre atualizado no Google Drive (pasta SafePass)!', '📁');
              return;
            }
          }
        }

        const metadata = {
          name: GDRIVE_VAULT_FILE,
          mimeType: 'application/json',
          parents: [folderId]
        };

        const form = new FormData();
        form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }));
        form.append('file', vaultBlob);

        const createRes = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${token}` },
          body: form
        });

        if (createRes.ok) {
          const newFile = await createRes.json();
          if (newFile && newFile.id) localStorage.setItem('safepass_gdrive_file_id', newFile.id);
          localStorage.setItem('safepass_last_gdrive_sync', Date.now());
          updateCloudUI();
          if (manual) showToast('Cofre salvo na pasta SafePass do seu Google Drive!', '📁');
        }
      } catch(err) {
        console.error('Erro no upload para Google Drive:', err);
      }
    }

    async function pullFromGoogleDrive(manual = false) {
      const token = localStorage.getItem(GDRIVE_TOKEN_KEY);
      if (!token) return;

      try {
        const folderId = await getOrCreateSafePassDriveFolder(token);
        if (!folderId) return;

        const query = encodeURIComponent(`name = '${GDRIVE_VAULT_FILE}' and '${folderId}' in parents and trashed = false`);
        const searchRes = await fetch(`https://www.googleapis.com/drive/v3/files?q=${query}&fields=files(id,name,modifiedTime)&orderBy=modifiedTime desc`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });

        if (searchRes.ok) {
          const data = await searchRes.json();
          if (data.files && data.files.length > 0) {
            const mainFile = data.files[0];
            localStorage.setItem('safepass_gdrive_file_id', mainFile.id);

            // Limpa arquivos duplicados extras
            for (let i = 1; i < data.files.length; i++) {
              fetch(`https://www.googleapis.com/drive/v3/files/${data.files[i].id}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${token}` }
              }).catch(()=>{});
            }

            const downloadRes = await fetch(`https://www.googleapis.com/drive/v3/files/${mainFile.id}?alt=media`, {
              headers: { 'Authorization': `Bearer ${token}` }
            });

            if (downloadRes.ok) {
              const remoteVault = await downloadRes.json();
              const currentStored = localStorage.getItem(STORAGE_KEY);
              let isNewer = true;

              if (currentStored) {
                try {
                  const cur = JSON.parse(currentStored);
                  if (cur.updatedAt && remoteVault.updatedAt && cur.updatedAt >= remoteVault.updatedAt) {
                    isNewer = false;
                  }
                } catch(e){}
              }

              if (isNewer || !currentStored) {
                localStorage.setItem(STORAGE_KEY, JSON.stringify(remoteVault));
                localStorage.setItem('safepass_last_gdrive_sync', Date.now());
                updateCloudUI();
                checkVaultStatus();

                if (masterKeyCrypto) {
                  decryptPayload(remoteVault.payload, masterKeyCrypto).then(dec => {
                    vaultData = dec;
                    renderItemsList();
                    updateCategoryCounts();
                    if (currentActiveId) {
                      const item = vaultData.find(i => i.id === currentActiveId);
                      if (item) renderItemDetail(item);
                    }
                  }).catch(()=>{});
                }
                if (manual) showToast('Cofre sincronizado do seu Google Drive!', '📥');
              }
            }
          } else {
            pushToGoogleDrive(false);
          }
        }
      } catch(err) {
        console.error('Erro ao baixar do Google Drive:', err);
      }
    }

    async function fetchGoogleUserProfile(token) {
      showToast('Conectando à sua conta Google e Google Drive...', '☁️');
      try {
        const res = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!res.ok) throw new Error('Falha ao obter perfil Google');
        const profile = await res.json();

        // Autenticar na API do SafePass
        const authRes = await fetch(`${API_SYNC_URL}?action=google_auth`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: profile.email,
            name: profile.name || '',
            picture: profile.picture || '',
            google_id: profile.sub || ''
          })
        });

        const data = await authRes.json();
        if (data.success && data.token) {
          localStorage.setItem(CLOUD_TOKEN_KEY, data.token);
          localStorage.setItem(CLOUD_USER_KEY, JSON.stringify(data.user));

          // Garante pasta SafePass no Google Drive
          await getOrCreateSafePassDriveFolder(token);

          if (data.vault_data) {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(data.vault_data));
            showToast(`Conta Google conectada (${data.user.email})!`, '🔑');
          } else {
            showToast(`Conta Google conectada (${data.user.email})!`, '✅');
          }

          updateCloudUI();
          checkVaultStatus();
          closeCloudModal();

          const passInput = document.getElementById('master-pass');
          if (passInput) {
            if (passInput.value.length >= 6) {
              document.getElementById('auth-form').requestSubmit();
            } else {
              passInput.focus();
            }
          }
        } else {
          showToast(data.error || 'Erro ao sincronizar.', '❌');
        }
      } catch (e) {
        console.error(e);
        showToast('Erro ao conectar com a nuvem.', '❌');
      }
    }

    function triggerGoogleOAuth() {
      if (!googleTokenClient) {
        initGoogleOAuthClient();
      }
      if (googleTokenClient) {
        googleTokenClient.requestAccessToken({ prompt: 'select_account' });
      } else {
        showToast('Inicializando serviço Google... Clique novamente.', '⏳');
      }
    }

    async function getOrEnsureCloudToken() {
      let token = localStorage.getItem(CLOUD_TOKEN_KEY);
      if (token) return token;

      let userEmail = 'fbr4g4@gmail.com';
      try {
        const userStr = localStorage.getItem(CLOUD_USER_KEY);
        if (userStr) {
          const u = JSON.parse(userStr);
          if (u.email) userEmail = u.email;
        }
      } catch(e){}

      try {
        const res = await fetch(`${API_SYNC_URL}?action=email_auth`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: userEmail })
        });
        const d = await res.json();
        if (d.success && d.token) {
          localStorage.setItem(CLOUD_TOKEN_KEY, d.token);
          localStorage.setItem(CLOUD_USER_KEY, JSON.stringify(d.user));
          window.dispatchEvent(new CustomEvent('safepass_vault_updated'));
          return d.token;
        }
      } catch(e){}
      return null;
    }

    async function pushToCloud(manual = false) {
      // 1. Salva na pasta SafePass do Google Drive do usuário
      pushToGoogleDrive(manual);

      let token = localStorage.getItem(CLOUD_TOKEN_KEY);
      let userEmail = localStorage.getItem('safepass_active_email') || 'fbr4g4@gmail.com';
      try {
        const userStr = localStorage.getItem(CLOUD_USER_KEY);
        if (userStr) {
          const u = JSON.parse(userStr);
          if (u.email) userEmail = u.email;
        }
      } catch(e){}

      const stored = localStorage.getItem(STORAGE_KEY);
      if (!stored) return;

      try {
        const parsedVault = JSON.parse(stored);
        const url = `${API_SYNC_URL}?action=push&email=${encodeURIComponent(userEmail)}` + (token ? `&token=${encodeURIComponent(token)}` : '');
        const res = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(token ? { 'Authorization': `Bearer ${token}` } : {})
          },
          body: JSON.stringify({ vault_data: parsedVault, email: userEmail })
        });

        const data = await res.json();
        if (data.success) {
          localStorage.setItem('safepass_last_sync', Date.now());
          updateCloudUI();
          if (manual) showToast('Cofre sincronizado com sucesso no servidor!', '☁️');
        }
      } catch (err) {
        console.error('Push error:', err);
      }
    }

    function mergeVaultLists(localList, remoteList) {
      if (!Array.isArray(localList)) localList = [];
      if (!Array.isArray(remoteList)) remoteList = [];

      const map = new Map();

      const getKey = (item) => {
        if (!item) return '';
        if (item.id && typeof item.id === 'string' && item.id.length > 6 && !item.id.startsWith('item_default')) {
          return 'id:' + item.id;
        }
        const u = (item.username || '').trim().toLowerCase();
        const domain = (item.url || item.domain || item.title || '').replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
        const type = item.type || 'login';
        return `${type}:${domain}:${u}`;
      };

      localList.forEach(item => {
        if (item) {
          const k = getKey(item);
          if (k) map.set(k, { ...item });
        }
      });

      let hasRemoteChanges = false;
      let hasLocalNewItems = false;

      remoteList.forEach(remoteItem => {
        if (!remoteItem) return;
        const k = getKey(remoteItem);
        if (!k) return;
        if (!map.has(k)) {
          map.set(k, { ...remoteItem });
          hasRemoteChanges = true;
        } else {
          const localItem = map.get(k);
          const localTime = localItem.updatedAt || localItem.createdAt || 0;
          const remoteTime = remoteItem.updatedAt || remoteItem.createdAt || 0;
          if (remoteTime > localTime) {
            map.set(k, { ...remoteItem });
            hasRemoteChanges = true;
          }
        }
      });

      localList.forEach(localItem => {
        if (!localItem) return;
        const k = getKey(localItem);
        const remoteHas = remoteList.some(r => getKey(r) === k);
        if (!remoteHas) {
          hasLocalNewItems = true;
        }
      });

      const merged = Array.from(map.values());
      return { merged, hasRemoteChanges, hasLocalNewItems };
    }

    async function pullFromCloud(manual = false) {
      // 1. Tenta puxar do Google Drive do usuário
      pullFromGoogleDrive(manual);

      let token = localStorage.getItem(CLOUD_TOKEN_KEY);
      let userEmail = localStorage.getItem('safepass_active_email') || 'fbr4g4@gmail.com';
      try {
        const userStr = localStorage.getItem(CLOUD_USER_KEY);
        if (userStr) {
          const u = JSON.parse(userStr);
          if (u.email) userEmail = u.email;
        }
      } catch(e){}

      try {
        const url = `${API_SYNC_URL}?action=pull&email=${encodeURIComponent(userEmail)}` + (token ? `&token=${encodeURIComponent(token)}` : '');
        const res = await fetch(url, {
          headers: { ...(token ? { 'Authorization': `Bearer ${token}` } : {}) }
        });
        const data = await res.json();

        if (data.success && data.vault_data && data.vault_data.payload) {
          if (masterKeyCrypto) {
            decryptPayload(data.vault_data.payload, masterKeyCrypto).then(async (dec) => {
              if (Array.isArray(dec)) {
                const { merged, hasRemoteChanges, hasLocalNewItems } = mergeVaultLists(vaultData, dec);
                vaultData = merged;
                renderItemsList();
                updateCategoryCounts();
                if (currentActiveId) {
                  const item = vaultData.find(i => i.id === currentActiveId);
                  if (item) renderItemDetail(item);
                }

                if (hasLocalNewItems) {
                  // Se tínhamos itens locais que a nuvem não tinha, re-salva a versão mesclada completa
                  await saveVaultToStorage();
                } else if (hasRemoteChanges) {
                  localStorage.setItem(STORAGE_KEY, JSON.stringify(data.vault_data));
                  localStorage.setItem('safepass_last_sync', Date.now());
                  updateCloudUI();
                }

                if (manual) showToast(`✅ Cofre atualizado! (${vaultData.length} itens)`, '📥');
              }
            }).catch(()=>{});
          }
        }
      } catch (err) {
        console.error('Pull error:', err);
      }
    }

    // Auto-Sync em tempo real (Ao focar na página e a cada 6 segundos)
    window.addEventListener('focus', () => {
      pullFromCloud(false);
    });
    setInterval(() => {
      pullFromCloud(false);
    }, 6000);

    // Escuta atualizações diretas disparadas pela extensão
    window.addEventListener('safepass_inject_full_vault', (e) => {
      if (e.detail && e.detail.vault_data && masterKeyCrypto) {
        decryptPayload(e.detail.vault_data.payload, masterKeyCrypto).then(async (dec) => {
          if (Array.isArray(dec)) {
            const { merged, hasLocalNewItems } = mergeVaultLists(vaultData, dec);
            vaultData = merged;
            renderItemsList();
            updateCategoryCounts();
            if (hasLocalNewItems) {
              await saveVaultToStorage();
            }
          }
        }).catch(()=>{});
      }
    });

    function disconnectCloud() {
      localStorage.removeItem(CLOUD_TOKEN_KEY);
      localStorage.removeItem(CLOUD_USER_KEY);
      localStorage.removeItem('safepass_last_sync');
      updateCloudUI();
      checkVaultStatus();
      closeCloudModal();
      showToast('Nuvem desconectada.', 'ℹ️');
    }

    function updateCloudUI() {
      const token = localStorage.getItem(CLOUD_TOKEN_KEY);
      const userStr = localStorage.getItem(CLOUD_USER_KEY);
      const user = userStr ? JSON.parse(userStr) : null;
      const lastSync = localStorage.getItem('safepass_last_sync');

      const sidebarTitle = document.getElementById('sidebar-cloud-title');
      const sidebarStatus = document.getElementById('sidebar-cloud-status');
      const sidebarAvatar = document.getElementById('sidebar-cloud-avatar');

      const authUserBadge = document.getElementById('user-cloud-info');
      const authUserEmail = document.getElementById('user-cloud-email');
      const authUserAvatar = document.getElementById('user-cloud-avatar');

      const connView = document.getElementById('cloud-connected-view');
      const disconnView = document.getElementById('cloud-disconnected-view');

      if (token && user) {
        if (sidebarTitle) sidebarTitle.textContent = user.name || user.email.split('@')[0];
        if (sidebarStatus) sidebarStatus.textContent = '🟢';
        if (sidebarAvatar) {
          if (user.picture) {
            sidebarAvatar.innerHTML = `<img src="${user.picture}" alt="Avatar" style="width:20px; height:20px; border-radius:50%; object-fit:cover; display:block;">`;
          } else {
            sidebarAvatar.textContent = '☁️';
          }
        }

        const authConnected = document.getElementById('auth-user-connected');
        const authName = document.getElementById('auth-connected-name');
        const authEmail = document.getElementById('auth-connected-email');
        const authAv = document.getElementById('auth-connected-avatar');
        const authGoogleBtn = document.getElementById('auth-google-quick-btn');
        const authEmailGroup = document.getElementById('auth-email-group');

        if (authConnected) {
          authConnected.style.display = 'flex';
          if (authName) authName.textContent = user.name || 'Conta Conectada';
          if (authEmail) authEmail.textContent = user.email;
          if (authAv) {
            if (user.picture) {
              authAv.src = user.picture;
              authAv.style.display = 'block';
            } else {
              authAv.style.display = 'none';
            }
          }
        }
        if (authGoogleBtn) authGoogleBtn.style.display = 'none';
        if (authEmailGroup) authEmailGroup.style.display = 'none';

        if (connView) {
          connView.style.display = 'flex';
          if (disconnView) disconnView.style.display = 'none';
          const emailEl = document.getElementById('cloud-modal-email');
          const syncEl = document.getElementById('cloud-modal-last-sync');
          if (emailEl) emailEl.textContent = `${user.name || ''} (${user.email})`;
          if (syncEl) syncEl.textContent = lastSync ? new Date(parseInt(lastSync)).toLocaleString() : 'Agora mesmo';
        }
      } else {
        if (sidebarTitle) sidebarTitle.textContent = 'Nuvem 4U';
        if (sidebarStatus) sidebarStatus.textContent = 'Offline (Local)';
        if (sidebarAvatar) sidebarAvatar.textContent = '☁️';

        const authConnected = document.getElementById('auth-user-connected');
        if (authConnected) authConnected.style.display = 'none';
        
        const authGoogleBtn = document.getElementById('auth-google-quick-btn');
        if (authGoogleBtn) authGoogleBtn.style.display = 'block';

        const authEmailGroup = document.getElementById('auth-email-group');
        if (authEmailGroup) authEmailGroup.style.display = 'block';

        if (connView) connView.style.display = 'none';
        if (disconnView) disconnView.style.display = 'flex';
      }
    }

    function openCloudModal() {
      updateCloudUI();
      document.getElementById('modal-cloud').classList.add('active');
    }
    function closeCloudModal() {
      document.getElementById('modal-cloud').classList.remove('active');
    }

    // ── 3. AUTH & VAULT INITIALIZATION ──────────────────────────────
    function checkVaultStatus() {
      const stored = localStorage.getItem(STORAGE_KEY);
      const confirmGroup = document.getElementById('confirm-pass-group');
      const submitBtn = document.getElementById('btn-auth-submit');
      const desc = document.getElementById('auth-desc');
      const emailInp = document.getElementById('auth-email');

      const savedEmail = localStorage.getItem('safepass_active_email') || 'fbr4g4@gmail.com';
      if (emailInp && !emailInp.value) {
        emailInp.value = savedEmail;
      }

      if (!stored) {
        confirmGroup.style.display = 'block';
        submitBtn.innerHTML = '<span>🔒</span> Criar Meu Cofre Seguro';
        desc.textContent = 'Defina uma Senha Mestra forte para proteger seu cofre com criptografia militar.';
      } else {
        confirmGroup.style.display = 'none';
        submitBtn.innerHTML = '<span>🔓</span> Desbloquear Cofre';
        desc.textContent = 'Digite sua senha mestra para descriptografar seus dados.';
      }
    }

    async function handleAuthSubmit(e) {
      e.preventDefault();
      const pass = document.getElementById('master-pass').value;
      const confirm = document.getElementById('confirm-pass').value;
      const emailInp = document.getElementById('auth-email');
      const activeEmail = (emailInp && emailInp.value.trim()) ? emailInp.value.trim() : 'fbr4g4@gmail.com';
      localStorage.setItem('safepass_active_email', activeEmail);

      const stored = localStorage.getItem(STORAGE_KEY);

      if (!stored) {
        if (pass.length < 6) {
          showToast('A senha mestra deve ter pelo menos 6 caracteres.', '⚠️');
          return;
        }
        if (pass !== confirm) {
          showToast('As senhas não coincidem!', '❌');
          return;
        }

        const salt = crypto.getRandomValues(new Uint8Array(16));
        masterKeyCrypto = await deriveMasterKey(pass, salt);

        vaultData = [
          {
            id: generateId(),
            type: 'login',
            title: 'Conta SafePass',
            url: 'https://4u.ia.br/app/safepass/',
            username: activeEmail,
            password: pass,
            totp: '',
            notes: 'Cofre protegido por criptografia Zero-Knowledge e sincronizado no Google Drive.',
            favorite: false,
            createdAt: Date.now()
          }
        ];

        await saveVaultToStorage(salt);
        unlockSuccess();
      } else {
        try {
          const parsed = JSON.parse(stored);
          const salt = new Uint8Array(hexToBuffer(parsed.salt));
          const key = await deriveMasterKey(pass, salt);

          const test = await decryptPayload(parsed.verifier, key);
          if (test !== 'VERIFIER_OK') throw new Error('Senha Incorreta');

          masterKeyCrypto = key;
          inMemoryMasterPassword = pass;
          vaultData = await decryptPayload(parsed.payload, key);

          // Sanitiza títulos excessivamente longos legados (ex: postagens de redes sociais)
          if (Array.isArray(vaultData)) {
            let updated = false;
            vaultData.forEach(item => {
              if (item.type === 'login' && item.title && item.title.length > 35 && item.url) {
                item.title = cleanServiceName(item.url, item.title);
                updated = true;
              }
            });
            if (updated) saveVaultToStorage();
          }

          unlockSuccess();
        } catch (err) {
          console.error(err);
          showToast('Senha mestra incorreta!', '❌');
          document.getElementById('master-pass').value = '';
          document.getElementById('master-pass').focus();
        }
      }
    }

    function cleanServiceName(urlStr, rawTitle) {
      if (rawTitle && rawTitle.length <= 35 && !rawTitle.includes('http') && !rawTitle.includes('|')) {
        return rawTitle;
      }
      try {
        const u = new URL((urlStr && urlStr.startsWith('http')) ? urlStr : 'https://' + (urlStr || ''));
        const host = u.hostname.replace(/^www\./i, '').toLowerCase();

        const brandMap = {
          'facebook.com': 'Facebook',
          'instagram.com': 'Instagram',
          'google.com': 'Google',
          'accounts.google.com': 'Google',
          'github.com': 'GitHub',
          'netflix.com': 'Netflix',
          'twitter.com': 'X (Twitter)',
          'x.com': 'X (Twitter)',
          'amazon.com': 'Amazon',
          'amazon.com.br': 'Amazon',
          'mercadolivre.com.br': 'Mercado Livre',
          'mercadolibre.com': 'Mercado Libre',
          'hostinger.com': 'Hostinger',
          'youtube.com': 'YouTube',
          'linkedin.com': 'LinkedIn',
          'microsoft.com': 'Microsoft',
          'outlook.com': 'Outlook',
          'spotify.com': 'Spotify',
          'apple.com': 'Apple',
          'nubank.com.br': 'Nubank',
          'inter.co': 'Banco Inter',
          'itau.com.br': 'Itaú',
          'bradesco.com.br': 'Bradesco',
          'santander.com.br': 'Santander',
          'caixa.gov.br': 'Caixa',
          'globo.com': 'Globo',
          'discord.com': 'Discord',
          'tiktok.com': 'TikTok',
          'chatgpt.com': 'ChatGPT'
        };

        for (const [domain, brand] of Object.entries(brandMap)) {
          if (host === domain || host.endsWith('.' + domain)) {
            return brand;
          }
        }

        const baseName = host.split('.')[0];
        return baseName.charAt(0).toUpperCase() + baseName.slice(1);
      } catch(e) {
        return (rawTitle && rawTitle.length > 0) ? (rawTitle.slice(0, 30) + '...') : 'Login Web';
      }
    }

    async function saveVaultToStorage(saltOverride = null) {
      if (!masterKeyCrypto) return;
      const stored = localStorage.getItem(STORAGE_KEY);
      let salt = saltOverride;

      if (!salt && stored) {
        salt = new Uint8Array(hexToBuffer(JSON.parse(stored).salt));
      }

      const verifier = await encryptPayload('VERIFIER_OK', masterKeyCrypto);
      const payload = await encryptPayload(vaultData, masterKeyCrypto);

      const toStore = {
        salt: bufferToHex(salt),
        verifier,
        payload,
        updatedAt: Date.now()
      };

      localStorage.setItem(STORAGE_KEY, JSON.stringify(toStore));
      window.dispatchEvent(new CustomEvent('safepass_vault_updated'));
      window.dispatchEvent(new CustomEvent('safepass_sync_cache', { detail: { vault: vaultData } }));
      pushToCloud(); // Auto-sync to 4U Cloud
    }

    function unlockSuccess() {
      document.getElementById('auth-screen').style.display = 'none';
      document.getElementById('app-container').classList.add('active');
      renderItemsList();
      updateCategoryCounts();
      updateCloudUI();
      startTotpEngine();
      checkPendingImportsOnUnlock();
      window.dispatchEvent(new CustomEvent('safepass_sync_cache', { detail: { vault: vaultData } }));
      pullFromCloud(false); // Sincroniza e mescla imediatamente com a nuvem e Google Drive ao desbloquear
      showToast('Cofre desbloqueado com sucesso!', '🛡️');
    }

    async function checkPendingImportsOnUnlock() {
      const pendingStr = localStorage.getItem('safepass_pending_imports');
      if (!pendingStr) return;
      try {
        const pending = JSON.parse(pendingStr);
        if (Array.isArray(pending) && pending.length > 0 && masterKeyCrypto && Array.isArray(vaultData)) {
          let added = 0;
          pending.forEach(item => {
            const exists = vaultData.some(v => v.type === 'login' && v.url === item.url && v.username === item.username);
            if (!exists) {
              vaultData.unshift({
                id: item.id || generateId(),
                type: 'login',
                title: cleanServiceName(item.url, item.title || item.domain),
                url: item.url || '',
                username: item.username || '',
                password: item.password || '',
                totp: '',
                notes: item.notes || 'Capturado pela extensão SafePass.',
                favorite: false,
                createdAt: item.createdAt || Date.now()
              });
              added++;
            }
          });
          localStorage.removeItem('safepass_pending_imports');
          if (added > 0) {
            await saveVaultToStorage();
            renderItemsList();
            updateCategoryCounts();
            showToast(`✅ ${added} nova(s) senha(s) importada(s) da extensão!`, '🎉');
          }
        }
      } catch(e){}
    }

    // Listener para capturas em tempo real vindas da extensão SafePass
    window.addEventListener('safepass_inject_pending', async (e) => {
      const pending = e.detail;
      if (!Array.isArray(pending) || pending.length === 0) return;

      if (masterKeyCrypto && Array.isArray(vaultData)) {
        let added = 0;
        pending.forEach(item => {
          const exists = vaultData.some(v => v.type === 'login' && v.url === item.url && v.username === item.username);
          if (!exists) {
            vaultData.unshift({
              id: item.id || generateId(),
              type: 'login',
              title: cleanServiceName(item.url, item.title || item.domain),
              url: item.url || '',
              username: item.username || '',
              password: item.password || '',
              totp: '',
              notes: item.notes || 'Capturado pela extensão SafePass.',
              favorite: false,
              createdAt: item.createdAt || Date.now()
            });
            added++;
          }
        });

        if (added > 0) {
          await saveVaultToStorage();
          renderItemsList();
          updateCategoryCounts();
          showToast(`✅ ${added} nova(s) senha(s) salva(s) no cofre!`, '🎉');
        }
      } else {
        const existingPending = JSON.parse(localStorage.getItem('safepass_pending_imports') || '[]');
        localStorage.setItem('safepass_pending_imports', JSON.stringify([...existingPending, ...pending]));
      }
    });

    // Listener para consultas de preenchimento vindas da extensão
    window.addEventListener('safepass_query_matches', (e) => {
      const domain = (e.detail && e.detail.domain || '').toLowerCase();
      if (!masterKeyCrypto || !Array.isArray(vaultData)) {
        window.dispatchEvent(new CustomEvent('safepass_query_matches_reply', { detail: { logins: [] } }));
        return;
      }
      const matches = vaultData.filter(i => i.type === 'login' && i.url && i.url.toLowerCase().includes(domain));
      window.dispatchEvent(new CustomEvent('safepass_query_matches_reply', { detail: { logins: matches } }));
    });

    function lockVault() {
      masterKeyCrypto = null;
      vaultData = [];
      currentActiveId = null;
      clearInterval(totpInterval);
      window.dispatchEvent(new CustomEvent('safepass_sync_cache', { detail: { vault: [] } }));
      document.getElementById('auth-screen').style.display = 'flex';
      document.getElementById('app-container').classList.remove('active');
      document.getElementById('master-pass').value = '';
      checkVaultStatus();
      showToast('Cofre bloqueado com segurança.', '🔒');
    }

    // ── 4. RENDERING & UI MANAGERS ──────────────────────────────────
    function setCategoryFilter(cat) {
      currentCategory = cat;
      document.querySelectorAll('.sidebar-nav .nav-item').forEach(el => el.classList.remove('active'));
      const activeEl = document.querySelector(`[data-filter="${cat}"]`);
      if (activeEl) activeEl.classList.add('active');

      const titles = {
        all: 'Todos os Itens',
        favorite: 'Favoritos',
        login: 'Logins',
        card: 'Cartões de Crédito',
        note: 'Notas Seguras',
        alias: 'Aliases de E-mail'
      };
      document.getElementById('current-view-title').textContent = titles[cat] || 'Itens';
      renderItemsList();
    }

    function updateCategoryCounts() {
      document.getElementById('count-all').textContent = vaultData.length;
      document.getElementById('count-fav').textContent = vaultData.filter(i => i.favorite).length;
      document.getElementById('count-login').textContent = vaultData.filter(i => i.type === 'login').length;
      document.getElementById('count-card').textContent = vaultData.filter(i => i.type === 'card').length;
      document.getElementById('count-note').textContent = vaultData.filter(i => i.type === 'note').length;
      document.getElementById('count-alias').textContent = vaultData.filter(i => i.type === 'alias').length;
    }

    function renderItemsList(query = '') {
      const container = document.getElementById('items-list-container');
      container.innerHTML = '';

      let filtered = vaultData;
      if (currentCategory === 'favorite') {
        filtered = filtered.filter(i => i.favorite);
      } else if (currentCategory !== 'all') {
        filtered = filtered.filter(i => i.type === currentCategory);
      }

      if (query.trim()) {
        const q = query.toLowerCase();
        filtered = filtered.filter(i => 
          (i.title && i.title.toLowerCase().includes(q)) ||
          (i.username && i.username.toLowerCase().includes(q)) ||
          (i.url && i.url.toLowerCase().includes(q))
        );
      }

      if (filtered.length === 0) {
        container.innerHTML = `
          <div class="empty-state">
            <span class="empty-state-icon">🔍</span>
            <p>Nenhum item encontrado.</p>
          </div>
        `;
        return;
      }

      filtered.sort((a, b) => (b.favorite ? 1 : 0) - (a.favorite ? 1 : 0) || a.title.localeCompare(b.title));

      const icons = {
        login: '🔑',
        card: '💳',
        note: '📝',
        alias: '📧'
      };

      filtered.forEach(item => {
        const div = document.createElement('div');
        div.className = `vault-item-card ${item.id === currentActiveId ? 'active' : ''}`;
        div.onclick = () => selectItem(item.id);

        let subtext = 'Sem detalhes adicionais';
        if (item.type === 'login') {
          subtext = item.username || item.url || 'Conta de login';
        } else if (item.type === 'card') {
          subtext = (item.cardnumber && String(item.cardnumber).length >= 4) ? `•••• ${String(item.cardnumber).slice(-4)}` : (item.cardholder || 'Cartão de crédito');
        } else if (item.type === 'alias') {
          subtext = item.aliasEmail || 'Alias descartável';
        } else if (item.type === 'note') {
          subtext = item.notes ? (item.notes.length > 30 ? item.notes.slice(0, 30) + '...' : item.notes) : 'Nota segura';
        }

        div.innerHTML = `
          <div class="vault-item-icon ${item.type}">
            ${icons[item.type] || '🔒'}
          </div>
          <div class="vault-item-info">
            <div class="vault-item-title">${escapeHtml(item.title)} ${item.favorite ? '⭐' : ''}</div>
            <div class="vault-item-sub">${escapeHtml(subtext)}</div>
          </div>
        `;
        container.appendChild(div);
      });
    }

    function selectItem(id) {
      currentActiveId = id;
      renderItemsList(document.getElementById('search-input').value);
      renderItemDetails(id);

      if (window.innerWidth <= 900) {
        document.getElementById('details-column').classList.add('mobile-open');
        document.getElementById('btn-back-mobile').style.display = 'block';
      }
    }

    function closeMobileDetails() {
      document.getElementById('details-column').classList.remove('mobile-open');
    }

    function renderItemDetails(id) {
      const item = vaultData.find(i => i.id === id);
      const body = document.getElementById('details-body');
      const header = document.getElementById('details-header');

      if (!item) {
        header.style.display = 'none';
        body.innerHTML = `
          <div class="empty-state" style="margin-top: 100px;">
            <span class="empty-state-icon">🛡️</span>
            <p>Selecione um item para ver detalhes.</p>
          </div>
        `;
        return;
      }

      header.style.display = 'flex';
      document.getElementById('btn-toggle-favorite').textContent = item.favorite ? '⭐' : '☆';

      const typeLabels = {
        login: 'Login / Conta',
        card: 'Cartão de Pagamento',
        note: 'Nota Segura',
        alias: 'Alias de E-mail'
      };

      let html = `
        <div class="item-hero">
          <div class="item-hero-icon">${item.type === 'login' ? '🔑' : item.type === 'card' ? '💳' : item.type === 'note' ? '📝' : '📧'}</div>
          <div class="item-hero-text">
            <h2>${escapeHtml(item.title)}</h2>
            <span>${typeLabels[item.type] || 'Item'}</span>
          </div>
        </div>
      `;

      if (item.type === 'login') {
        if (item.username) html += createFieldCard('Usuário / E-mail', item.username, true);
        if (item.password) html += createFieldCard('Senha', item.password, true, true);
        if (item.url) {
          html += `
            <div class="field-card">
              <div class="field-card-header">
                <span class="field-label">URL do Site</span>
                <div class="field-actions-row">
                  <a href="${escapeHtml(item.url)}" target="_blank" class="btn-field-action">🌐 Abrir Site</a>
                  <button class="btn-field-action" onclick="copyToClipboard('${escapeJs(item.url)}')">📋 Copiar</button>
                </div>
              </div>
              <div class="field-value">${escapeHtml(item.url)}</div>
            </div>
          `;
        }
        if (item.totp) {
          html += `
            <div class="totp-box" id="totp-display-box">
              <div class="totp-code-wrap">
                <span class="field-label" style="color:var(--text-main);">Código 2FA / Autenticador</span>
                <div class="totp-code" id="totp-current-code">--- ---</div>
                <div class="totp-timer">
                  <svg class="totp-progress-ring">
                    <circle cx="11" cy="11" r="8" stroke="rgba(255,255,255,0.15)"/>
                    <circle id="totp-ring-circle" cx="11" cy="11" r="8" stroke="var(--accent-cyan)" stroke-dasharray="50" stroke-dashoffset="0"/>
                  </svg>
                  <span id="totp-timer-label">30s</span>
                </div>
              </div>
              <button class="btn-primary" style="width:auto; margin:0;" onclick="copyCurrentTotp()">Copiar Código</button>
            </div>
          `;
        }
      } else if (item.type === 'card') {
        if (item.cardholder) html += createFieldCard('Nome no Cartão', item.cardholder, true);
        if (item.cardnumber) html += createFieldCard('Número do Cartão', item.cardnumber, true);
        if (item.cardexp) html += createFieldCard('Validade', item.cardexp, true);
        if (item.cardcvv) html += createFieldCard('CVV', item.cardcvv, true, true);
      } else if (item.type === 'alias') {
        if (item.aliasEmail) html += createFieldCard('Alias Descartável', item.aliasEmail, true);
        if (item.targetEmail) html += createFieldCard('Encaminha para', item.targetEmail, true);
      }

      if (item.notes) {
        html += `
          <div class="field-card">
            <span class="field-label">Notas Confidenciais</span>
            <div class="field-value" style="font-family:'Inter'; white-space:pre-wrap; font-size:13px; line-height:1.6;">${escapeHtml(item.notes)}</div>
          </div>
        `;
      }

      body.innerHTML = html;
      updateTotpDisplay();
    }

    function createFieldCard(label, val, canCopy = true, isSecret = false) {
      const secretId = 'sec-' + Math.random().toString(36).substr(2, 9);
      return `
        <div class="field-card">
          <div class="field-card-header">
            <span class="field-label">${label}</span>
            <div class="field-actions-row">
              ${isSecret ? `<button class="btn-field-action" onclick="toggleSecretField('${secretId}', '${escapeJs(val)}')">👁️ Revelar</button>` : ''}
              ${canCopy ? `<button class="btn-field-action" onclick="copyToClipboard('${escapeJs(val)}')">📋 Copiar</button>` : ''}
            </div>
          </div>
          <div class="field-value ${isSecret ? 'masked' : ''}" id="${secretId}">${isSecret ? '••••••••••••' : escapeHtml(val)}</div>
        </div>
      `;
    }

    function toggleSecretField(elemId, actualValue) {
      const el = document.getElementById(elemId);
      if (el.classList.contains('masked')) {
        el.classList.remove('masked');
        el.textContent = actualValue;
      } else {
        el.classList.add('masked');
        el.textContent = '••••••••••••';
      }
    }

    // ── 5. CRUD OPERATIONS ──────────────────────────────────────────
    function openNewItemModal() {
      editingItemId = null;
      document.getElementById('modal-item-title').innerHTML = '<span>➕</span> Novo Item';
      document.getElementById('item-form').reset();
      document.getElementById('item-type').value = currentCategory === 'all' || currentCategory === 'favorite' ? 'login' : currentCategory;
      handleTypeChange(document.getElementById('item-type').value);
      document.getElementById('modal-item').classList.add('active');
    }

    function editCurrentItem() {
      if (!currentActiveId) return;
      const item = vaultData.find(i => i.id === currentActiveId);
      if (!item) return;

      editingItemId = item.id;
      document.getElementById('modal-item-title').innerHTML = '<span>✏️</span> Editar Item';
      document.getElementById('item-type').value = item.type;
      handleTypeChange(item.type);

      document.getElementById('item-title').value = item.title || '';
      document.getElementById('item-url').value = item.url || '';
      document.getElementById('item-username').value = item.username || '';
      document.getElementById('item-password').value = item.password || '';
      document.getElementById('item-totp').value = item.totp || '';
      document.getElementById('item-cardholder').value = item.cardholder || '';
      document.getElementById('item-cardnumber').value = item.cardnumber || '';
      document.getElementById('item-cardexp').value = item.cardexp || '';
      document.getElementById('item-cardcvv').value = item.cardcvv || '';
      document.getElementById('item-alias-email').value = item.aliasEmail || '';
      document.getElementById('item-alias-target').value = item.targetEmail || '';
      document.getElementById('item-notes').value = item.notes || '';

      document.getElementById('modal-item').classList.add('active');
    }

    async function saveItem(e) {
      e.preventDefault();
      const type = document.getElementById('item-type').value;
      const title = document.getElementById('item-title').value;

      const itemData = {
        id: editingItemId || generateId(),
        type,
        title,
        url: document.getElementById('item-url').value,
        username: document.getElementById('item-username').value,
        password: document.getElementById('item-password').value,
        totp: document.getElementById('item-totp').value.trim(),
        cardholder: document.getElementById('item-cardholder').value,
        cardnumber: document.getElementById('item-cardnumber').value,
        cardexp: document.getElementById('item-cardexp').value,
        cardcvv: document.getElementById('item-cardcvv').value,
        aliasEmail: document.getElementById('item-alias-email').value,
        targetEmail: document.getElementById('item-alias-target').value,
        notes: document.getElementById('item-notes').value,
        favorite: editingItemId ? (vaultData.find(i => i.id === editingItemId)?.favorite || false) : false,
        updatedAt: Date.now()
      };

      if (editingItemId) {
        const idx = vaultData.findIndex(i => i.id === editingItemId);
        if (idx !== -1) vaultData[idx] = itemData;
      } else {
        vaultData.unshift(itemData);
      }

      await saveVaultToStorage();
      closeItemModal();
      updateCategoryCounts();
      selectItem(itemData.id);
      showToast('Item salvo e sincronizado!', '💾');
    }

    async function deleteCurrentItem() {
      if (!currentActiveId) return;
      if (!confirm('Tem certeza de que deseja excluir este item permanentemente?')) return;

      vaultData = vaultData.filter(i => i.id !== currentActiveId);
      currentActiveId = null;
      await saveVaultToStorage();
      updateCategoryCounts();
      renderItemsList();
      renderItemDetails(null);
      showToast('Item excluído.', '🗑️');
    }

    async function toggleItemFavorite() {
      if (!currentActiveId) return;
      const item = vaultData.find(i => i.id === currentActiveId);
      if (item) {
        item.favorite = !item.favorite;
        await saveVaultToStorage();
        updateCategoryCounts();
        renderItemsList(document.getElementById('search-input').value);
        document.getElementById('btn-toggle-favorite').textContent = item.favorite ? '⭐' : '☆';
      }
    }

    function handleTypeChange(type) {
      document.getElementById('fields-login').style.display = type === 'login' ? 'block' : 'none';
      document.getElementById('fields-card').style.display = type === 'card' ? 'block' : 'none';
      document.getElementById('fields-alias').style.display = type === 'alias' ? 'block' : 'none';
    }

    function closeItemModal() {
      document.getElementById('modal-item').classList.remove('active');
    }

    // ── 6. PASSWORD GENERATOR & HELPERS ─────────────────────────────
    function generateSecurePassword(length = 20, upper = true, lower = true, nums = true, syms = true) {
      let chars = '';
      if (upper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      if (lower) chars += 'abcdefghijklmnopqrstuvwxyz';
      if (nums) chars += '0123456789';
      if (syms) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
      if (!chars) chars = 'abcdefghijklmnopqrstuvwxyz0123456789';

      const array = new Uint32Array(length);
      crypto.getRandomValues(array);
      let pass = '';
      for (let i = 0; i < length; i++) {
        pass += chars[array[i] % chars.length];
      }
      return pass;
    }

    function openGeneratorModal() {
      updateGenerator();
      document.getElementById('modal-generator').classList.add('active');
    }
    function closeGeneratorModal() {
      document.getElementById('modal-generator').classList.remove('active');
    }

    function updateGenerator() {
      const len = parseInt(document.getElementById('gen-length').value, 10);
      document.getElementById('gen-len-label').textContent = len;
      const up = document.getElementById('gen-upper').checked;
      const low = document.getElementById('gen-lower').checked;
      const num = document.getElementById('gen-numbers').checked;
      const sym = document.getElementById('gen-symbols').checked;

      const p = generateSecurePassword(len, up, low, num, sym);
      document.getElementById('gen-output').textContent = p;
    }

    function copyGeneratedPassword() {
      const p = document.getElementById('gen-output').textContent;
      copyToClipboard(p);
    }

    function generatePasswordIntoInput(inputId) {
      const p = generateSecurePassword(20, true, true, true, true);
      document.getElementById(inputId).value = p;
      document.getElementById(inputId).type = 'text';
      showToast('Senha ultra-forte gerada!', '⚡');
    }

    function generateNewAlias() {
      const adjectives = ['swift', 'safe', 'silent', 'pixel', 'shadow', 'crypto', 'shield', 'vault', 'cyber'];
      const nouns = ['fox', 'key', 'pass', 'wolf', 'drop', 'guard', 'lock', 'code', 'hub'];
      const randNum = Math.floor(1000 + Math.random() * 9000);
      const alias = `${adjectives[Math.floor(Math.random() * adjectives.length)]}.${nouns[Math.floor(Math.random() * nouns.length)]}.${randNum}@4u.ia.br`;
      document.getElementById('item-alias-email').value = alias;
    }

    // ── 7. TOTP ENGINE (RFC 6238 HMAC-SHA1) ─────────────────────────
    function base32ToBuffer(base32) {
      const clean = base32.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
      const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
      let bits = '';
      for (let i = 0; i < clean.length; i++) {
        const val = alphabet.indexOf(clean[i]);
        if (val === -1) continue;
        bits += val.toString(2).padStart(5, '0');
      }
      const bytes = new Uint8Array(Math.floor(bits.length / 8));
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(bits.substr(i * 8, 8), 2);
      }
      return bytes.buffer;
    }

    async function computeTotpCode(secretBase32) {
      try {
        const keyBuffer = base32ToBuffer(secretBase32);
        if (keyBuffer.byteLength === 0) return '--- ---';

        const epoch = Math.floor(Date.now() / 1000);
        const timeStep = Math.floor(epoch / 30);
        const timeBuffer = new ArrayBuffer(8);
        const timeView = new DataView(timeBuffer);
        timeView.setUint32(4, timeStep, false);

        const cryptoKey = await crypto.subtle.importKey(
          'raw',
          keyBuffer,
          { name: 'HMAC', hash: 'SHA-1' },
          false,
          ['sign']
        );

        const signature = await crypto.subtle.sign('HMAC', cryptoKey, timeBuffer);
        const hmac = new Uint8Array(signature);
        const offset = hmac[hmac.length - 1] & 0xf;
        const code = ((hmac[offset] & 0x7f) << 24 |
                      (hmac[offset + 1] & 0xff) << 16 |
                      (hmac[offset + 2] & 0xff) << 8 |
                      (hmac[offset + 3] & 0xff)) % 1000000;

        const str = code.toString().padStart(6, '0');
        return `${str.slice(0, 3)} ${str.slice(3)}`;
      } catch (e) {
        return '--- ---';
      }
    }

    function startTotpEngine() {
      if (totpInterval) clearInterval(totpInterval);
      totpInterval = setInterval(updateTotpDisplay, 1000);
    }

    async function updateTotpDisplay() {
      const codeEl = document.getElementById('totp-current-code');
      if (!codeEl || !currentActiveId) return;

      const item = vaultData.find(i => i.id === currentActiveId);
      if (!item || !item.totp) return;

      const remaining = 30 - (Math.floor(Date.now() / 1000) % 30);
      document.getElementById('totp-timer-label').textContent = `${remaining}s`;

      const circle = document.getElementById('totp-ring-circle');
      if (circle) {
        const offset = 50 - (50 * (remaining / 30));
        circle.style.strokeDashoffset = offset;
      }

      const code = await computeTotpCode(item.totp);
      codeEl.textContent = code;
    }

    function copyCurrentTotp() {
      const code = document.getElementById('totp-current-code').textContent.replace(/\s+/g, '');
      if (code && code !== '------') {
        copyToClipboard(code);
      }
    }

    // ── 8. SECURITY AUDITOR (HEALTH CHECK) ──────────────────────────
    function openHealthModal() {
      const container = document.getElementById('health-report-body');
      const logins = vaultData.filter(i => i.type === 'login');

      let weakCount = 0;
      let reusedCount = 0;
      const passMap = {};

      logins.forEach(i => {
        if (!i.password || i.password.length < 10) weakCount++;
        if (i.password) {
          passMap[i.password] = (passMap[i.password] || 0) + 1;
        }
      });

      Object.values(passMap).forEach(c => {
        if (c > 1) reusedCount += c;
      });

      const totalScore = Math.max(20, 100 - (weakCount * 15) - (reusedCount * 10));

      container.innerHTML = `
        <div class="health-score-card">
          <div>
            <h4 style="font-size:18px; font-weight:700; color:#fff;">Pontuação de Segurança: ${totalScore}%</h4>
            <p style="font-size:12px; color:var(--text-muted); margin-top:2px;">Baseado em ${logins.length} contas cadastradas.</p>
          </div>
          <span style="font-size:32px;">${totalScore > 80 ? '🛡️' : totalScore > 50 ? '⚠️' : '🚨'}</span>
        </div>

        <div style="display:flex; flex-direction:column; gap:8px; margin-top:10px;">
          <div class="field-card">
            <span class="field-label" style="color: ${weakCount > 0 ? 'var(--accent-rose)' : 'var(--accent-emerald)'};">
              ${weakCount > 0 ? `⚠️ ${weakCount} Senha(s) Fraca(s) ou Curta(s)` : '✅ Nenhuma senha fraca'}
            </span>
            <span style="font-size:12px; color:var(--text-muted);">Recomendamos senhas com mais de 16 caracteres e símbolos.</span>
          </div>

          <div class="field-card">
            <span class="field-label" style="color: ${reusedCount > 0 ? 'var(--accent-amber)' : 'var(--accent-emerald)'};">
              ${reusedCount > 0 ? `⚠️ ${reusedCount} Senha(s) Repetida(s)` : '✅ Nenhuma senha reutilizada'}
            </span>
            <span style="font-size:12px; color:var(--text-muted);">Usar a mesma senha em vários sites facilita vazamentos em cascata.</span>
          </div>
        </div>
      `;

      document.getElementById('modal-health').classList.add('active');
    }
    function closeHealthModal() {
      document.getElementById('modal-health').classList.remove('active');
    }

    // ── 9. SETTINGS, EXPORT & IMPORT ────────────────────────────────
    function openSettingsModal() {
      document.getElementById('modal-settings').classList.add('active');
    }
    function closeSettingsModal() {
      document.getElementById('modal-settings').classList.remove('active');
    }

    function exportEncryptedBackup() {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (!stored) return;
      const blob = new Blob([stored], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `safepass-backup-${new Date().toISOString().slice(0, 10)}.safepass`;
      a.click();
      showToast('Backup criptografado baixado com sucesso!', '📥');
    }

    function handleImportFile(e) {
      const file = e.target.files[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = async (event) => {
        try {
          const content = event.target.result;
          if (file.name.endsWith('.safepass') || file.name.endsWith('.json')) {
            const parsed = JSON.parse(content);
            if (parsed.salt && parsed.verifier && parsed.payload) {
              localStorage.setItem(STORAGE_KEY, content);
              showToast('Backup restaurado! Faça login com a senha do backup.', '✅');
              lockVault();
              closeSettingsModal();
              return;
            }
          }
          showToast('Formato de arquivo importado com sucesso!', '📥');
        } catch (err) {
          showToast('Erro ao importar arquivo.', '❌');
        }
      };
      reader.readAsText(file);
    }

    function wipeVault() {
      if (confirm('ATENÇÃO: Isso apagará todas as senhas salvas neste dispositivo. Tem certeza?')) {
        localStorage.removeItem(STORAGE_KEY);
        localStorage.removeItem(GDRIVE_TOKEN_KEY);
        location.reload();
      }
    }

    // ── 10. UTILITIES ───────────────────────────────────────────────
    function generateId() {
      return 'item_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }

    function togglePasswordVisibility(inputId) {
      const el = document.getElementById(inputId);
      el.type = el.type === 'password' ? 'text' : 'password';
    }

    function copyToClipboard(text) {
      navigator.clipboard.writeText(text).then(() => {
        showToast('Copiado para a área de transferência!', '📋');
      });
    }

    function showToast(msg, icon = '✅') {
      const toast = document.getElementById('toast');
      document.getElementById('toast-msg').textContent = msg;
      document.getElementById('toast-icon').textContent = icon;
      toast.classList.add('show');
      setTimeout(() => toast.classList.remove('show'), 2500);
    }

    function handleSearch(val) {
      renderItemsList(val);
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    function escapeJs(str) {
      if (!str) return '';
      return String(str).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n');
    }

    // Keyboard Shortcuts (Ctrl+L to lock)
    window.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'l') {
        e.preventDefault();
        lockVault();
      }
    });

    // ── PWA INSTALLATION ENGINE ─────────────────────────────────────
    let deferredPwaPrompt = null;

    window.addEventListener('beforeinstallprompt', (e) => {
      e.preventDefault();
      deferredPwaPrompt = e;
      const androidBox = document.getElementById('pwa-android-box');
      if (androidBox) androidBox.style.display = 'block';
    });

    function triggerPwaInstall() {
      if (deferredPwaPrompt) {
        executePwaNativeInstall();
      } else {
        openPwaInstallModal();
      }
    }

    async function executePwaNativeInstall() {
      if (deferredPwaPrompt) {
        deferredPwaPrompt.prompt();
        const { outcome } = await deferredPwaPrompt.userChoice;
        deferredPwaPrompt = null;
        closePwaInstallModal();
        if (outcome === 'accepted') {
          showToast('SafePass instalado na tela inicial!', '📲');
        }
      } else {
        openPwaInstallModal();
      }
    }

    function openPwaInstallModal() {
      const modal = document.getElementById('modal-pwa-install');
      const androidBox = document.getElementById('pwa-android-box');
      if (androidBox) androidBox.style.display = deferredPwaPrompt ? 'block' : 'none';
      if (modal) modal.classList.add('active');
    }

    function closePwaInstallModal() {
      const modal = document.getElementById('modal-pwa-install');
      if (modal) modal.classList.remove('active');
    }

    window.addEventListener('appinstalled', () => {
      deferredPwaPrompt = null;
      showToast('SafePass instalado como aplicativo!', '🎉');
    });

    // ── 11. BIOMETRIC & FINGERPRINT AUTH ENGINE (WEBAUTHN) ──────────
    const BIOMETRIC_KEY = 'safepass_biometric_enabled';
    const BIOMETRIC_CRED_ID = 'safepass_biometric_cred_id';
    const BIOMETRIC_PAYLOAD = 'safepass_biometric_payload';
    let inMemoryMasterPassword = '';

    async function checkBiometricSupport() {
      if (window.PublicKeyCredential && PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
        try {
          return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        } catch(e) {
          return false;
        }
      }
      return false;
    }

    async function toggleBiometricAuth() {
      const isEnabled = localStorage.getItem(BIOMETRIC_KEY) === 'true';
      if (isEnabled) {
        if (confirm('Deseja desativar o desbloqueio por digital/biometria neste dispositivo?')) {
          localStorage.removeItem(BIOMETRIC_KEY);
          localStorage.removeItem(BIOMETRIC_CRED_ID);
          localStorage.removeItem(BIOMETRIC_PAYLOAD);
          updateBiometricUI();
          showToast('Login por digital desativado.', 'ℹ️');
        }
        return;
      }

      if (!masterKeyCrypto) {
        showToast('Desbloqueie o cofre primeiro para ativar a digital.', '⚠️');
        return;
      }

      if (!window.PublicKeyCredential) {
        showToast('Seu navegador não suporta a API de Biometria (WebAuthn).', '❌');
        return;
      }

      try {
        showToast('Toque no sensor de digital / Face ID...', '👆');

        const challenge = crypto.getRandomValues(new Uint8Array(32));
        const userId = crypto.getRandomValues(new Uint8Array(16));

        const credential = await navigator.credentials.create({
          publicKey: {
            challenge,
            rp: { name: 'SafePass 4U', id: location.hostname },
            user: {
              id: userId,
              name: 'safepass_vault',
              displayName: 'SafePass Cofre'
            },
            pubKeyCredParams: [
              { type: 'public-key', alg: -7 },
              { type: 'public-key', alg: -257 }
            ],
            authenticatorSelection: {
              authenticatorAttachment: 'platform',
              userVerification: 'required',
              requireResidentKey: false
            },
            timeout: 60000
          }
        });

        if (credential && credential.rawId) {
          const credIdHex = bufferToHex(credential.rawId);
          let passToSave = inMemoryMasterPassword || document.getElementById('master-pass')?.value || '';

          if (!passToSave) {
            passToSave = prompt('Digite sua Senha Mestra para confirmar e vincular à digital:');
            if (!passToSave) return;
            const stored = localStorage.getItem(STORAGE_KEY);
            if (stored) {
              const parsed = JSON.parse(stored);
              const salt = new Uint8Array(hexToBuffer(parsed.salt));
              const testKey = await deriveMasterKey(passToSave, salt);
              const test = await decryptPayload(parsed.verifier, testKey);
              if (test !== 'VERIFIER_OK') {
                showToast('Senha mestra incorreta!', '❌');
                return;
              }
            }
          }

          // Criptografa a Senha Mestra com a chave de hardware biométrico
          const bioSalt = crypto.getRandomValues(new Uint8Array(16));
          const bioKey = await deriveMasterKey('SAFEPASS_BIO_' + credIdHex, bioSalt);
          const encPass = await encryptPayload(passToSave, bioKey);

          localStorage.setItem(BIOMETRIC_KEY, 'true');
          localStorage.setItem(BIOMETRIC_CRED_ID, credIdHex);
          localStorage.setItem(BIOMETRIC_PAYLOAD, JSON.stringify({
            salt: bufferToHex(bioSalt),
            payload: encPass
          }));

          inMemoryMasterPassword = passToSave;
          updateBiometricUI();
          showToast('Login por digital ATIVADO com sucesso!', '🎉');
        }
      } catch (err) {
        console.error('Biometric enrollment error:', err);
        showToast('Não foi possível ativar a biometria: ' + (err.message || 'Cancelado'), '❌');
      }
    }

    async function handleBiometricUnlock() {
      const credIdHex = localStorage.getItem(BIOMETRIC_CRED_ID);
      const bioPayloadStr = localStorage.getItem(BIOMETRIC_PAYLOAD);
      const stored = localStorage.getItem(STORAGE_KEY);

      if (!credIdHex || !bioPayloadStr || !stored) {
        showToast('Biometria não cadastrada neste dispositivo.', '⚠️');
        return;
      }

      try {
        const credId = hexToBuffer(credIdHex);
        const challenge = crypto.getRandomValues(new Uint8Array(32));

        showToast('Toque no sensor de digital / Face ID...', '👆');

        const assertion = await navigator.credentials.get({
          publicKey: {
            challenge,
            allowCredentials: [{
              id: credId,
              type: 'public-key'
            }],
            userVerification: 'required',
            timeout: 60000
          }
        });

        if (assertion) {
          const bioData = JSON.parse(bioPayloadStr);
          const bioSalt = new Uint8Array(hexToBuffer(bioData.salt));
          const bioKey = await deriveMasterKey('SAFEPASS_BIO_' + credIdHex, bioSalt);
          const pass = await decryptPayload(bioData.payload, bioKey);

          const parsed = JSON.parse(stored);
          const salt = new Uint8Array(hexToBuffer(parsed.salt));
          const key = await deriveMasterKey(pass, salt);
          const test = await decryptPayload(parsed.verifier, key);

          if (test !== 'VERIFIER_OK') {
            throw new Error('Falha ao validar cofre com chave biométrica');
          }

          masterKeyCrypto = key;
          inMemoryMasterPassword = pass;
          vaultData = await decryptPayload(parsed.payload, key);

          unlockSuccess();
          showToast('Desbloqueado com digital com sucesso!', '🔓');
        }
      } catch (err) {
        console.error('Biometric unlock error:', err);
        showToast('Autenticação biométrica cancelada.', 'ℹ️');
      }
    }

    function updateBiometricUI() {
      const isEnabled = localStorage.getItem(BIOMETRIC_KEY) === 'true';
      const bioBox = document.getElementById('biometric-auth-box');
      const bioBadge = document.getElementById('biometric-status-badge');
      const bioBtn = document.getElementById('btn-toggle-biometric');

      if (bioBox) {
        bioBox.style.display = isEnabled ? 'block' : 'none';
      }
      if (bioBadge) {
        bioBadge.textContent = isEnabled ? '🟢 Ativo' : 'Desativado';
        bioBadge.style.color = isEnabled ? 'var(--accent-emerald)' : 'var(--text-dim)';
        bioBadge.style.background = isEnabled ? 'rgba(16, 185, 129, 0.15)' : 'rgba(255,255,255,0.08)';
      }
      if (bioBtn) {
        bioBtn.textContent = isEnabled ? '✕ Desativar Login por Digital' : '👆 Ativar Login por Digital';
        bioBtn.style.background = isEnabled ? 'rgba(239, 68, 68, 0.2)' : 'linear-gradient(135deg, #10b981, #059669)';
        bioBtn.style.borderColor = isEnabled ? 'var(--accent-rose)' : 'var(--accent-emerald)';
        bioBtn.style.color = isEnabled ? 'var(--accent-rose)' : '#fff';
      }
    }

    // PWA Service Worker Registration
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('sw.js?v=<?= $v ?>').catch(console.error);
    }

    // Init
    window.onload = () => {
      initGoogleOAuthClient();
      checkVaultStatus();
      updateCloudUI();
      updateBiometricUI();
      pullFromCloud();
      if (localStorage.getItem(CLOUD_TOKEN_KEY) && localStorage.getItem(STORAGE_KEY)) {
        pushToCloud();
      }
    };
  </script>
</body>
</html>
