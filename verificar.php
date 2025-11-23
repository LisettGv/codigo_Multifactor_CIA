<?php
session_start();
$msg = "";

// Configuración y utilidades JWT
$SECRET_KEY = "clave_secreta_super_segura";

function b64url_decode($data){
  $repl = ['-'=>'+','_'=>'/'];
  $data = strtr($data, $repl);
  return base64_decode($data . str_repeat('=', (4 - strlen($data) % 4) % 4));
}
function validar_mfa_jwt($jwt, $key){
  $parts = explode('.', $jwt);
  if(count($parts) !== 3) return [false,"Formato JWT inválido"];
  [$h,$p,$s] = $parts;
  $payload = json_decode(b64url_decode($p), true);
  if(!$payload) return [false,"Payload inválido"];
  // exp
  if(($payload['exp'] ?? 0) < time()) return [false,"JWT expirado"];
  // iss/aud (opcional, recomendado)
  if(($payload['iss'] ?? '') !== 'mfa-demo') return [false,"Issuer inválido"];
  if(($payload['aud'] ?? '') !== 'mfa-web') return [false,"Audience inválida"];
  // firma
  $calc = rtrim(strtr(base64_encode(hash_hmac('sha256', "$h.$p", $key, true)), '+/', '-_'), '=');
  if($calc !== $s) return [false,"Firma JWT inválida"];
  // challenge
  if(($payload['challenge'] ?? '') !== 'otp') return [false,"JWT sin desafío OTP"];
  return [true,$payload];
}

// Cálculo del tiempo restante para contador
$ttl = 60; // 1 minutos
$remaining = 0;
if (!empty($_SESSION['otp_ts'])) {
    $elapsed = time() - $_SESSION['otp_ts'];
    $remaining = max(0, $ttl - $elapsed);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['accion']) && $_POST['accion'] === 'verificar') {
    $codigo = trim($_POST['codigo'] ?? '');

    if (empty($_SESSION['otp']) || empty($_SESSION['otp_ts'])) {
        $msg = "No hay código generado. Vuelve a iniciar sesión.";
    } else {
        // Valida primero el JWT de desafío
        if(empty($_SESSION['mfa_jwt'])) {
          $msg = "Falta JWT de desafío. Vuelve a iniciar sesión.";
        } else {
          [$ok,$info] = validar_mfa_jwt($_SESSION['mfa_jwt'], $SECRET_KEY);
          if(!$ok){
            $msg = "Error JWT: $info";
          } else if (time() - $_SESSION['otp_ts'] > $ttl) {
            $msg = "El código expiró. Genera uno nuevo.";
            unset($_SESSION['otp'], $_SESSION['otp_ts'], $_SESSION['mfa_jwt']);
            $remaining = 0;
          } else if ($codigo == $_SESSION['otp']) {
            $user = htmlspecialchars($_SESSION['user'] ?? 'usuario');
            $msg = "✅ Autenticación exitosa. Bienvenido, $user.";
            // Consumir OTP y JWT de desafío
            unset($_SESSION['otp'], $_SESSION['otp_ts'], $_SESSION['mfa_jwt']);

            // OPCIONAL: emitir JWT de sesión (1 hora)
            // Nota: reutilizamos utilidades de b64url manualmente aquí
            $header = rtrim(strtr(base64_encode(json_encode(["alg"=>"HS256","typ"=>"JWT"])), '+/', '-_'), '=');
            $payload = rtrim(strtr(base64_encode(json_encode([
              "sub" => $_SESSION['user'] ?? 'admin',
              "email" => $_SESSION['user_email'] ?? null,
              "mfa" => true,
              "iat" => time(),
              "exp" => time() + 3600,
              "iss" => "mfa-demo",
              "aud" => "protected-web"
            ])), '+/', '-_'), '=');
            $signature = rtrim(strtr(base64_encode(hash_hmac('sha256', "$header.$payload", $SECRET_KEY, true)), '+/', '-_'), '=');
            $session_jwt = "$header.$payload.$signature";
            $_SESSION['session_jwt'] = $session_jwt; // disponible si quieres usarlo en otra página
          } else {
            $msg = "❌ Código incorrecto.";
          }
        }
    }
}
?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Verificar OTP</title>
<style>
  body{font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;background:#f7f9fc}
  .card{background:#fff;padding:20px;border-radius:10px;box-shadow:0 6px 18px rgba(31,45,61,.06);width:420px}
  input{width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:6px}
  button{width:100%;padding:10px;background:#28a745;color:#fff;border:0;border-radius:6px;cursor:pointer}
  .msg{margin-bottom:8px}
  .timer{margin:8px 0;color:#555}
  .barWrap{height:8px;background:#eee;border-radius:6px;overflow:hidden}
  .bar{height:8px;background:#28a745;width:0%}
  .row{margin-top:10px}
  .secondary{background:#2b7cff}
</style>
</head>
<body>
  <div class="card">
    <h3>Verificar Código</h3>

    <?php if ($msg) echo "<div class='msg'>$msg</div>"; ?>

    <div class="timer">
      Tiempo restante: <strong><span id="secLeft"><?php echo (int)$remaining; ?></span> s</strong>
    </div>
    <div class="barWrap"><div id="bar" class="bar"></div></div>

    <form method="POST" class="row">
      <input name="codigo" placeholder="Ingresa el código OTP" required />
      <input type="hidden" name="accion" value="verificar" />
      <button type="submit">Verificar</button>
    </form>

    <form method="POST" action="regenerar.php" class="row">
      <button type="submit" class="secondary">Generar un nuevo código</button>
    </form>

    <div class="row">
      <a class="small" href="login.php">Volver a inicio</a>
    </div>

    <?php
    /*
      // Si existe el JWT de sesión, lo mostramos para que lo puedas pegar en jwt.io
      if (!empty($_SESSION['session_jwt'])) {
        echo "<div class='row'><div class='msg'>Token de sesión emitido (JWT):</div><pre style='white-space:pre-wrap;word-wrap:break-word;'>"
        . htmlspecialchars($_SESSION['session_jwt']) . "</pre><p>Puedes copiarlo y verlo en jwt.io</p></div>";
      }
      */
    ?>
  </div>

<script>
  const ttl = 300; // total segundos
  let remaining = parseInt(document.getElementById('secLeft').textContent || '0', 10);
  const bar = document.getElementById('bar');
  function updateBar() {
    const pct = Math.max(0, Math.min(100, (remaining/ttl)*100));
    bar.style.width = pct + '%';
    bar.style.background = remaining > ttl*0.5 ? '#28a745' : (remaining > ttl*0.2 ? '#ffc107' : '#dc3545');
  }
  function tick() {
    if (remaining > 0) {
      remaining--;
      document.getElementById('secLeft').textContent = remaining;
      updateBar();
    }
  }
  updateBar();
  setInterval(tick, 1000);
</script>
</body>
</html>

