<?php
session_start();
$msg = "";

// Utilidades JWT (Base64URL)
function b64url($data){ return rtrim(strtr(base64_encode($data), '+/', '-_'), '='); }

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $usuario = trim($_POST['usuario'] ?? '');
    $pass    = trim($_POST['password'] ?? '');
    $email   = trim($_POST['email'] ?? '');

    // Validación mínima
    if ($usuario === "admin" && $pass === "1234") {
        // Generar OTP seguro y guardarlo en sesión con timestamp
        $otp = random_int(100000, 999999);
        $_SESSION['otp'] = $otp;
        $_SESSION['otp_ts'] = time();
        $_SESSION['user'] = $usuario;
        $_SESSION['user_email'] = $email;

        // ==== JWT CHALLENGE ====
        $SECRET_KEY = "clave_secreta_super_segura"; // clave compartida
        $header = b64url(json_encode(["alg"=>"HS256","typ"=>"JWT"]));
        $payload = b64url(json_encode([
          "sub" => $usuario,
          "email" => $email,
          "challenge" => "otp",
          "iat" => time(),
          "exp" => time()+60, // válido 1 min, igual que OTP
          "iss" => "mfa-demo",
          "aud" => "mfa-web"
        ]));
        $signature = b64url(hash_hmac('sha256', "$header.$payload", $SECRET_KEY, true));
        $jwt = "$header.$payload.$signature";

        // Guarda el JWT de desafío en sesión
        $_SESSION['mfa_jwt'] = $jwt;

        // Redirigir a página de envío/muestra del OTP
        header("Location: enviar_otp.php");
        exit;
    } else {
        $msg = "Credenciales incorrectas.";
    }
}
?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Login - MFA con JWT</title>
<style>
  body{font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;background:#f5f7fb}
  .card{background:#fff;padding:22px;border-radius:10px;box-shadow:0 6px 18px rgba(31,45,61,.06);width:340px}
  input{width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:6px}
  button{width:100%;padding:10px;background:#2b7cff;color:#fff;border:0;border-radius:6px;cursor:pointer}
  .msg{color:#c00;margin-bottom:8px}
  small{color:#666}
</style>
</head>
<body>
  <div class="card">
    <h3>Ingreso</h3>
    <?php if($msg) echo "<div class='msg'>$msg</div>"; ?>
    <form method="POST">
      <input name="usuario" placeholder="Usuario (admin)" required />
      <input name="password" type="password" placeholder="Contraseña (1234)" required />
      <input name="email" type="email" placeholder="Correo (opcional)" />
      <button type="submit">Ingresar</button>
    </form>
  </div>
</body>
</html>

