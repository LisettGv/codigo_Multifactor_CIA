<?php
session_start();
if (empty($_SESSION['user'])) {
  header("Location: login.php"); exit;
}

// Genera un nuevo OTP
$otp = random_int(100000, 999999);
$_SESSION['otp'] = $otp;
$_SESSION['otp_ts'] = time();

// Opcional: también puedes regenerar el JWT de desafío para mantener tiempos sincronizados
$SECRET_KEY = "clave_secreta_super_segura";
function b64url($data){ return rtrim(strtr(base64_encode($data), '+/', '-_'), '='); }
$header = b64url(json_encode(["alg"=>"HS256","typ"=>"JWT"]));
$payload = b64url(json_encode([
  "sub" => $_SESSION['user'] ?? 'admin',
  "email" => $_SESSION['user_email'] ?? null,
  "challenge" => "otp",
  "iat" => time(),
  "exp" => time()+60,
  "iss" => "mfa-demo",
  "aud" => "mfa-web"
]));
$signature = b64url(hash_hmac('sha256', "$header.$payload", $SECRET_KEY, true));
$_SESSION['mfa_jwt'] = "$header.$payload.$signature";

// Redirige a la página que muestra el OTP
header("Location: enviar_otp.php");
exit;

