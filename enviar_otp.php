<?php
session_start();

if (!isset($_SESSION['otp'])) {
    echo "No hay OTP. <a href='login.php'>Volver</a>";
    exit;
}

$otp = $_SESSION['otp'];
$email = $_SESSION['user_email'] ?? '(sin correo)';
$user  = $_SESSION['user'] ?? '(usuario)';

// Registrar en archivo con fecha y usuario
$line = date('c') . " | Usuario: $user | Email: $email | OTP: $otp\n";
file_put_contents('otp_log.txt', $line, FILE_APPEND);

// Mostrar OTP y simulación de envío
?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>OTP generado</title>
<style>
  body{font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;background:#f7f9fc}
  .card{background:#fff;padding:20px;border-radius:10px;box-shadow:0 6px 18px rgba(31,45,61,.06);width:420px}
  pre{background:#f6f8fa;border:1px solid #e1e4e8;padding:10px;border-radius:6px}
  a.btn{display:inline-block;margin-top:10px;padding:10px 12px;background:#2b7cff;color:#fff;text-decoration:none;border-radius:6px}
  button{padding:8px 10px;border:0;border-radius:6px;background:#666;color:#fff;cursor:pointer}
  small{color:#666}
</style>
</head>
<body>
  <div class="card">
    <h3>OTP generado</h3>
    <p>Simulamos el envío del código al correo: <strong><?php echo htmlspecialchars($email); ?></strong></p>
    <details>
      <summary>Mostrar OTP (modo demo)</summary>
      <pre id="otp"><?php echo htmlspecialchars($otp); ?></pre>
      <button onclick="copyOtp()">Copiar</button>
    </details>
    <a class="btn" href="verificar.php">Ir a verificar</a>
    <small>El código y el ticket JWT expiran en 5 minutos.</small>
  </div>
<script>
function copyOtp(){
  const text = document.getElementById('otp').textContent.trim();
  navigator.clipboard.writeText(text).then(()=>alert('Código copiado'));
}
</script>
</body>
</html>


