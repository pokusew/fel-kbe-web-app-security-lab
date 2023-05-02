<?php
//
// 888    d8P  888888b.   8888888888
// 888   d8P   888  "88b  888
// 888  d8P    888  .88P  888
// 888d88K     8888888K.  8888888
// 8888888b    888  "Y88b 888
// 888  Y88b   888    888 888
// 888   Y88b  888   d88P 888
// 888    Y88b 8888888P"  8888888888
//
/*
 * ----------------------------
 * Server logic
 * ----------------------------
 */
define("MESSAGES_PER_PAGE", 1);
//define("AES_ENCRYPT_CODE_KEY", "iHw35UKAPaSYKf8SI44CwYPa");
define("AES_ENCRYPT_CODE_KEY", "ebMHfcrRJn3EE1r8SHZ3Gv6N");
define("OTP_SERVER_CORRECTIONS", array(0, -1, -2));

function xor_key($username, $pattern = "kbe_REPLACE_xor_key_2022", $len = 4) {
    return str_replace("REPLACE", substr(sha1($username . $pattern), 0, $len), $pattern);
}

if (isset($_GET["timeslot"])) {
    echo floor(time()/30);
}

session_start();
$db = new mysqli("localhost", "kbe", "kbe", "kbe");

function q($query) {
    global $db;
    $result = $db->query($query);
    if ($result === FALSE) {
        echo("Wrong SQL query: $query");
        exit();
    }
    return $result;
}

function e($str) {
    global $db;
    return $db->escape_string($str);
}

if (isset($_GET["logout"])) {
    unset($_SESSION["username"], $_SESSION["pin"], $_SESSION["logged"]);
    header("Location: index.php");
}

if (isset($_GET["open"]) and in_array($_GET["open"], array("warning.txt", "index.php", "./index.php"))) {
    highlight_file($_GET["open"]);
    exit();
}

if (isset($_GET["code"], $_SESSION["username"], $_SESSION["logged"])) {
    $code = q("SELECT AES_DECRYPT(UNHEX(aes_encrypt_code), '" . e(AES_ENCRYPT_CODE_KEY) . "') AS code FROM codes WHERE username = '" . e($_SESSION["username"]) . "'")->fetch_assoc()["code"];
    echo($code);
    exit();
}

if (isset($_POST["username"], $_POST["password"])) {
    $username = q("SELECT username FROM users WHERE username = '$_POST[username]' AND password = SHA1(CONCAT('$_POST[password]', (SELECT salt FROM users WHERE username = '" . e($_POST["username"]) . "')))")->fetch_assoc()["username"];
    if ($username) {
        if (q("SELECT 1 FROM users WHERE username = '" . e($username) ."' OR secret = '" . e($username) ."'")->num_rows) {
            $_SESSION["username"] = $username;
        } else {
            $wrong_creditials = TRUE;
        }
    } else {
        $wrong_creditials = TRUE;
    }
}

if (isset($_POST["pin"], $_SESSION["username"])) {
    $result = q("SELECT 1 FROM users WHERE username = '" . e($_SESSION["username"]) . "' AND pin = '" . e($_POST["pin"]) . "'");
    if ($result->num_rows) {
        $_SESSION["pin"] = TRUE;
    } else {
        $wrong_pin = TRUE;
    }
}

function otp($secret, $time_slot) {
    $data = str_pad(pack('N', $time_slot), 8, "\0", STR_PAD_LEFT);
    $hash = hash_hmac('sha1', $data, $secret, TRUE);
    $offset = ord(substr($hash, -1)) & 0xF;
    $unpacked = unpack('N', substr($hash, $offset, 4));
    return ($unpacked[1] & 0x7FFFFFFF) % 1e6;
}

function base32_decode($d) {
    list($t, $b, $r) = array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "", "");
    foreach(str_split($d) as $c) {
        $b = $b . sprintf("%05b", strpos($t, $c));
    }
    foreach(str_split($b, 8) as $c) {
        $r = $r . chr(bindec($c));
    }
    return($r);
}

if (isset($_POST["otp"], $_SESSION["username"], $_SESSION["pin"])) {
    $secret = q("SELECT secret FROM users WHERE username = '" . e($_SESSION['username']) ."'")->fetch_assoc()["secret"];
    $otps = array_map(function ($correction) use ($secret) {
        $time_slot = floor(time()/30) + $correction;
        return otp(base32_decode($secret), $time_slot);
    }, OTP_SERVER_CORRECTIONS);
    if (in_array($_POST["otp"], $otps)) {
        $_SESSION["logged"] = TRUE;
    } else {
        $wrong_otp = TRUE;
    }
}

function base64_xor_cipher($data, $key, $encode = TRUE) {
    $data = ($encode) ? $data : base64_decode($data);
    for ($i = 0; $i < strlen($data); $i++) {
        $data[$i] = ($data[$i] ^ $key[$i % strlen($key)]);
    }
    return ($encode) ? base64_encode($data) : $data;
}

function h($val) {
    return htmlspecialchars($val, ENT_QUOTES);
}
/*
 * ----------------------------
 * HTML page
 * ----------------------------
 */
?>
<!DOCTYPE html>
<html>
<head>
<title>KBE - SQL Injection</title>
<style type="text/css">
* {font-family: sans-serif; box-sizing: border-box;}
body {background: #76b852;}
main {position: relative; width: 360px; margin: 0 auto; padding: 30px; margin-top: 12%; text-align: center; background: #FFFFFF; box-shadow: 0 0 20px 0 rgba(0, 0, 0, 0.2), 0 5px 5px 0 rgba(0, 0, 0, 0.24)}
input[type="text"], input[type="password"] {width: 100%; text-align: center; padding: 12px; margin-bottom: 15px; font-size: 18px; background: #f2f2f2; border: none;}
input[type="submit"] {width: 100%; padding: 12px; font-size: 18px; cursor: pointer; background: #4CAF50; color: white; text-transform: uppercase; border: none;}
input[type="submit"]:hover { background: #43A047; }
form {text-align: center; }
h2 {font-weight: normal; font-size: 1.2em;}
h3 {color: red;}
a:link, a:visited, a:active {color: green; text-decoration: none;}
a:hover {text-decoration: underline;}
.wrong {border: 2px solid red !important;}
.message {font-size: 0.8em; }
#warning {position: absolute; left: 15px; top: 15px; color: orange; }
#logout {position: absolute; right: 15px; top: 15px; color: blue; }
}
</style>
</head>
<body>
<main>

<?php
/*
 * ----------------------------
 * Messages
 * ----------------------------
 */
if (isset($_SESSION["username"], $_SESSION["logged"])):
?>
<h1>Messages</h1>
<?php
    $offset = isset($_GET["offset"]) ? $_GET["offset"] : 0;
    $count = q("SELECT COUNT(*) AS count FROM messages WHERE username = '$_SESSION[username]'")->fetch_assoc()["count"];
    $messages = q("SELECT date_time, base64_message_xor_key AS message FROM messages WHERE username = '$_SESSION[username]' LIMIT " . MESSAGES_PER_PAGE . " OFFSET $offset");
    $xorkey = xor_key($_SESSION["username"]);

    while ($row = $messages->fetch_assoc()) {
        echo "<p class='message'>" . h($row["date_time"]) . "</p><p>" . base64_xor_cipher($row["message"], $xorkey, False) . "</p>";
    }

    echo "<p>";
    if ($offset > 0) {
        echo "<a href='?offset=" . (h($offset) - MESSAGES_PER_PAGE) . "'>&lt;&lt; Back</a>&nbsp;";
    }

    if ($count - $offset > MESSAGES_PER_PAGE) {
        echo "<a href='?offset=" . (h($offset) + MESSAGES_PER_PAGE) . "'>Next &gt;&gt;</a>";
    }
    echo "</p>";
?>
<a id="warning" href="index.php?open=warning.txt">Warning!</a>
<a id="logout" href="index.php?logout">Logout</a>

<?php
/*
 * ----------------------------
 * OTP form
 * ----------------------------
 */
elseif (isset($_SESSION["username"], $_SESSION["pin"])):
?>
<h1>3th Step Verification</h1>
<h2>Enter One-Time-Password</h2>
<form id="otp" action="index.php" method="post" autocomplete="off">
<?php if (isset($wrong_otp)) { echo "<h3>Wrong OTP</h3>";} ?>
<input type="text" maxlength="16" name="otp" placeholder="_ _ _ _ _ _ _ _" required autofocus <?php if (isset($wrong_otp)) {echo 'class="wrong"';} ?>>
<input type="submit" value="Verify">
</form>
<a id="logout" href="index.php?logout">Logout</a>

<?php
/*
 * ----------------------------
 * PIN form
 * ----------------------------
 */
elseif (isset($_SESSION["username"])):
?>
<h1>2nd Step Verification</h1>
<h2>Welcome <font color="green"><?php echo h($_SESSION["username"]); ?></font>, enter your four digit PIN number</h2>
<form id="pin" action="index.php" method="post" autocomplete="off">
<?php if (isset($wrong_pin)) { echo "<h3>Wrong pin</h3>";} ?>
<input type="text" maxlength="4" name="pin" placeholder="_ _ _ _" required autofocus <?php if (isset($wrong_pin)) {echo 'class="wrong"';} ?>>
<input type="submit" value="Verify">
</form>
<a id="logout" href="index.php?logout">Logout</a>

<?php
/*
 * ----------------------------
 * Login form
 * ----------------------------
 */
else:
?>
<h1>Login</h1>
<form name="login" action="index.php" method="post" autocomplete="off">
<?php if (isset($wrong_creditials)) {echo "<h3>Wrong credentials</h3>";} ?>
<input type="text" placeholder="Username" name="username" required autofocus <?php if (isset($wrong_creditials)) {echo 'class="wrong"';} ?>>
<input type="password" placeholder="Password" name="password" required <?php if (isset($wrong_creditials)) {echo 'class="wrong"';} ?>>
<input type="submit" value="Login">
</form>

<?php endif; ?>
</main>
</body>
</html>
