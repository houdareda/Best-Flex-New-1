<?php

// ====================== الإعدادات ======================
const SHEET_URL = '';
const PRODUCT = 'Best Flex';
const AGENT = '';              // <-----  هنا الايجنت كود بين النقطتين دول '' ـ



// الحد الأقصى للأوردرات الحقيقية لنفس الـ IP في اليوم (تنزل في الشيت حتى 4 مرات، والمرة 5 لا تنزل)
const IP_MAX_REAL_ORDERS = 4;
const MAX_AGE_SECONDS = 3600;

// ======================================================
date_default_timezone_set('Africa/Cairo');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Robots-Tag: noindex');

function out($code, $arr)
{
    http_response_code($code);
    echo json_encode($arr, JSON_UNESCAPED_UNICODE);
    exit;
}

function secret()
{
    return hash('sha256', 'tok|' . SHEET_URL . '|' . AGENT);
}

function client_ip()
{
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        return $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
}

function cell($v, $max = 300)
{
    $s = trim(strip_tags((string) $v));
    $s = function_exists('mb_substr') ? mb_substr($s, 0, $max) : substr($s, 0, $max);
    return preg_match('/^[=+\-@]/', $s) ? "'" . $s : $s;
}

function bare_host($h)
{
    $h = strtolower(preg_replace('/:\d+$/', '', (string) $h));
    return preg_replace('/^www\./', '', $h);
}

function store_open()
{
    $dir = __DIR__ . '/.submit_data';
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
        @file_put_contents(
            $dir . '/.htaccess',
            "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n"
        );
    }
    $fh = @fopen($dir . '/state.json', 'c+');
    if (!$fh)
        return null;
    flock($fh, LOCK_EX);
    return $fh;
}

function store_read($fh)
{
    rewind($fh);
    $raw = stream_get_contents($fh);
    $d = $raw ? json_decode($raw, true) : array();
    if (!is_array($d))
        $d = array();
    $now = time();
    foreach ($d as $k => $v) {
        if (!is_array($v) || $v[1] < $now) {
            unset($d[$k]);
        }
    }
    return $d;
}

function store_write($fh, $d)
{
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, json_encode($d));
    fflush($fh);
}

function store_close($fh)
{
    if ($fh) {
        flock($fh, LOCK_UN);
        fclose($fh);
    }
}

function get_ip_geo($ip, &$d)
{
    if (!empty($_SERVER['HTTP_CF_IPCOUNTRY'])) {
        return array(
            'country' => strtoupper($_SERVER['HTTP_CF_IPCOUNTRY']),
            'city' => isset($_SERVER['HTTP_CF_IPCITY']) ? $_SERVER['HTTP_CF_IPCITY'] : ''
        );
    }

    $cacheKey = 'geo:' . $ip;
    if (isset($d[$cacheKey]) && is_array($d[$cacheKey])) {
        return $d[$cacheKey][0];
    }

    $geo = array('country' => '', 'city' => '');
    if ($ip !== '127.0.0.1' && $ip !== '0.0.0.0') {
        $ch = curl_init("http://ip-api.com/json/{$ip}?fields=countryCode,city");
        curl_setopt_array($ch, array(
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 2,
            CURLOPT_CONNECTTIMEOUT => 1,
        ));
        $res = curl_exec($ch);
        curl_close($ch);

        if ($res) {
            $data = json_decode($res, true);
            if (isset($data['countryCode'])) {
                $geo['country'] = strtoupper($data['countryCode']);
                $geo['city'] = isset($data['city']) ? $data['city'] : '';
            }
        }
    }

    $d[$cacheKey] = array($geo, time() + 172800);
    return $geo;
}

$method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';

// 1. إصدار التوكن عبر GET
if ($method === 'GET') {
    $ts = time();
    $nonce = bin2hex(random_bytes(8));
    $sig = hash_hmac('sha256', $ts . '.' . $nonce, secret());
    out(200, array('t' => $ts . '.' . $nonce . '.' . $sig));
}

if ($method !== 'POST') {
    out(405, array('ok' => false));
}

// 2. التحقق من الدومين
$origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';
if ($origin !== '') {
    $oh = bare_host(parse_url($origin, PHP_URL_HOST));
    $hh = bare_host(isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '');
    if ($oh !== $hh) {
        out(403, array('ok' => false, 'error' => 'origin'));
    }
}

$raw = file_get_contents('php://input', false, null, 0, 4097);
if ($raw === false || strlen($raw) > 4096) {
    out(413, array('ok' => false));
}
$b = json_decode($raw, true);
if (!is_array($b)) {
    out(400, array('ok' => false));
}

// Honeypot: نجاح وهمي صامت للبوتات مع تعطيل البيكسل
if (!empty($b['hp']) && trim((string) $b['hp']) !== '') {
    out(200, array('ok' => true, 'pixel' => false));
}

// فحص التوكن وصلاحيته
$parts = explode('.', isset($b['t']) ? (string) $b['t'] : '');
if (count($parts) !== 3 || !ctype_digit($parts[0])) {
    out(403, array('ok' => false, 'error' => 'token'));
}
list($ts, $nonce, $sig) = $parts;
if (!hash_equals(hash_hmac('sha256', $ts . '.' . $nonce, secret()), $sig)) {
    out(403, array('ok' => false, 'error' => 'token_invalid'));
}
$age = time() - (int) $ts;
if ($age > MAX_AGE_SECONDS) {
    out(403, array('ok' => false, 'error' => 'expired'));
}

// تنظيف والتحقق من صحة الاسم ورقم الهاتف
$phone = strtr(
    isset($b['phone']) ? (string) $b['phone'] : '',
    array('٠' => '0', '١' => '1', '٢' => '2', '٣' => '3', '٤' => '4', '٥' => '5', '٦' => '6', '٧' => '7', '٨' => '8', '٩' => '9')
);
$phone = preg_replace('/[\s\-+()]/', '', $phone);
$name = cell(isset($b['name']) ? $b['name'] : '', 60);

if (!preg_match('/^(05|06|07|08)\d{8}$/', $phone) || preg_match('/^(\d)\1{9}$/', $phone) || mb_strlen($name, 'UTF-8') < 2) {
    out(400, array('ok' => false, 'error' => 'invalid'));
}

// كشف نوع الجهاز (كمبيوتر / لابتوب / تابلت)
$screenWidth = 0;
if (!empty($b['sz'])) {
    $szParts = explode('x', (string) $b['sz']);
    $screenWidth = (int) $szParts[0];
}

$ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
$isMobileUA = (bool) preg_match('/Mobile|Android|iP(hone|od)|IEMobile|BlackBerry|Kindle|Silk-Accelerated|(hpw|web)OS|Opera M(obi|ini)/i', $ua);

$isPC = false;
if ($screenWidth > 768) {
    $isPC = true;
} elseif ($screenWidth <= 0 && !$isMobileUA) {
    $isPC = true;
} elseif (preg_match('/Windows NT|Macintosh|Mac OS X(?!.*Mobile)|Linux x86_64/i', $ua) && !preg_match('/Android|Mobile/i', $ua)) {
    $isPC = true;
}

$ip = client_ip();
$tk = 'tk:' . substr(hash('sha256', $nonce), 0, 20);
$ipk = 'ip:' . substr(hash('sha256', $ip), 0, 20);

$fh = store_open();
$geo = array('country' => '', 'city' => '');
$ipCount = 0;

if ($fh) {
    $d = store_read($fh);
    $now = time();

    // فحص استخدام التوكن مرة واحدة
    if (isset($d[$tk])) {
        store_close($fh);
        out(403, array('ok' => false, 'error' => 'token_used'));
    }

    $ipCount = isset($d[$ipk]) ? (int) $d[$ipk][0] : 0;

    // فحص حد الـ IP: من بعد المرة الرابعة (المرة الخامسة وما بعدها) -> لا ينزل في الشيت وتحويل للثانكس بدون تفعيل البيكسل
    if ($ipCount >= IP_MAX_REAL_ORDERS) {
        $d[$tk] = array(1, $now + MAX_AGE_SECONDS + 60);
        $d[$ipk] = array($ipCount + 1, isset($d[$ipk]) ? $d[$ipk][1] : $now + 86400);
        store_write($fh, $d);
        store_close($fh);
        out(200, array('ok' => true, 'pixel' => false));
    }

    $geo = get_ip_geo($ip, $d);

    $d[$tk] = array(1, $now + MAX_AGE_SECONDS + 60);
    $d[$ipk] = array($ipCount + 1, isset($d[$ipk]) ? $d[$ipk][1] : $now + 86400);

    store_write($fh, $d);
    store_close($fh);
}

// بناء تصنيف المخاطر (Risk)
$risks = array();


// 2. فحص أجهزة الـ PC / Tablet
if ($isPC) {
    $risks[] = 'PC';
}

// 3. فحص تكرار الـ IP (عند التسجيل للمرة الثانية وحتى الرابعة)
if ($ipCount > 0) {
    $risks[] = 'مكرر IP';
}

$risk = empty($risks) ? 'OK' : implode(' | ', $risks);

// حساب مدة التسجيل بالثواني للمتابعة والإحصاء فقط (بدون أي إجراء عقابي)
$durationSeconds = ($age >= 0) ? $age : 0;
$durationText = $durationSeconds . ' ثانية';

$row = array(
    'Name' => $name,
    'Number' => $phone,
    'Product' => PRODUCT,
    'Agent Code' => AGENT,
    'Unique Key' => 'KEY-True-' . date('y_m_d_His') . '-' . bin2hex(random_bytes(4)),
    'Date' => date('Y-m-d'),
    'Time' => date('h:i:s A'),
    'Duration' => $durationText,
    'City' => cell($geo['city'], 60),
    'Country' => cell($geo['country'], 10),
    'IP' => $ip,
    'Honeypot' => '',
    'FingerPrint' => '',
    'ScreenSize' => cell(isset($b['sz']) ? $b['sz'] : '', 20),
    'TimeZone' => cell(isset($b['tz']) ? $b['tz'] : '', 60),
    'UserAgent' => cell(isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '', 300),
    'Page URL' => cell(isset($b['pg']) ? $b['pg'] : '', 300),
    'Referrer' => cell(isset($b['rf']) ? $b['rf'] : 'Direct', 300),
    'Domain' => bare_host(isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : ''),
    'Risk' => $risk,
);

// الإرسال إلى SheetMonkey
$ch = curl_init(SHEET_URL);
curl_setopt_array($ch, array(
    CURLOPT_POST => true,
    CURLOPT_HTTPHEADER => array('Content-Type: application/json'),
    CURLOPT_POSTFIELDS => json_encode($row, JSON_UNESCAPED_UNICODE),
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_CONNECTTIMEOUT => 7,
    CURLOPT_TIMEOUT => 15,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
));

$res = curl_exec($ch);
$code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($res === false || $code < 200 || $code >= 400) {
    out(502, array('ok' => false, 'error' => 'upstream'));
}

// تحديد إمكانية تفعيل البيكسل: بغض النظر عن الدولة
$allowPixel = true;

$pxToken = '';
if ($allowPixel) {
    $pTs = time();
    $pSig = hash_hmac('sha256', 'px|' . $pTs . '|' . $nonce, secret());
    $pxToken = $pTs . '.' . $pSig;
}

out(200, array(
    'ok' => true,
    'pixel' => $allowPixel,
    'px_token' => $pxToken
));