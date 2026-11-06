<?php
/**
 * RavakWP Build Engine — LOCAL MODE dispatcher (optional convenience).
 *
 * Primary local flow (documented in docs/03-new-build-fa.md and
 * build-engine/README.md) is the persistent compose service:
 *
 *     cd build-engine/docker && cp .env.example .env && docker compose up -d worker
 *
 * This script is for hosts that prefer spawning a throwaway container per
 * build (the plugin's BuildDispatcher may call it via proc_open):
 *
 *     echo "$HMAC_KEY" | php local/dispatch.php \
 *         --site=https://shop.example.com --build=42
 *
 * SECURITY: the HMAC key is read ONLY from the STDIN pipe — never from argv
 * (argv is visible in `ps`/shell history). The key is handed to the container
 * through a 0600 temp env-file that is zero-wiped + deleted afterwards.
 *
 * The container runs `worker.py --once --build-id N`, which polls the WP
 * table queue (HMAC-signed /internal/poll), claims build N, runs the full
 * pipeline inside the container and exits. Requires the `docker` binary.
 *
 * PHP 8.2+, no composer dependencies.
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "dispatch.php must run from the CLI\n");
    exit(2);
}

const DEFAULT_IMAGE = 'ravakwp/build-engine:1.0.0';

// ---------------------------------------------------------------------------
// Args: --site=URL --build=ID [--image=NAME] [--build-engine-dir=PATH]
// ---------------------------------------------------------------------------

function parse_args(array $argv): array
{
    $opts = ['site' => '', 'build' => 0, 'image' => DEFAULT_IMAGE, 'dir' => ''];
    foreach (array_slice($argv, 1) as $arg) {
        if (str_starts_with($arg, '--site=')) {
            $opts['site'] = rtrim(substr($arg, 7), '/');
        } elseif (str_starts_with($arg, '--build=')) {
            $opts['build'] = (int) substr($arg, 8);
        } elseif (str_starts_with($arg, '--image=')) {
            $opts['image'] = substr($arg, 8);
        } elseif (str_starts_with($arg, '--build-engine-dir=')) {
            $opts['dir'] = substr($arg, 19);
        }
    }
    return $opts;
}

$opts = parse_args($argv);
if ($opts['site'] === '' || $opts['build'] <= 0) {
    fwrite(STDERR, "usage: echo KEY | php dispatch.php --site=https://… --build=42 [--image=…] \n");
    exit(2);
}
if (preg_match('/(--hmac|WP_HMAC_KEY)/i', implode(' ', $argv)) === 1) {
    fwrite(STDERR, "SECURITY: HMAC key must arrive via STDIN, never via argv.\n");
    exit(2);
}

// ---------------------------------------------------------------------------
// 1. docker binary present?
// ---------------------------------------------------------------------------

exec('command -v docker 2>/dev/null', $out, $code);
if ($code !== 0 || ($out[0] ?? '') === '') {
    fwrite(STDERR, "docker binary not found — install Docker first (داکر نصب نیست)\n");
    exit(2);
}
$docker = $out[0];

// ---------------------------------------------------------------------------
// 2. image built? build it from build-engine/docker when missing
// ---------------------------------------------------------------------------

$engineDir = $opts['dir'] !== ''
    ? $opts['dir']
    : dirname(__DIR__) . '/docker';
if (!is_dir($engineDir)) {
    fwrite(STDERR, "build-engine/docker directory not found: {$engineDir}\n");
    exit(2);
}
exec(sprintf('%s image inspect %s >/dev/null 2>&1', escapeshellarg($docker), escapeshellarg($opts['image'])), $_, $hasImage);
if ($hasImage !== 0) {
    echo "[dispatch] image {$opts['image']} missing — building (a few minutes)…\n";
    passthru(sprintf(
        '%s build -t %s %s',
        escapeshellarg($docker),
        escapeshellarg($opts['image']),
        escapeshellarg($engineDir)
    ), $buildCode);
    if ($buildCode !== 0) {
        fwrite(STDERR, "docker build failed (کد خطا {$buildCode})\n");
        exit($buildCode);
    }
}

// ---------------------------------------------------------------------------
// 3. read the HMAC key from STDIN (first line) — never argv
// ---------------------------------------------------------------------------

$key = '';
$stdin = fopen('php://stdin', 'rb');
if (is_resource($stdin)) {
    $key = trim((string) fgets($stdin, 4096));
    fclose($stdin);
}
if ($key === '') {
    fwrite(STDERR, "empty STDIN — pipe the HMAC key: echo KEY | php dispatch.php …\n");
    exit(2);
}

// ---------------------------------------------------------------------------
// 4. temp env-file (0600) → docker run --env-file → shred
// ---------------------------------------------------------------------------

$envFile = tempnam(sys_get_temp_dir(), 'rvk-env-');
if ($envFile === false) {
    fwrite(STDERR, "cannot create temp env file\n");
    exit(2);
}
chmod($envFile, 0600);
file_put_contents($envFile, implode("\n", [
    'WORKER_MODE=local',
    'WP_SITE_URL=' . $opts['site'],
    'WP_HMAC_KEY=' . $key,
    'RVK_ONCE_BUILD_ID=' . $opts['build'],
]));

$cmd = sprintf(
    '%s run --rm --env-file %s -v ravakwp-workspaces:/var/lib/ravakwp/workspaces %s python3 /opt/worker/worker.py --once --build-id %d',
    escapeshellarg($docker),
    escapeshellarg($envFile),
    escapeshellarg($opts['image']),
    $opts['build']
);

echo "[dispatch] {$cmd}   (key hidden)\n";
$process = proc_open($cmd, [0 => STDIN, 1 => STDOUT, 2 => STDERR], $pipes);

// shred the env file regardless of the outcome (overwrite with zeros)
if (is_resource(@fopen($envFile, 'r+b'))) {
    $fh = fopen($envFile, 'r+b');
    fwrite($fh, str_repeat("\0", (int) (filesize($envFile) ?: 1)));
    fclose($fh);
}
@unlink($envFile);

if (!is_resource($process)) {
    fwrite(STDERR, "proc_open failed — cannot start docker\n");
    exit(2);
}
$exit = proc_close($process);
echo "[dispatch] build {$opts['build']} container exited with code {$exit}\n";
exit($exit);
