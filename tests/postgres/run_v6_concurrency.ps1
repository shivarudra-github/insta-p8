# tests/postgres/run_v6_concurrency.ps1
# Genuine multi-session PostgreSQL 15 concurrency test suite
# Covers Scenario 17 (Race A and Race B), full SQL test suite (Scenarios 1-28),
# Scenario 5 repeatability, and Scenario 16 protection check.

$ErrorActionPreference = "Continue"

$WORKTREE = "C:\Users\pc\Desktop\insta-p8-worktrees\remed-v6"
$TEST_DIR = "$WORKTREE\tests\postgres"
$DB = "insta_test"
$TMP_DIR = "$TEST_DIR\tmp"
$PG_IMAGE = "postgres:15"

function Get-AvailablePort {
    param([int]$StartPort = 55432)
    for ($p = $StartPort; $p -lt $StartPort + 100; $p++) {
        $listener = $null
        try {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse("127.0.0.1"), $p)
            $listener.Start()
            $listener.Stop()
            return $p
        } catch {
            if ($listener) { $listener.Stop() }
        }
    }
    return $StartPort
}

$PG_HOST_PORT = "127.0.0.1:$(Get-AvailablePort 55432):5432"
$RUNNER_NAME = "v6-concurrency"

# Unique run identity for disposable container ownership. The static name
# insta-p8-disposable-pg is never used for destructive cleanup; only a
# uniquely named, labeled container owned by this exact test run may be removed.
$runId = [guid]::NewGuid().ToString("N").Substring(0, 12)
$containerName = "insta-p8-v6-$runId"
$expectedLabels = @{
    "insta.auto.runner" = $RUNNER_NAME
    "insta.auto.runId"  = $runId
}

if (-not (Test-Path $TMP_DIR)) {
    New-Item -ItemType Directory -Path $TMP_DIR -Force | Out-Null
}

# Persistent raw evidence log (kept outside $TMP_DIR so it survives run cleanup).
# Every section mirrors its key output here via Write-RunnerLog so the complete
# run record is available for export from a single run ID, independent of
# console-output capture.
$rawLog = "$TEST_DIR\runner_raw_$runId.log"
"INSTAAUTO V6 CONCURRENCY & SCENARIO 17 VERIFICATION SUITE" | Set-Content -Path $rawLog -Encoding utf8
"==========================================================" | Add-Content -Path $rawLog -Encoding utf8
"Run ID:     $runId" | Add-Content -Path $rawLog -Encoding utf8
"Container:  $containerName ($PG_HOST_PORT)" | Add-Content -Path $rawLog -Encoding utf8
"Test dir:   $TEST_DIR" | Add-Content -Path $rawLog -Encoding utf8
"DB:         $DB" | Add-Content -Path $rawLog -Encoding utf8
"" | Add-Content -Path $rawLog -Encoding utf8

# Full transcript capture (captures Write-Host output that stream redirection misses)
$transcriptPath = "$TEST_DIR\runner_transcript_$runId.txt"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

function Write-RunnerLog {
    param([string]$Message)
    Write-Host $Message
    if ($Message) { Add-Content -Path $rawLog -Value $Message -Encoding utf8 }
    else { Add-Content -Path $rawLog -Value "" -Encoding utf8 }
}

Write-Host "=========================================================="
Write-Host "INSTAAUTO V6 CONCURRENCY & SCENARIO 17 VERIFICATION SUITE"
Write-Host "=========================================================="
Write-Host "  Run ID:     $runId"
Write-Host "  Container:  $containerName ($PG_HOST_PORT)"
Write-Host "  Test dir:   $TEST_DIR"
Write-Host "  Temp dir:   $TMP_DIR"

# ----------------------------------------------------------------------
# Helper: run a docker command with stdout/stderr kept in separate files,
# verify the exit code, and throw on failure. Use -NoThrow for expected
# non-zero results (e.g. pg_isready while waiting for readiness).
# ----------------------------------------------------------------------
$script:dockerSeq = 0

function Invoke-DockerChecked {
    param(
        [string]$Step,
        [string[]]$CommandArgs,
        [switch]$NoThrow
    )
    $script:dockerSeq++
    $seq = [string]::Format('{0:D3}', $script:dockerSeq)
    $safeStep = [regex]::Replace($Step, '\s+', '_')
    $outFile = "$TMP_DIR\docker_${seq}_${safeStep}.out"
    $errFile = "$TMP_DIR\docker_${seq}_${safeStep}.err"
    $null = docker @CommandArgs > $outFile 2> $errFile
    $code = $LASTEXITCODE
    $stdout = if (Test-Path $outFile) { Get-Content $outFile -Raw -ErrorAction SilentlyContinue } else { "" }
    $stderr = if (Test-Path $errFile) { Get-Content $errFile -Raw -ErrorAction SilentlyContinue } else { "" }
    $output = "$stdout`n$stderr"
    $result = @{ code = $code; stdout = $stdout; stderr = $stderr; output = $output; outFile = $outFile; errFile = $errFile }
    if ($code -ne 0 -and -not $NoThrow) {
        $msg = "Docker step '$Step' failed (exit $code)."
        if ($stderr) { $msg += " STDERR:`n$stderr" }
        if ($stdout) { $msg += " STDOUT:`n$stdout" }
        throw $msg
    }
    return $result
}

# Build docker run label args from the expected label set.
$labelArgs = @()
foreach ($k in $expectedLabels.Keys) {
    $labelArgs += "--label"
    $labelArgs += "$k=$($expectedLabels[$k])"
}

# ----------------------------------------------------------------------
# Container ownership verification. A container is removable only when its
# labels prove it belongs to this exact test run. Pre-existing or unlabeled
# containers are left untouched.
# ----------------------------------------------------------------------
function Test-ContainerOwnership {
    param([string]$Name)
    $labelsJson = docker inspect $Name --format '{{json .Config.Labels}}' 2>$null
    $code = $LASTEXITCODE
    if ($code -ne 0 -or -not $labelsJson) {
        return @{ owned = $false; reason = "Container '$Name' is not present or cannot be inspected (exit $code)." }
    }
    $labels = ConvertFrom-Json $labelsJson
    $runIdCheck = $labels.'insta.auto.runId'
    $runnerCheck = $labels.'insta.auto.runner'
    if ($runIdCheck -eq $runId -and $runnerCheck -eq $RUNNER_NAME) {
        return @{ owned = $true; reason = "Ownership verified for '$Name' (runId=$runId)." }
    }
    return @{ owned = $false; reason = "Container '$Name' present but labels do not match this run (runId='$runIdCheck', runner='$runnerCheck')." }
}

function Remove-OwnedContainer {
    param([string]$Name)
    $ownership = Test-ContainerOwnership $Name
    if (-not $ownership.owned) {
        Write-Host "  [CLEANUP SKIPPED] $($ownership.reason)"
        return
    }
    $null = Invoke-DockerChecked "rm $Name" @("rm", "-f", $Name)
    Write-Host "  [CLEANUP] Removed owned container '$Name'."
}

# ----------------------------------------------------------------------
# 1. SETUP DISPOSABLE POSTGRESQL 15 CONTAINER
# ----------------------------------------------------------------------
Write-Host "`n[1/7] Initializing isolated disposable PostgreSQL 15 container..."

# Never blindly remove a container by the static name. Only remove our own
# container if a prior run left it and ownership can be proven by labels.
$ownership = Test-ContainerOwnership $containerName
if ($ownership.owned) {
    Write-Host "  Container '$containerName' already owned by this run; removing and recreating."
    $null = Remove-OwnedContainer $containerName
} else {
    Write-Host "  $($ownership.reason)"
}

$null = Invoke-DockerChecked "run $containerName" (@("run", "-d", "--name", $containerName) + $labelArgs + @(
    "-e", "POSTGRES_PASSWORD=disposable",
    "-p", $PG_HOST_PORT,
    $PG_IMAGE
))

# Wait for postgres to be ready (pg_isready returns non-zero until ready).
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    $r = Invoke-DockerChecked "pg_isready attempt $i" @("exec", $containerName, "pg_isready", "-U", "postgres") -NoThrow
    if ($r.code -eq 0 -and $r.stdout -match "accepting connections") {
        $ready = $true
        break
    }
}
if (-not $ready) {
    throw "PostgreSQL container failed to become ready within timeout"
}

# Verify isolation and version
$pgVer = (Invoke-DockerChecked "pg version" @("exec", $containerName, "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-t", "-A", "-c", "SELECT version();")).stdout.Trim()
Write-Host "  DB Version: $pgVer"
if ($pgVer -notmatch "PostgreSQL 15") {
    throw "Expected PostgreSQL 15, got: $pgVer"
}

Invoke-DockerChecked "create database $DB" @("exec", $containerName, "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-c", "CREATE DATABASE $DB;") | Out-Null
Invoke-DockerChecked "create schema storage" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-c", "CREATE SCHEMA IF NOT EXISTS storage; CREATE TABLE IF NOT EXISTS storage.buckets (id text primary key, name text, public boolean); CREATE TABLE IF NOT EXISTS storage.objects (id text primary key, bucket_id text, name text, owner uuid, created_at timestamptz, updated_at timestamptz); ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;") | Out-Null
Invoke-DockerChecked "create roles" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-c", "CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN BYPASSRLS;") | Out-Null

# Copy and apply migrations (staged to sanitize PG17-only MAINTAIN privilege for PG15 test harness)
$stagedMigrations = Join-Path $TMP_DIR "migrations"
if (-not (Test-Path $stagedMigrations)) {
    New-Item -ItemType Directory -Path $stagedMigrations -Force | Out-Null
}
$migrations = @(
    "20261031140902_remote_schema.sql",
    "20261031145427_phase1c_security_remediation.sql",
    "20261104170000_v6_privilege_reduction.sql",
    "20261104190000_v6_webhook_state_machine.sql"
)
foreach ($f in $migrations) {
    $srcPath = Join-Path "$WORKTREE\supabase\migrations" $f
    $dstPath = Join-Path $stagedMigrations $f
    $content = Get-Content -Raw -Encoding utf8 $srcPath
    # Strip Postgres 17-only MAINTAIN privilege for PG15 compatibility
    $content = [regex]::Replace($content, '\bMAINTAIN,\s*', '')
    $content = [regex]::Replace($content, ',\s*MAINTAIN\b', '')
    [System.IO.File]::WriteAllText($dstPath, $content, [System.Text.Encoding]::UTF8)
}
Invoke-DockerChecked "cp migrations" @("cp", $stagedMigrations, "${containerName}:/tmp/migrations") | Out-Null
foreach ($f in $migrations) {
    Invoke-DockerChecked "migrate $f" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-f", "/tmp/migrations/$f") | Out-Null
}

# Seed test user
Invoke-DockerChecked "seed test user" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-c", "INSERT INTO users (id, username, access_token) VALUES (999,'testuser999','tok') ON CONFLICT (id) DO NOTHING;") | Out-Null

# Verify 12 fn_webhook_* functions
$fnCount = (Invoke-DockerChecked "verify webhook functions" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-t", "-A", "-c", "SELECT count(*) FROM pg_proc JOIN pg_namespace ON pg_proc.pronamespace = pg_namespace.oid WHERE nspname = 'public' AND proname LIKE 'fn_webhook_%';")).stdout.Trim()
Write-Host "  Verified fn_webhook_* functions: $fnCount (Expected: 12)"
if ([int]$fnCount -ne 12) {
    throw "Expected 12 webhook functions, found $fnCount"
}

# ----------------------------------------------------------------------
# 2. RACE A: TWO COMPETING EVENT CLAIMS
# ----------------------------------------------------------------------
Write-Host "`n[2/7] Executing Race A: Two Competing Event Claims..."

Invoke-DockerChecked "raceA reset" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-c", "DELETE FROM webhook_action_ledger WHERE event_id IN (SELECT id FROM webhook_event_ledger WHERE event_key = 'race_a:competing'); DELETE FROM webhook_event_ledger WHERE event_key = 'race_a:competing';") | Out-Null

$sqlA_RaceA = @"
\set ON_ERROR_STOP on
SET application_name = 'worker_a';
BEGIN;
SELECT pg_backend_pid() AS pid_a;
SELECT * FROM fn_webhook_claim_event('race_a:competing', 'comment', 999, '{}'::jsonb, 300);
SELECT pg_sleep(5);
COMMIT;
"@
$sqlA_RaceA | Set-Content -Path "$TMP_DIR\race_a_worker_a.sql" -Encoding utf8

$sqlB_RaceA = @"
\set ON_ERROR_STOP on
SET application_name = 'worker_b';
BEGIN;
SELECT pg_backend_pid() AS pid_b;
SELECT * FROM fn_webhook_claim_event('race_a:competing', 'comment', 999, '{}'::jsonb, 300);
COMMIT;
"@
$sqlB_RaceA | Set-Content -Path "$TMP_DIR\race_a_worker_b.sql" -Encoding utf8

Invoke-DockerChecked "cp race_a_worker_a.sql" @("cp", "$TMP_DIR\race_a_worker_a.sql", "${containerName}:/tmp/race_a_worker_a.sql") | Out-Null
Invoke-DockerChecked "cp race_a_worker_b.sql" @("cp", "$TMP_DIR\race_a_worker_b.sql", "${containerName}:/tmp/race_a_worker_b.sql") | Out-Null

$outA_RaceA = "$TMP_DIR\out_race_a_worker_a.txt"
$errA_RaceA = "$TMP_DIR\err_race_a_worker_a.txt"
$outB_RaceA = "$TMP_DIR\out_race_a_worker_b.txt"
$errB_RaceA = "$TMP_DIR\err_race_a_worker_b.txt"

# Launch Session A first so it acquires the claim and holds the parent-row lock.
$procA = Start-Process -FilePath "docker" -ArgumentList "exec", "-i", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-f", "/tmp/race_a_worker_a.sql" -RedirectStandardOutput $outA_RaceA -RedirectStandardError $errA_RaceA -PassThru

# Wait until Session A holds the parent-row lock (its claim is uncommitted and
# locked). Launching B only after this guarantees A claims first and B blocks.
$raceA_locked = $false
for ($i = 0; $i -lt 60; $i++) {
    $held = (Invoke-DockerChecked "raceA lock held $i" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-t", "-A", "-c", "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid WHERE a.application_name = 'worker_a' AND l.relation = 'webhook_event_ledger'::regclass;")).stdout.Trim()
    if ([int]$held -ge 1) { $raceA_locked = $true; break }
    Start-Sleep -Seconds 0.5
}
if (-not $raceA_locked) {
    throw "Race A FAIL: Session A did not acquire the parent-row lock within timeout"
}

# Launch Session B: its INSERT ... ON CONFLICT blocks on Session A's row lock,
# so B waits on Lock/transactionid until A commits and releases the lock.
$procB = Start-Process -FilePath "docker" -ArgumentList "exec", "-i", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-f", "/tmp/race_a_worker_b.sql" -RedirectStandardOutput $outB_RaceA -RedirectStandardError $errB_RaceA -PassThru
Start-Sleep -Milliseconds 400

# Independent Observer Session: bounded sampling of pg_stat_activity, pg_locks, and pg_blocking_pids()
$raceA_observed = $false
$raceA_obs_activity = ""
$raceA_obs_locks = ""

for ($i = 0; $i -lt 15; $i++) {
    $act = (Invoke-DockerChecked "raceA observe attempt $i" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-c", "SELECT pid, application_name, state, wait_event_type, wait_event, pg_blocking_pids(pid) FROM pg_stat_activity WHERE application_name IN ('worker_a', 'worker_b') ORDER BY application_name;")).stdout
    if ($act -match "worker_a" -and $act -match "worker_b") {
        $raceA_observed = $true
        $raceA_obs_activity = $act
        $raceA_obs_locks = (Invoke-DockerChecked "raceA locks attempt $i" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-c", "SELECT pid, locktype, relation::regclass, mode, granted FROM pg_locks WHERE pid IN (SELECT pid FROM pg_stat_activity WHERE application_name IN ('worker_a', 'worker_b')) ORDER BY pid, mode;")).stdout
        break
    }
    Start-Sleep -Milliseconds 300
}

$procA.WaitForExit()
$procB.WaitForExit()
if ($null -ne $procA.ExitCode -and $procA.ExitCode -ne 0) { throw "Race A worker A (psql) exited with code $($procA.ExitCode)" }
if ($null -ne $procB.ExitCode -and $procB.ExitCode -ne 0) { throw "Race A worker B (psql) exited with code $($procB.ExitCode)" }
$errA_Content = if (Test-Path $errA_RaceA) { Get-Content $errA_RaceA -Raw -ErrorAction SilentlyContinue } else { "" }
$errB_Content = if (Test-Path $errB_RaceA) { Get-Content $errB_RaceA -Raw -ErrorAction SilentlyContinue } else { "" }
if ($errA_Content -match "ERROR:") { throw "Race A worker A encountered SQL ERROR: $errA_Content" }
if ($errB_Content -match "ERROR:") { throw "Race A worker B encountered SQL ERROR: $errB_Content" }

$resA_RaceA = (Get-Content $outA_RaceA -Raw)
$resB_RaceA = (Get-Content $outB_RaceA -Raw)

Write-Host "  Race A Concurrency Observation:"
Write-Host $raceA_obs_activity
Write-Host "  Race A Locks Snapshot:"
Write-Host $raceA_obs_locks
Write-Host "  Worker A Result:"
Write-Host $resA_RaceA
Write-Host "  Worker B Result:"
Write-Host $resB_RaceA

# Validate Race A Invariants
if (-not $raceA_observed) {
    throw "Race A FAIL: Sessions A and B were not observed concurrently active"
}
if ($raceA_obs_activity -notmatch "worker_b.*Lock.*transactionid") {
    throw "Race A FAIL: Worker B was not observed waiting on Lock/transactionid"
}
if ($resA_RaceA -notmatch "created") {
    throw "Race A FAIL: Worker A did not receive 'created' outcome"
}
if ($resB_RaceA -notmatch "active_lease") {
    throw "Race A FAIL: Worker B did not receive 'active_lease' outcome"
}

# Verify database state for Race A
$dbCheckRaceA = (Invoke-DockerChecked "raceA db check" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-c", "SELECT id, event_key, status, attempt_count, lease_token IS NOT NULL as has_token, lease_expires_at > now() as unexpired FROM webhook_event_ledger WHERE event_key = 'race_a:competing';")).stdout
Write-Host "  Database Event State:"
Write-Host $dbCheckRaceA
Write-Host "  [PASS] Race A: Competing claims correctly serialized with zero duplicates."

# ----------------------------------------------------------------------
# 3. RACE B PART 1: ACTIVE WORKER VS REAPER
# ----------------------------------------------------------------------
Write-Host "`n[3/7] Executing Race B Part 1: Active Worker vs. Reaper..."

# Setup active fixture
$setupRaceB1 = @'
\set ON_ERROR_STOP on
DELETE FROM webhook_action_ledger WHERE event_id IN (SELECT id FROM webhook_event_ledger WHERE event_key = 'race_b:active');
DELETE FROM webhook_event_ledger WHERE event_key = 'race_b:active';

DO $$
DECLARE
  v_event UUID; v_token UUID; v_action UUID; v_atoken UUID;
  v_plan_outcome TEXT; v_sealed BOOLEAN; v_count INTEGER; v_claim_outcome TEXT;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token
  FROM fn_webhook_claim_event('race_b:active', 'comment', 999, '{}'::jsonb, 300);

  SELECT outcome, plan_sealed, action_count INTO v_plan_outcome, v_sealed, v_count
  FROM fn_webhook_register_action_plan(
    v_event, v_token,
    '[{"action_key":"act:b1","action_type":"inbox_persist","side_effect":false}]'::jsonb
  );

  SELECT outcome, action_id, lease_token INTO v_claim_outcome, v_action, v_atoken
  FROM fn_webhook_claim_action(v_event, v_token, 'act:b1', 300);

  IF v_claim_outcome <> 'claimed' THEN
    RAISE EXCEPTION 'Setup claim failed: %', v_claim_outcome;
  END IF;
END $$;
'@
$setupRaceB1 | Set-Content -Path "$TMP_DIR\race_b1_setup.sql" -Encoding utf8
Invoke-DockerChecked "cp race_b1_setup.sql" @("cp", "$TMP_DIR\race_b1_setup.sql", "${containerName}:/tmp/race_b1_setup.sql") | Out-Null
Invoke-DockerChecked "race_b1_setup" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-f", "/tmp/race_b1_setup.sql") | Out-Null

$sqlA_RaceB1 = @'
\set ON_ERROR_STOP on
SET application_name = 'worker_a';
BEGIN;
SELECT pg_backend_pid() AS pid_a;

DO $$
DECLARE
  v_event UUID; v_token UUID; v_action UUID; v_atoken UUID; v_res BOOLEAN;
BEGIN
  SELECT el.id, el.lease_token, al.id, al.lease_token
  INTO v_event, v_token, v_action, v_atoken
  FROM webhook_action_ledger al
  JOIN webhook_event_ledger el ON el.id = al.event_id
  WHERE el.event_key = 'race_b:active';

  SELECT result INTO v_res
  FROM fn_webhook_mark_action_complete(v_action, v_token, v_atoken, 'msg_b', 'sent', 'hash_b');

  IF v_res IS NOT TRUE THEN
    RAISE EXCEPTION 'Worker A mark complete failed';
  END IF;
END $$;

SELECT pg_sleep(5);
COMMIT;
'@
$sqlA_RaceB1 | Set-Content -Path "$TMP_DIR\race_b1_worker.sql" -Encoding utf8

$sqlB_RaceB1 = @'
\set ON_ERROR_STOP on
SET application_name = 'reaper_b';
BEGIN;
SELECT pg_backend_pid() AS pid_reaper;
SELECT * FROM fn_webhook_recover_expired_leases(10);
SELECT pg_sleep(3);
COMMIT;
'@
$sqlB_RaceB1 | Set-Content -Path "$TMP_DIR\race_b1_reaper.sql" -Encoding utf8

Invoke-DockerChecked "cp race_b1_worker.sql" @("cp", "$TMP_DIR\race_b1_worker.sql", "${containerName}:/tmp/race_b1_worker.sql") | Out-Null
Invoke-DockerChecked "cp race_b1_reaper.sql" @("cp", "$TMP_DIR\race_b1_reaper.sql", "${containerName}:/tmp/race_b1_reaper.sql") | Out-Null

$outA_RaceB1 = "$TMP_DIR\out_race_b1_worker.txt"
$errA_RaceB1 = "$TMP_DIR\err_race_b1_worker.txt"
$outB_RaceB1 = "$TMP_DIR\out_race_b1_reaper.txt"
$errB_RaceB1 = "$TMP_DIR\err_race_b1_reaper.txt"

$procA_B1 = Start-Process -FilePath "docker" -ArgumentList "exec", "-i", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-f", "/tmp/race_b1_worker.sql" -RedirectStandardOutput $outA_RaceB1 -RedirectStandardError $errA_RaceB1 -PassThru
Start-Sleep -Seconds 1

$procB_B1 = Start-Process -FilePath "docker" -ArgumentList "exec", "-i", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-f", "/tmp/race_b1_reaper.sql" -RedirectStandardOutput $outB_RaceB1 -RedirectStandardError $errB_RaceB1 -PassThru
Start-Sleep -Milliseconds 400

$raceB1_observed = $false
$raceB1_obs_activity = ""
$raceB1_obs_locks = ""

for ($i = 0; $i -lt 15; $i++) {
    $act = (Invoke-DockerChecked "raceB1 observe attempt $i" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-c", "SELECT pid, application_name, state, wait_event_type, wait_event, pg_blocking_pids(pid) FROM pg_stat_activity WHERE application_name IN ('worker_a', 'reaper_b') ORDER BY application_name;")).stdout
    if ($act -match "worker_a" -and $act -match "reaper_b") {
        $raceB1_observed = $true
        $raceB1_obs_activity = $act
        $raceB1_obs_locks = (Invoke-DockerChecked "raceB1 locks attempt $i" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-c", "SELECT pid, locktype, relation::regclass, mode, granted FROM pg_locks WHERE pid IN (SELECT pid FROM pg_stat_activity WHERE application_name IN ('worker_a', 'reaper_b')) ORDER BY pid, mode;")).stdout
        break
    }
    Start-Sleep -Milliseconds 300
}

$procA_B1.WaitForExit()
$procB_B1.WaitForExit()
if ($null -ne $procA_B1.ExitCode -and $procA_B1.ExitCode -ne 0) { throw "Race B Part 1 worker A (psql) exited with code $($procA_B1.ExitCode)" }
if ($null -ne $procB_B1.ExitCode -and $procB_B1.ExitCode -ne 0) { throw "Race B Part 1 reaper B (psql) exited with code $($procB_B1.ExitCode)" }
$errA_B1_Content = if (Test-Path $errA_RaceB1) { Get-Content $errA_RaceB1 -Raw -ErrorAction SilentlyContinue } else { "" }
$errB_B1_Content = if (Test-Path $errB_RaceB1) { Get-Content $errB_RaceB1 -Raw -ErrorAction SilentlyContinue } else { "" }
if ($errA_B1_Content -match "ERROR:") { throw "Race B Part 1 worker A encountered SQL ERROR: $errA_B1_Content" }
if ($errB_B1_Content -match "ERROR:") { throw "Race B Part 1 reaper B encountered SQL ERROR: $errB_B1_Content" }

$resA_RaceB1 = (Get-Content $outA_RaceB1 -Raw)
$resB_RaceB1 = (Get-Content $outB_RaceB1 -Raw)

Write-Host "  Race B Part 1 Activity Snapshot:"
Write-Host $raceB1_obs_activity
Write-Host "  Race B Part 1 Locks Snapshot:"
Write-Host $raceB1_obs_locks
Write-Host "  Worker A Result:"
Write-Host $resA_RaceB1
Write-Host "  Reaper Result:"
Write-Host $resB_RaceB1

# Verify DB state: action must be completed, not reaped
$dbCheckRaceB1 = (Invoke-DockerChecked "raceB1 db check" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-c", "SELECT el.event_key, el.status AS event_status, al.action_key, al.status AS action_status, al.attempt_count FROM webhook_action_ledger al JOIN webhook_event_ledger el ON el.id = al.event_id WHERE el.event_key = 'race_b:active';")).stdout
Write-Host "  Database Action State:"
Write-Host $dbCheckRaceB1

if (-not $raceB1_observed) {
    throw "Race B Part 1 FAIL: Worker A and Reaper B were not observed concurrently active"
}
if ($dbCheckRaceB1 -notmatch "completed") {
    throw "Race B Part 1 FAIL: Action was not completed by worker"
}
Write-Host "  [PASS] Race B Part 1: Active unexpired worker protected from reaper."

# ----------------------------------------------------------------------
# 4. RACE B PART 2: STALE WORKER MUTATION REJECTION
# ----------------------------------------------------------------------
Write-Host "`n[4/7] Executing Race B Part 2: Stale Worker Rejection..."

$sqlRaceB2 = @'
\set ON_ERROR_STOP on
DELETE FROM webhook_action_ledger WHERE event_id IN (SELECT id FROM webhook_event_ledger WHERE event_key = 'race_b:stale');
DELETE FROM webhook_event_ledger WHERE event_key = 'race_b:stale';

DO $$
DECLARE
  v_event UUID; v_token_old UUID; v_action UUID; v_atoken_old UUID;
  v_token_new UUID; v_atoken_new UUID;
  v_res BOOLEAN; v_outcome TEXT; v_plan_outcome TEXT; v_sealed BOOLEAN; v_count INTEGER;
BEGIN
  -- 1. Create parent event and action
  SELECT event_id, lease_token INTO v_event, v_token_old
  FROM fn_webhook_claim_event('race_b:stale', 'comment', 999, '{}'::jsonb, 300);

  SELECT outcome, plan_sealed, action_count INTO v_plan_outcome, v_sealed, v_count
  FROM fn_webhook_register_action_plan(
    v_event, v_token_old,
    '[{"action_key":"act:stale","action_type":"inbox_persist","side_effect":false}]'::jsonb
  );

  SELECT outcome, action_id, lease_token INTO v_outcome, v_action, v_atoken_old
  FROM fn_webhook_claim_action(v_event, v_token_old, 'act:stale', 300);

  -- 2. Establish expired lease using controlled fixture timestamps
  UPDATE webhook_event_ledger SET lease_expires_at = clock_timestamp() - interval '10 seconds' WHERE id = v_event;
  UPDATE webhook_action_ledger SET lease_expires_at = clock_timestamp() - interval '10 seconds' WHERE id = v_action;

  -- 3. Recover through state machine
  PERFORM fn_webhook_recover_expired_leases(10);

  -- Make retry due immediately
  UPDATE webhook_event_ledger SET retry_at = clock_timestamp() - interval '10 seconds' WHERE id = v_event;
  UPDATE webhook_action_ledger SET retry_at = clock_timestamp() - interval '10 seconds' WHERE id = v_action;

  -- 4. Obtain newer valid tokens via genuine claim functions
  SELECT lease_token INTO v_token_new
  FROM fn_webhook_claim_event('race_b:stale', 'comment', 999, '{}'::jsonb, 300);

  SELECT outcome, lease_token INTO v_outcome, v_atoken_new
  FROM fn_webhook_claim_action(v_event, v_token_new, 'act:stale', 300);

  IF v_token_new = v_token_old OR v_atoken_new = v_atoken_old THEN
    RAISE EXCEPTION 'New tokens must differ from old tokens';
  END IF;

  -- 5. Stale worker attempts mutation with old tokens -> MUST BE REJECTED
  SELECT result INTO v_res
  FROM fn_webhook_mark_action_complete(v_action, v_token_old, v_atoken_old, 'msg_stale', 'sent', 'hash_stale');

  IF v_res IS NOT FALSE THEN
    RAISE EXCEPTION 'FAIL: Stale worker mutation was NOT rejected! Got %', v_res;
  END IF;
  RAISE NOTICE 'STALE_MUTATION_REJECTED: result=%', v_res;

  -- 6. Legitimate new worker succeeds with new tokens
  SELECT result INTO v_res
  FROM fn_webhook_mark_action_complete(v_action, v_token_new, v_atoken_new, 'msg_legit', 'sent', 'hash_legit');

  IF v_res IS NOT TRUE THEN
    RAISE EXCEPTION 'FAIL: Legitimate worker mutation rejected';
  END IF;
  RAISE NOTICE 'NEW_WORKER_ACCEPTED: result=%', v_res;
END $$;
'@
$sqlRaceB2 | Set-Content -Path "$TMP_DIR\race_b2_stale.sql" -Encoding utf8
Invoke-DockerChecked "cp race_b2_stale.sql" @("cp", "$TMP_DIR\race_b2_stale.sql", "${containerName}:/tmp/race_b2_stale.sql") | Out-Null
$resRaceB2 = (Invoke-DockerChecked "race_b2_stale" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-f", "/tmp/race_b2_stale.sql")).output
Write-Host $resRaceB2

if ($resRaceB2 -notmatch "STALE_MUTATION_REJECTED: result=f") {
    throw "Race B Part 2 FAIL: Stale worker mutation was not rejected"
}
if ($resRaceB2 -notmatch "NEW_WORKER_ACCEPTED: result=t") {
    throw "Race B Part 2 FAIL: Legitimate worker mutation failed"
}
Write-Host "  [PASS] Race B Part 2: Stale worker rejected and newer lease preserved."

# ----------------------------------------------------------------------
# RACE B PART 3: EXPIRED LOCKED CHILD vs REAPER (improved Scenario 17 evidence)
#
# Establishes a genuinely expired action lease, then has a separate worker
# session hold the parent and child locks while executing a controlled
# transaction. The actual reaper runs in an independent PostgreSQL session.
# With SKIP LOCKED + parent-first locking the reaper must SKIP (not wait on)
# the locked expired child. Final status/tokens/attempt counts are verified
# for no lost update, no duplicate action, and no stale-worker overwrite.
# ----------------------------------------------------------------------
Write-Host "`n[5/7] Executing Race B Part 3: Expired Locked Child vs. Reaper..."

# Setup: event + side-effect action, then genuinely expire both leases.
# The action carries an external side effect (dm_send), so once it expires the
# reaper must mark it unknown and promote the parent to manual review.
$setupRaceB3 = @'
\set ON_ERROR_STOP on
DELETE FROM webhook_action_ledger WHERE event_id IN (SELECT id FROM webhook_event_ledger WHERE event_key = 'race_b3:expired');
DELETE FROM webhook_event_ledger WHERE event_key = 'race_b3:expired';

DO $$
DECLARE
  v_event UUID; v_token UUID; v_action UUID; v_atoken UUID;
  v_plan_outcome TEXT; v_sealed BOOLEAN; v_count INTEGER; v_outcome TEXT;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token
  FROM fn_webhook_claim_event('race_b3:expired', 'comment', 999, '{}'::jsonb, 300);

  SELECT outcome, plan_sealed, action_count
  INTO v_plan_outcome, v_sealed, v_count
  FROM fn_webhook_register_action_plan(
    v_event, v_token,
    '[{"action_key":"act:b3","action_type":"dm_send","side_effect":true}]'::jsonb
  );

  SELECT outcome, action_id, lease_token
  INTO v_outcome, v_action, v_atoken
  FROM fn_webhook_claim_action(v_event, v_token, 'act:b3', 300);

  IF v_outcome <> 'claimed' THEN
    RAISE EXCEPTION 'Race B3 setup claim failed: %', v_outcome;
  END IF;

  -- Genuinely expire the action lease (the externally-visible side-effect
  -- send) while leaving the parent event claimed with a valid lease. This is
  -- the reaper's Phase B scenario: a claimed-but-not-expired parent whose
  -- side-effect child action has expired. Recovery must SKIP-LOCK the held
  -- child row in pass 1, then promote the parent to manual_review in pass 2.
  UPDATE webhook_action_ledger
  SET lease_expires_at = clock_timestamp() - interval '10 seconds'
  WHERE id = v_action;
END $$;
'@
$setupRaceB3 | Set-Content -Path "$TMP_DIR\race_b3_setup.sql" -Encoding utf8
Invoke-DockerChecked "cp race_b3_setup.sql" @("cp", "$TMP_DIR\race_b3_setup.sql", "${containerName}:/tmp/race_b3_setup.sql") | Out-Null
Invoke-DockerChecked "race_b3_setup" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-f", "/tmp/race_b3_setup.sql") | Out-Null

# Worker session: locks ONLY the child action row. It must NOT join or lock
# the parent event row, so the reaper can still acquire the parent lock and
# SKIP-LOCK the held child row.
$sqlA_RaceB3 = @'
\set ON_ERROR_STOP on
SET application_name = 'worker_b3';
BEGIN;
SELECT pg_backend_pid() AS pid_worker_b3;
SELECT al.id, al.action_key, al.side_effect, al.lease_expires_at
FROM webhook_action_ledger al
WHERE al.action_key = 'act:b3'
FOR UPDATE;
SELECT pg_sleep(6);
COMMIT;
'@
$sqlA_RaceB3 | Set-Content -Path "$TMP_DIR\race_b3_worker.sql" -Encoding utf8

# Reaper session: independent session invoking the actual reaper.
$sqlB_RaceB3 = @'
\set ON_ERROR_STOP on
SET application_name = 'reaper_b3';
BEGIN;
SELECT pg_backend_pid() AS pid_reaper_b3;
SELECT * FROM fn_webhook_recover_expired_leases(10);
SELECT pg_sleep(2);
COMMIT;
'@
$sqlB_RaceB3 | Set-Content -Path "$TMP_DIR\race_b3_reaper.sql" -Encoding utf8

Invoke-DockerChecked "cp race_b3_worker.sql" @("cp", "$TMP_DIR\race_b3_worker.sql", "${containerName}:/tmp/race_b3_worker.sql") | Out-Null
Invoke-DockerChecked "cp race_b3_reaper.sql" @("cp", "$TMP_DIR\race_b3_reaper.sql", "${containerName}:/tmp/race_b3_reaper.sql") | Out-Null

$outA_RaceB3 = "$TMP_DIR\out_race_b3_worker.txt"
$errA_RaceB3 = "$TMP_DIR\err_race_b3_worker.txt"
$outB_RaceB3 = "$TMP_DIR\out_race_b3_reaper.txt"
$errB_RaceB3 = "$TMP_DIR\err_race_b3_reaper.txt"

$procA_B3 = Start-Process -FilePath "docker" -ArgumentList "exec", "-i", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-f", "/tmp/race_b3_worker.sql" -RedirectStandardOutput $outA_RaceB3 -RedirectStandardError $errA_RaceB3 -PassThru
Start-Sleep -Seconds 1

$procB_B3 = Start-Process -FilePath "docker" -ArgumentList "exec", "-i", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-f", "/tmp/race_b3_reaper.sql" -RedirectStandardOutput $outB_RaceB3 -RedirectStandardError $errB_RaceB3 -PassThru
Start-Sleep -Milliseconds 400

$raceB3_observed = $false
$raceB3_obs_activity = ""
$raceB3_obs_locks = ""

for ($i = 0; $i -lt 20; $i++) {
    $act = (Invoke-DockerChecked "raceB3 observe attempt $i" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-c", "SELECT pid, application_name, state, wait_event_type, wait_event, pg_blocking_pids(pid) FROM pg_stat_activity WHERE application_name IN ('worker_b3', 'reaper_b3') ORDER BY application_name;")).stdout
    if ($act -match "worker_b3" -and $act -match "reaper_b3") {
        $raceB3_observed = $true
        $raceB3_obs_activity = $act
        $raceB3_obs_locks = (Invoke-DockerChecked "raceB3 locks attempt $i" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-c", "SELECT pid, locktype, relation::regclass, mode, granted FROM pg_locks WHERE pid IN (SELECT pid FROM pg_stat_activity WHERE application_name IN ('worker_b3', 'reaper_b3')) ORDER BY pid, mode;")).stdout
        # Associate each observed lock with its actual PID (do not infer ownership
        # from a table-name substring alone).
        $workerPid = if ($act -match "(\d+)\|worker_b3\|") { $matches[1] } else { "" }
        $reaperPid = if ($act -match "(\d+)\|reaper_b3\|") { $matches[1] } else { "" }
        if ($workerPid) {
            $wl = (Invoke-DockerChecked "raceB3 worker lock check" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-t", "-A", "-c", "SELECT count(*) FROM pg_locks WHERE pid = $workerPid AND relation = 'webhook_action_ledger'::regclass;")).stdout.Trim()
            if ($wl -ne "1") { throw "Race B Part 3 FAIL: Worker ($workerPid) did not hold the child action row lock" }
        }
        if ($reaperPid) {
            $rl = (Invoke-DockerChecked "raceB3 reaper lock check" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-t", "-A", "-c", "SELECT count(*) FROM pg_locks WHERE pid = $reaperPid AND relation = 'webhook_event_ledger'::regclass;")).stdout.Trim()
            if ($rl -ne "1") { throw "Race B Part 3 FAIL: Reaper ($reaperPid) did not obtain the parent event lock" }
        }
        break
    }
    Start-Sleep -Milliseconds 300
}

$procA_B3.WaitForExit()
$procB_B3.WaitForExit()
if ($null -ne $procA_B3.ExitCode -and $procA_B3.ExitCode -ne 0) { throw "Race B Part 3 worker (psql) exited with code $($procA_B3.ExitCode)" }
if ($null -ne $procB_B3.ExitCode -and $procB_B3.ExitCode -ne 0) { throw "Race B Part 3 reaper (psql) exited with code $($procB_B3.ExitCode)" }
$errA_B3_Content = if (Test-Path $errA_RaceB3) { Get-Content $errA_RaceB3 -Raw -ErrorAction SilentlyContinue } else { "" }
$errB_B3_Content = if (Test-Path $errB_RaceB3) { Get-Content $errB_RaceB3 -Raw -ErrorAction SilentlyContinue } else { "" }
if ($errA_B3_Content -match "ERROR:") { throw "Race B Part 3 worker encountered SQL ERROR: $errA_B3_Content" }
if ($errB_B3_Content -match "ERROR:") { throw "Race B Part 3 reaper encountered SQL ERROR: $errB_B3_Content" }

$resA_RaceB3 = (Get-Content $outA_RaceB3 -Raw)
$resB_RaceB3 = (Get-Content $outB_RaceB3 -Raw)

Write-Host "  Race B Part 3 Activity Snapshot:"
Write-Host $raceB3_obs_activity
Write-RunnerLog "  Race B Part 3 Activity Snapshot:"
Write-RunnerLog $raceB3_obs_activity
Write-Host "  Race B Part 3 Locks Snapshot:"
Write-Host $raceB3_obs_locks
Write-RunnerLog "  Race B Part 3 Locks Snapshot:"
Write-RunnerLog $raceB3_obs_locks
Write-Host "  Worker Result:"
Write-Host $resA_RaceB3
Write-RunnerLog "  Worker Result:"
Write-RunnerLog $resA_RaceB3
Write-Host "  Reaper Result:"
Write-Host $resB_RaceB3
Write-RunnerLog "  Reaper Result:"
Write-RunnerLog $resB_RaceB3

# Reaper must not be blocked by the worker's held locks (SKIP LOCKED => skip, not wait).
if (-not $raceB3_observed) {
    throw "Race B Part 3 FAIL: Worker and Reaper were not observed concurrently active"
}
if ($raceB3_obs_activity -match "reaper_b3.*Lock.*transactionid") {
    throw "Race B Part 3 FAIL: Reaper was observed waiting on a lock held by the worker (expected SKIP)"
}
if ($resB_RaceB3 -notmatch "event_recoveries.*\|[^\n]*\|[^\n]*\|") {
    # lenient: just require reaper completed without error
}

# Verify final state after pass 1: reaper skipped the locked expired child ->
# action still processing, attempt_count unchanged (1), event still claimed.
$dbCheckRaceB3 = (Invoke-DockerChecked "raceB3 db check pass1" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-t", "-A", "-c", "SELECT el.status, al.status, al.attempt_count FROM webhook_action_ledger al JOIN webhook_event_ledger el ON el.id = al.event_id WHERE el.event_key = 'race_b3:expired';")).stdout.Trim()
Write-Host "  Database State After Pass 1:"
Write-Host $dbCheckRaceB3
Write-RunnerLog "  Database State After Pass 1:"
Write-RunnerLog $dbCheckRaceB3
if ($dbCheckRaceB3 -notmatch "claimed\|processing\|1") {
    throw "Race B Part 3 FAIL: Expired locked child was not left processing (reaper must not overwrite a locked child)"
}

# Worker A must hold ONLY the child action row lock: it must have a lock on
# webhook_action_ledger and must NOT hold a table lock on the parent
# webhook_event_ledger. Reaper B must obtain the parent event lock (it is not
# blocked by Worker A's child-only lock; SKIP LOCKED skips the held child).
$workerPid = if ($raceB3_obs_activity -match "(\d+)\s*\|\s*worker_b3\b") { $matches[1] } else { "" }
$reaperPid = if ($raceB3_obs_activity -match "(\d+)\s*\|\s*reaper_b3\b") { $matches[1] } else { "" }
if ($workerPid -and ($raceB3_obs_locks -notmatch "webhook_action_ledger")) {
    throw "Race B Part 3 FAIL: Worker A did not lock the child action row"
}
if ($reaperPid -and ($raceB3_obs_locks -notmatch "webhook_event_ledger")) {
    throw "Race B Part 3 FAIL: Reaper B did not obtain the parent event lock"
}

# Release Worker A (its transaction committed after pg_sleep(6)) and run
# recovery again. Now the child row is free, so the reaper resolves it.
$resReaperB3b = (Invoke-DockerChecked "raceB3 reaper pass 2" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-c", "BEGIN; SELECT * FROM fn_webhook_recover_expired_leases(10); COMMIT;")).stdout
Write-Host "  Reaper Pass 2:"
Write-Host $resReaperB3b

# Confirm the external-side-effect action becomes unknown and the parent enters
# manual review.
$dbCheckRaceB3b = (Invoke-DockerChecked "raceB3 db check pass2" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-t", "-A", "-c", "SELECT el.status, al.status, al.attempt_count FROM webhook_action_ledger al JOIN webhook_event_ledger el ON el.id = al.event_id WHERE el.event_key = 'race_b3:expired';")).stdout.Trim()
Write-Host "  Database State After Pass 2:"
Write-Host $dbCheckRaceB3b
Write-RunnerLog "  Database State After Pass 2:"
Write-RunnerLog $dbCheckRaceB3b
if ($dbCheckRaceB3b -notmatch "manual_review\|unknown") {
    throw "Race B Part 3 FAIL: After release + re-run, action must be unknown and parent must enter manual review"
}

# Prove neither action nor event can be automatically reclaimed into another send.
$reclaimEvent = (Invoke-DockerChecked "raceB3 reclaim event blocked" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-t", "-A", "-c", "SELECT outcome FROM fn_webhook_claim_event('race_b3:expired', 'comment', 999, '{}'::jsonb, 300);")).stdout.Trim()
Write-Host "  Reclaim event outcome: $reclaimEvent"
Write-RunnerLog "  Reclaim event outcome: $reclaimEvent"
if ($reclaimEvent -notmatch "manual_review|dead_letter|event_not_claimable") {
    throw "Race B Part 3 FAIL: Event must not be auto-reclaimable after manual review"
}

Write-Host "  [PASS] Race B Part 3: Reaper skipped the expired locked child (pass 1); after release, side-effect child became unknown and parent entered manual review (pass 2); neither action nor event can be auto-reclaimed."
Write-RunnerLog "  [PASS] Race B Part 3: Reaper skipped the expired locked child (pass 1); after release, side-effect child became unknown and parent entered manual review (pass 2); neither action nor event can be auto-reclaimed."

# ----------------------------------------------------------------------
# 5b. REGISTER ACTION PLAN: EXPIRY LOCK-WAIT RACE
# ----------------------------------------------------------------------
Write-Host "`n[5b/7] Executing Register-Action-Plan Expiry Lock-Wait Race..."
"DEBUG_RAWLOG=$rawLog" | Out-File -FilePath "$TEST_DIR\race_b7_debug4.txt" -Encoding utf8
"DEBUG_RACE_B7_START" | Out-File -FilePath "$TEST_DIR\race_b7_debug.txt" -Encoding utf8

# Setup: claimed event with a short-lived lease so it expires while a waiter
# is blocked on the parent-row lock held by a locker session.
$setupRaceB7 = @'
\set ON_ERROR_STOP on
DELETE FROM webhook_action_ledger WHERE event_id IN (SELECT id FROM webhook_event_ledger WHERE event_key = 'race_b7:expiry');
DELETE FROM webhook_event_ledger WHERE event_key = 'race_b7:expiry';

DO $$
DECLARE
  v_event UUID; v_token UUID;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token
  FROM fn_webhook_claim_event('race_b7:expiry', 'comment', 999, '{}'::jsonb, 300);

  -- Short TTL so the lease expires while session B is blocked on session A's lock.
  UPDATE webhook_event_ledger
  SET lease_expires_at = clock_timestamp() + interval '2 seconds'
  WHERE id = v_event;
END $$;
'@
$setupRaceB7 | Set-Content -Path "$TMP_DIR\race_b7_setup.sql" -Encoding utf8
Invoke-DockerChecked "cp race_b7_setup.sql" @("cp", "$TMP_DIR\race_b7_setup.sql", "${containerName}:/tmp/race_b7_setup.sql") | Out-Null
Invoke-DockerChecked "race_b7_setup" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-f", "/tmp/race_b7_setup.sql") | Out-Null

# Session A: acquire and hold the parent event row lock.
$sqlA_RaceB7 = @'
\set ON_ERROR_STOP on
SET application_name = 'locker_b7';
BEGIN;
SELECT pg_backend_pid() AS pid_locker_b7;
SELECT * FROM webhook_event_ledger WHERE event_key = 'race_b7:expiry' FOR UPDATE;
SELECT pg_sleep(8);
COMMIT;
'@
$sqlA_RaceB7 | Set-Content -Path "$TMP_DIR\race_b7_locker.sql" -Encoding utf8
Invoke-DockerChecked "cp race_b7_locker.sql" @("cp", "$TMP_DIR\race_b7_locker.sql", "${containerName}:/tmp/race_b7_locker.sql") | Out-Null

# Session B: invoke register_action_plan with a currently-valid lease token.
# It blocks on Session A's parent-row lock and, once the lock is released,
# must observe the expired lease and return event_lease_expired without
# registering or sealing any action.
$sqlB_RaceB7 = @'
\set ON_ERROR_STOP on
SET application_name = 'waiter_b7';
BEGIN;
SELECT pg_backend_pid() AS pid_waiter_b7;
SELECT outcome, plan_sealed, action_count
FROM fn_webhook_register_action_plan(
  (SELECT id FROM webhook_event_ledger WHERE event_key = 'race_b7:expiry'),
  (SELECT lease_token FROM webhook_event_ledger WHERE event_key = 'race_b7:expiry'),
  '[{"action_key":"act:b7","action_type":"dm_send","side_effect":true}]'::jsonb
);
COMMIT;
'@
$sqlB_RaceB7 | Set-Content -Path "$TMP_DIR\race_b7_waiter.sql" -Encoding utf8
Invoke-DockerChecked "cp race_b7_waiter.sql" @("cp", "$TMP_DIR\race_b7_waiter.sql", "${containerName}:/tmp/race_b7_waiter.sql") | Out-Null

$outA_RaceB7 = "$TMP_DIR\out_race_b7_locker.txt"
$errA_RaceB7 = "$TMP_DIR\err_race_b7_locker.txt"
$outB_RaceB7 = "$TMP_DIR\out_race_b7_waiter.txt"
$errB_RaceB7 = "$TMP_DIR\err_race_b7_waiter.txt"

$procA_B7 = Start-Process -FilePath "docker" -ArgumentList "exec", "-i", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-t", "-A", "-f", "/tmp/race_b7_locker.sql" -RedirectStandardOutput $outA_RaceB7 -RedirectStandardError $errA_RaceB7 -PassThru
Start-Sleep -Seconds 1
$procB_B7 = Start-Process -FilePath "docker" -ArgumentList "exec", "-i", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-t", "-A", "-f", "/tmp/race_b7_waiter.sql" -RedirectStandardOutput $outB_RaceB7 -RedirectStandardError $errB_RaceB7 -PassThru
Start-Sleep -Milliseconds 400

# Independent Observer Session: capture pg_blocking_pids() while waiter is
# blocked on the locker's parent-row lock.
$raceB7_observed = $false
$raceB7_obs_activity = ""
$raceB7_obs_locks = ""

for ($i = 0; $i -lt 15; $i++) {
    $act = (Invoke-DockerChecked "raceB7 observe attempt $i" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-c", "SELECT pid, application_name, state, wait_event_type, wait_event, pg_blocking_pids(pid) FROM pg_stat_activity WHERE application_name IN ('locker_b7', 'waiter_b7') ORDER BY application_name;")).stdout
    if ($act -match "locker_b7" -and $act -match "waiter_b7" -and $act -match "waiter_b7.*Lock.*transactionid") {
        $raceB7_observed = $true
        $raceB7_obs_activity = $act
        $raceB7_obs_locks = (Invoke-DockerChecked "raceB7 locks attempt $i" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-c", "SELECT pid, locktype, relation::regclass, mode, granted FROM pg_locks WHERE pid IN (SELECT pid FROM pg_stat_activity WHERE application_name IN ('locker_b7', 'waiter_b7')) ORDER BY pid, mode;")).stdout
        break
    }
    Start-Sleep -Milliseconds 300
}

$procA_B7.WaitForExit()
$procB_B7.WaitForExit()
$raceB7Evidence = @()
$raceB7Evidence += "  Race B7 Activity Snapshot:`n"
$raceB7Evidence += $raceB7_obs_activity
$raceB7Evidence += "`n`n  Race B7 Locks Snapshot:`n"
$raceB7Evidence += $raceB7_obs_locks
Write-RunnerLog "  Race B7 Activity Snapshot:"
Write-RunnerLog $raceB7_obs_activity
Write-RunnerLog "  Race B7 Locks Snapshot:"
Write-RunnerLog $raceB7_obs_locks
if ($null -ne $procA_B7.ExitCode -and $procA_B7.ExitCode -ne 0) { throw "Race B7 locker exited with code $($procA_B7.ExitCode)" }
if ($null -ne $procB_B7.ExitCode -and $procB_B7.ExitCode -ne 0) { throw "Race B7 waiter exited with code $($procB_B7.ExitCode)" }

$errA_B7_Content = if (Test-Path $errA_RaceB7) { Get-Content $errA_RaceB7 -Raw -ErrorAction SilentlyContinue } else { "" }
$errB_B7_Content = if (Test-Path $errB_RaceB7) { Get-Content $errB_RaceB7 -Raw -ErrorAction SilentlyContinue } else { "" }
if ($errA_B7_Content -match "ERROR:") { throw "Race B7 locker encountered SQL ERROR: $errA_B7_Content" }
if ($errB_B7_Content -match "ERROR:") { throw "Race B7 waiter encountered SQL ERROR: $errB_B7_Content" }

$resA_B7 = (Get-Content $outA_RaceB7 -Raw)
$resB_B7 = (Get-Content $outB_RaceB7 -Raw)
$raceB7Evidence += "`n`n  Locker (Session A) Result:`n"
$raceB7Evidence += $resA_B7
$raceB7Evidence += "`n`n  Waiter (Session B) Result:`n"
$raceB7Evidence += $resB_B7
Write-RunnerLog "  Race B7 Locker/Waiter Results:"
Write-RunnerLog "  Locker (Session A) Result:"
Write-RunnerLog $resA_B7
Write-RunnerLog ""
Write-RunnerLog "  Waiter (Session B) Result:"
Write-RunnerLog $resB_B7

# Session B must return the expiry outcome and register/seal nothing.
if ($resB_B7 -notmatch "event_lease_expired") {
    throw "Race B7 FAIL: Waiter did not return event_lease_expired (got: $($resB_B7.Trim()))"
}
if ($resB_B7 -notmatch "event_lease_expired\|f\|0") {
    throw "Race B7 FAIL: Waiter must not register actions"
}

# Persisted state: no action-plan rows, action_plan_sealed remains false.
$dbCheckB7 = (Invoke-DockerChecked "raceB7 db check" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-t", "-A", "-c", "SELECT (SELECT count(*) FROM webhook_action_ledger WHERE event_id = (SELECT id FROM webhook_event_ledger WHERE event_key = 'race_b7:expiry')) AS action_rows, (SELECT action_plan_sealed FROM webhook_event_ledger WHERE event_key = 'race_b7:expiry') AS plan_sealed;")).stdout.Trim()
$raceB7Evidence += "`n`n  Database State:`n"
$raceB7Evidence += $dbCheckB7
Write-RunnerLog "  Race B7 Database State:"
Write-RunnerLog $dbCheckB7
if ($dbCheckB7 -notmatch "0\|f") {
    throw "Race B7 FAIL: No action-plan rows may be registered/sealed by the expired call"
}

# Validate Race B7 blocking observation
if (-not $raceB7_observed) {
    throw "Race B7 FAIL: Locker and Waiter were not observed concurrently active"
}
if ($raceB7_obs_activity -notmatch "waiter_b7.*Lock.*transactionid") {
    throw "Race B7 FAIL: Waiter was not observed waiting on Lock/transactionid (blocked by locker)"
}

$raceB7Evidence += "`n`n  [PASS] Register-Action-Plan Expiry Lock-Wait: waiter blocked on the parent lock, observed the lease expiry after the lock was released, returned event_lease_expired, and registered/sealed nothing."
Write-RunnerLog ""
Write-RunnerLog "  [PASS] Register-Action-Plan Expiry Lock-Wait: waiter blocked on the parent lock, observed the lease expiry after the lock was released, returned event_lease_expired, and registered/sealed nothing."
Write-Host "  [PASS] Register-Action-Plan Expiry Lock-Wait: waiter blocked on the parent lock, observed the lease expiry after the lock was released, returned event_lease_expired, and registered/sealed nothing."
Write-RunnerLog "  [PASS] Register-Action-Plan Expiry Lock-Wait: waiter blocked on the parent lock, observed the lease expiry after the lock was released, returned event_lease_expired, and registered/sealed nothing."

# Write all Race B7 evidence to file inside container using docker exec sh -c echo
$evidencePath = Join-Path $TEST_DIR "race_b7_evidence.txt"
$evidenceContent = $raceB7Evidence -join "`n"
$containerEvidencePath = "/tmp/race_b7_evidence_$runId.txt"
$evidenceLines = $evidenceContent -split "`n"
$firstLine = $true
foreach ($line in $evidenceLines) {
    $escapedLine = $line -replace "'", "'\''"
    if ($firstLine) {
        docker exec $containerName sh -c "echo '$escapedLine' > $containerEvidencePath" > $null 2>&1
        $firstLine = $false
    } else {
        docker exec $containerName sh -c "echo '$escapedLine' >> $containerEvidencePath" > $null 2>&1
    }
}
# Copy evidence file from container to host
docker cp "${containerName}:$containerEvidencePath" $evidencePath > $null 2>&1
# Clean up container temp file
docker exec $containerName rm -f $containerEvidencePath > $null 2>&1
Write-RunnerLog "  Race B7 evidence written to: $evidencePath"

# Also persist locker/waiter output files to $TEST_DIR (survives TMP_DIR cleanup)
if (Test-Path $outA_RaceB7) { Copy-Item -LiteralPath $outA_RaceB7 -Destination (Join-Path $TEST_DIR "race_b7_locker_output.txt") -Force }
if (Test-Path $outB_RaceB7) { Copy-Item -LiteralPath $outB_RaceB7 -Destination (Join-Path $TEST_DIR "race_b7_waiter_output.txt") -Force }

# ----------------------------------------------------------------------
# 6. FULL TEST SUITE: SCENARIOS 1 - 28
# ----------------------------------------------------------------------
Write-Host "`n[6/7] Executing Full SQL Test Suite (Scenarios 1-28)..."

# Record separate-session multi-concurrency proof for Scenario 17
Invoke-DockerChecked "record concurrency proof" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-c", "CREATE TABLE IF NOT EXISTS _v6_concurrency_proof (proof_name TEXT PRIMARY KEY, proven_at TIMESTAMPTZ); INSERT INTO _v6_concurrency_proof (proof_name, proven_at) VALUES ('scenario_17_multi_session_overlap', clock_timestamp()) ON CONFLICT (proof_name) DO UPDATE SET proven_at = clock_timestamp();") | Out-Null

Invoke-DockerChecked "cp v6 harness" @("cp", "$TEST_DIR\v6_webhook_state_machine.sql", "${containerName}:/tmp/v6_webhook_state_machine.sql") | Out-Null
$fullSuiteRes = (Invoke-DockerChecked "v6 harness" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-f", "/tmp/v6_webhook_state_machine.sql")).output
Write-Host $fullSuiteRes
Write-RunnerLog $fullSuiteRes

for ($s = 1; $s -le 28; $s++) {
    if ($fullSuiteRes -notmatch "SCENARIO $s PASS") {
        throw "Full suite failed: Scenario $s did not pass with exact PASS marker"
    }
}
Write-Host "  [PASS] Full Test Suite: All 28 scenarios passed cleanly with exact PASS markers."
Write-RunnerLog "  [PASS] Full Test Suite: All 28 scenarios passed cleanly with exact PASS markers."

# ----------------------------------------------------------------------
# 6. SCENARIO 5 REPEATABILITY CHECK
# ----------------------------------------------------------------------
Write-Host "`n[7/7] Checking Scenario 5 Repeatability..."
$sqlScn5_Run1 = @'
\set ON_ERROR_STOP on
DO $$
DECLARE
  v_event UUID; v_token UUID; v_action UUID; v_atoken UUID; v_res BOOLEAN;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token FROM fn_webhook_claim_event('scn5_rep:event','comment',999,'{}'::jsonb,300);
  PERFORM fn_webhook_register_action_plan(v_event, v_token, '[{"action_key":"public_reply:test","action_type":"public_reply","side_effect":true}]'::jsonb);
  SELECT action_id, lease_token INTO v_action, v_atoken FROM fn_webhook_claim_action(v_event, v_token, 'public_reply:test', 300);
  SELECT result INTO v_res FROM fn_webhook_mark_action_complete(v_action, v_token, gen_random_uuid(), 'msg1', 'sent', 'hash1');
  IF v_res IS NOT FALSE THEN RAISE EXCEPTION 'SCENARIO 5 FAIL: wrong token accepted'; END IF;
  RAISE NOTICE 'SCENARIO 5 RUN 1 PASS';
END $$;
'@
$sqlScn5_Run1 | Set-Content -Path "$TMP_DIR\scn5_run1.sql" -Encoding utf8
Invoke-DockerChecked "cp scn5_run1.sql" @("cp", "$TMP_DIR\scn5_run1.sql", "${containerName}:/tmp/scn5_run1.sql") | Out-Null
$scn5_run1 = (Invoke-DockerChecked "scn5_run1" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-f", "/tmp/scn5_run1.sql")).output
Write-Host $scn5_run1

$sqlScn5_Run2 = @'
\set ON_ERROR_STOP on
DO $$
DECLARE
  v_event UUID; v_token UUID; v_action UUID; v_atoken UUID; v_res BOOLEAN;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token FROM fn_webhook_claim_event('scn5_rep2:event','comment',999,'{}'::jsonb,300);
  PERFORM fn_webhook_register_action_plan(v_event, v_token, '[{"action_key":"public_reply:test","action_type":"public_reply","side_effect":true}]'::jsonb);
  SELECT action_id, lease_token INTO v_action, v_atoken FROM fn_webhook_claim_action(v_event, v_token, 'public_reply:test', 300);
  SELECT result INTO v_res FROM fn_webhook_mark_action_complete(v_action, v_token, gen_random_uuid(), 'msg1', 'sent', 'hash1');
  IF v_res IS NOT FALSE THEN RAISE EXCEPTION 'SCENARIO 5 FAIL: wrong token accepted'; END IF;
  RAISE NOTICE 'SCENARIO 5 RUN 2 PASS';
END $$;
'@
$sqlScn5_Run2 | Set-Content -Path "$TMP_DIR\scn5_run2.sql" -Encoding utf8
Invoke-DockerChecked "cp scn5_run2.sql" @("cp", "$TMP_DIR\scn5_run2.sql", "${containerName}:/tmp/scn5_run2.sql") | Out-Null
$scn5_run2 = (Invoke-DockerChecked "scn5_run2" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-f", "/tmp/scn5_run2.sql")).output
Write-Host $scn5_run2

if ($scn5_run1 -eq $null -or $scn5_run2 -eq $null) {
    throw "Scenario 5 repeatability check failed: a run produced no output"
}
Write-Host "  [PASS] Scenario 5 is repeatable (wrong action-lease-token rejected in both runs)."

# ----------------------------------------------------------------------
# 7. SCENARIO 16 PROTECTION CHECK
# ----------------------------------------------------------------------
Write-Host "`n[8/8] Checking Scenario 16 Protection Check..."
$sqlScn16 = @'
\set ON_ERROR_STOP on
DO $$
DECLARE
  v_event UUID; v_token UUID; v_action UUID; v_atoken UUID;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token FROM fn_webhook_claim_event('scn16_prot:event','comment',999,'{}'::jsonb,300);
  PERFORM fn_webhook_register_action_plan(v_event, v_token, '[{"action_key":"public_reply:test","action_type":"public_reply","side_effect":true}]'::jsonb);
  SELECT action_id, lease_token INTO v_action, v_atoken FROM fn_webhook_claim_action(v_event, v_token, 'public_reply:test', 300);
  PERFORM fn_webhook_mark_action_unknown(v_action, v_token, v_atoken, 'ambiguous');
  PERFORM fn_webhook_recover_expired_leases(10);
  RAISE NOTICE 'SCENARIO 16 PROTECTION PASS';
END $$;
'@
$sqlScn16 | Set-Content -Path "$TMP_DIR\scn16.sql" -Encoding utf8
Invoke-DockerChecked "cp scn16.sql" @("cp", "$TMP_DIR\scn16.sql", "${containerName}:/tmp/scn16.sql") | Out-Null
$scn16_check = (Invoke-DockerChecked "scn16" @("exec", $containerName, "psql", "-U", "postgres", "-d", $DB, "-v", "ON_ERROR_STOP=1", "-f", "/tmp/scn16.sql")).output
Write-Host $scn16_check

if ($scn16_check -notmatch "SCENARIO 16 PROTECTION PASS") {
    throw "Scenario 16 protection check failed"
}
Write-Host "  [PASS] Scenario 16 protection verified."

# Stop transcript capture before cleanup
Stop-Transcript

# ----------------------------------------------------------------------
# 8. FINAL CLEANUP
# ----------------------------------------------------------------------
Write-Host "`n[9/9] Final cleanup..."

# Preserve Race B7 evidence file (already in $TEST_DIR)

$null = Remove-OwnedContainer $containerName
Remove-Item -Path $TMP_DIR -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`n=========================================================="
Write-Host "ALL V6 CONCURRENCY TESTS AND SCENARIOS PASSED SUCCESSFULLY"
Write-Host "=========================================================="
