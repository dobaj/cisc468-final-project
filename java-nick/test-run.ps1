param()

$base  = "e:\github\cisc468-final-project\java-nick"
$jar   = "$base\target\p2p-file-sharing-1.0-SNAPSHOT.jar"
$data  = "$base\data"
$logs  = "$base\test-logs"
New-Item -ItemType Directory -Force -Path $logs | Out-Null

Write-Host "=== P2P Automated Test ===" -ForegroundColor Cyan

# ── Pre-test setup ──────────────────────────────────────────────────────────
# Ensure shared files exist
New-Item -ItemType Directory -Force "$data\Nick1\shared" | Out-Null
New-Item -ItemType Directory -Force "$data\Nick2\shared" | Out-Null
Set-Content "$data\Nick1\shared\secret.txt"  "Top secret file from Nick1. If you're reading this on Nick2 it worked!" -Encoding UTF8
Set-Content "$data\Nick1\shared\hello.txt"   "Hello from Nick1!"  -Encoding UTF8
Set-Content "$data\Nick2\shared\gift.txt"    "A gift from Nick2!" -Encoding UTF8

# Read identity public keys and pre-populate trust stores so no prompt appears
$nick1pub = [System.IO.File]::ReadAllBytes("$data\Nick1\identity.pub")
$nick2pub = [System.IO.File]::ReadAllBytes("$data\Nick2\identity.pub")
$sha256   = [System.Security.Cryptography.SHA256]::Create()
$nick1fp  = ($sha256.ComputeHash($nick1pub) | ForEach-Object { $_.ToString("x2") }) -join ""
$nick2fp  = ($sha256.ComputeHash($nick2pub) | ForEach-Object { $_.ToString("x2") }) -join ""
$nick1b64 = [Convert]::ToBase64String($nick1pub)
$nick2b64 = [Convert]::ToBase64String($nick2pub)
$now      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

@"
[{"name":"Nick2","identity_pub":"$nick2b64","fingerprint":"$nick2fp","trusted_at":"$now"}]
"@ | Set-Content "$data\Nick1\truststore.json" -Encoding UTF8

@"
[{"name":"Nick1","identity_pub":"$nick1b64","fingerprint":"$nick1fp","trusted_at":"$now"}]
"@ | Set-Content "$data\Nick2\truststore.json" -Encoding UTF8

Write-Host "  Setup: shared files and trust stores written." -ForegroundColor Gray

# ── Process helpers ──────────────────────────────────────────────────────────
function Start-Peer($peerName) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName        = "java"
    $psi.Arguments       = "-jar $jar"
    $psi.WorkingDirectory = $base
    $psi.RedirectStandardInput  = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow  = $true

    $p  = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    $sb = [System.Text.StringBuilder]::new()

    $handler = { if ($EventArgs.Data) { [void]$Event.MessageData.AppendLine($EventArgs.Data) } }
    Register-ObjectEvent -InputObject $p -EventName OutputDataReceived -Action $handler -MessageData $sb | Out-Null
    Register-ObjectEvent -InputObject $p -EventName ErrorDataReceived  -Action $handler -MessageData $sb | Out-Null

    $p.Start() | Out-Null
    $p.BeginOutputReadLine()
    $p.BeginErrorReadLine()
    return @{ Process = $p; Output = $sb; Name = $peerName }
}

function Wait-For($peer, $expected, $sendAfter=$null, $timeoutSec=15) {
    $dl = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $dl) {
        if ($peer.Output.ToString() -match [regex]::Escape($expected)) {
            if ($sendAfter) {
                Start-Sleep -Milliseconds 150
                $peer.Process.StandardInput.WriteLine($sendAfter)
                Write-Host "  [$($peer.Name)] >> $sendAfter" -ForegroundColor Yellow
            }
            return $true
        }
        Start-Sleep -Milliseconds 250
    }
    Write-Host "  TIMEOUT waiting for '$expected' on $($peer.Name)" -ForegroundColor Red
    return $false
}

function Send($peer, $cmd) {
    Start-Sleep -Milliseconds 350
    $peer.Process.StandardInput.WriteLine($cmd)
    Write-Host "  [$($peer.Name)] >> $cmd" -ForegroundColor Yellow
}

function Pass($msg) { Write-Host "  PASS: $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "  FAIL: $msg" -ForegroundColor Red }
function Check($ok, $pass, $fail) { if ($ok) { Pass $pass } else { Fail $fail } }

# ── Start peers ──────────────────────────────────────────────────────────────
Write-Host "`n[1] Starting Nick1 and Nick2..." -ForegroundColor Cyan
$nick1 = Start-Peer "Nick1"
$nick2 = Start-Peer "Nick2"

Start-Sleep -Milliseconds 600
$nick1.Process.StandardInput.WriteLine("Nick1")
$nick1.Process.StandardInput.WriteLine("password")
Start-Sleep -Milliseconds 300
$nick2.Process.StandardInput.WriteLine("Nick2")
$nick2.Process.StandardInput.WriteLine("password")

Check (Wait-For $nick1 "mDNS registered" -timeoutSec 20) "Nick1 started" "Nick1 did not start"
Check (Wait-For $nick2 "mDNS registered" -timeoutSec 20) "Nick2 started" "Nick2 did not start"

# ── Peer Discovery ───────────────────────────────────────────────────────────
Write-Host "`n[2] Peer Discovery..." -ForegroundColor Cyan
Start-Sleep -Milliseconds 3500
Send $nick1 "peers"
Check (Wait-For $nick1 "Nick2" -timeoutSec 8) "Nick1 discovers Nick2" "Nick1 did not discover Nick2"

# ── Mutual Auth: Nick1 -> Nick2 ──────────────────────────────────────────────
Write-Host "`n[3] Nick1 connects to Nick2 (outgoing session)..." -ForegroundColor Cyan
Send $nick1 "connect Nick2"
Check (Wait-For $nick1 "authenticated with 'Nick2'" -timeoutSec 12) `
      "Nick1 authenticated with Nick2" "Nick1 handshake failed"
Check (Wait-For $nick2 "Incoming connection from 'Nick1'" -timeoutSec 12) `
      "Nick2 accepted Nick1's connection" "Nick2 did not see incoming connection"

# ── Mutual Auth: Nick2 -> Nick1 (bidirectional) ──────────────────────────────
Write-Host "`n[4] Nick2 connects to Nick1 (outgoing session for bidirectional ops)..." -ForegroundColor Cyan
Send $nick2 "connect Nick1"
Check (Wait-For $nick2 "authenticated with 'Nick1'" -timeoutSec 12) `
      "Nick2 authenticated with Nick1" "Nick2 handshake failed"

# ── File Listing ─────────────────────────────────────────────────────────────
Write-Host "`n[5] File listing (no consent required)..." -ForegroundColor Cyan
Send $nick1 "list Nick2"
Check (Wait-For $nick1 "gift.txt" -timeoutSec 8) `
      "Nick1 sees Nick2's file list (gift.txt)" "Nick1 file list missing gift.txt"

Send $nick2 "list Nick1"
Check (Wait-For $nick2 "secret.txt" -timeoutSec 8) `
      "Nick2 sees Nick1's file list (secret.txt)" "Nick2 file list missing secret.txt"

# ── File Send (Nick1 pushes to Nick2, Nick2 consents) ────────────────────────
# Note: wait for the full line "[?] ... wants to send you ..." (ends with newline)
# rather than "Accept? [y/n]:" which has no newline and is never delivered to the async reader.
Write-Host "`n[6] File send with consent: Nick1 -> Nick2..." -ForegroundColor Cyan
Send $nick1 "send Nick2 secret.txt"
Check (Wait-For $nick2 "wants to send you" "y" -timeoutSec 12) `
      "Nick2 prompted and accepted" "Nick2 consent prompt not seen"
# Nick2 is the receiver — it prints "Hash verified". Nick1 is the sender — it prints "sent successfully".
Check (Wait-For $nick2 "Hash verified" -timeoutSec 12) `
      "Nick2 received file and verified hash" "Nick2 hash check failed or transfer incomplete"
Check (Wait-For $nick1 "sent successfully" -timeoutSec 12) `
      "Nick1 confirmed file sent" "Nick1 send confirmation not seen"

# ── File Request (Nick2 pulls from Nick1, Nick1 consents) ───────────────────
Write-Host "`n[7] File request with consent: Nick2 requests hello.txt from Nick1..." -ForegroundColor Cyan
Send $nick2 "request Nick1 hello.txt"
Check (Wait-For $nick1 "is requesting file" "y" -timeoutSec 12) `
      "Nick1 prompted and allowed" "Nick1 consent prompt not seen"
Check (Wait-For $nick2 "hash verified" -timeoutSec 12) `
      "File received, hash verified" "Receive or hash check failed"

# ── File Request Rejected ────────────────────────────────────────────────────
Write-Host "`n[8] File request rejected: Nick1 requests gift.txt from Nick2, Nick2 says no..." -ForegroundColor Cyan
Send $nick1 "request Nick2 gift.txt"
Check (Wait-For $nick2 "is requesting file 'gift.txt'" "n" -timeoutSec 12) `
      "Nick2 prompted" "Nick2 consent prompt not seen"
Check (Wait-For $nick1 "rejected" -timeoutSec 8) `
      "Nick1 sees rejection" "Nick1 did not see rejection message"

# ── Key Migration ────────────────────────────────────────────────────────────
Write-Host "`n[9] Key migration: Nick1 migrates key..." -ForegroundColor Cyan
Send $nick1 "migrate"
Check (Wait-For $nick2 "Key migration accepted" -timeoutSec 12) `
      "Nick2 received migration notification" "Nick2 did not get migration"
Check (Wait-For $nick1 "Key migration complete" -timeoutSec 8) `
      "Nick1 migration completed" "Nick1 migration did not complete"

# ── Contacts ─────────────────────────────────────────────────────────────────
Write-Host "`n[10] Contacts check..." -ForegroundColor Cyan
Send $nick1 "contacts"
Send $nick2 "contacts"
Start-Sleep -Milliseconds 1500

# ── Shutdown ─────────────────────────────────────────────────────────────────
Write-Host "`n[11] Shutting down..." -ForegroundColor Cyan
Send $nick1 "exit"
Send $nick2 "exit"
Start-Sleep -Milliseconds 2000

# Save logs
$log1 = $nick1.Output.ToString()
$log2 = $nick2.Output.ToString()
$log1 | Set-Content "$logs\nick1.log" -Encoding UTF8
$log2 | Set-Content "$logs\nick2.log" -Encoding UTF8

Write-Host "`n========== Nick1 Output ==========" -ForegroundColor Cyan
$log1 -split "`n" | Where-Object {$_.Trim()} | ForEach-Object { Write-Host "  $_" }
Write-Host "`n========== Nick2 Output ==========" -ForegroundColor Cyan
$log2 -split "`n" | Where-Object {$_.Trim()} | ForEach-Object { Write-Host "  $_" }

Write-Host "`n=== Done. Logs saved to $logs ===" -ForegroundColor Cyan
try { $nick1.Process.Kill() } catch {}
try { $nick2.Process.Kill() } catch {}
Get-EventSubscriber | Unregister-Event -Force -ErrorAction SilentlyContinue
