param()

$base = "C:\Users\alice\PycharmProjects\python-client"
$python = "$base\venv\Scripts\python.exe"
$app = "$base\app.py"
$data = "$base\data"
$logs = "$base\test-logs"

New-Item -ItemType Directory -Force -Path $logs | Out-Null

Write-Host "=== Python P2P Automated Test ===" -ForegroundColor Cyan

function Write-Pass($msg) { Write-Host "  PASS: $msg" -ForegroundColor Green }
function Write-Fail($msg) { Write-Host "  FAIL: $msg" -ForegroundColor Red }
function Check($ok, $pass, $fail) { if ($ok) { Write-Pass $pass } else { Write-Fail $fail } }

function Start-Peer($peerName, $port) {
    # each peer gets its own consent queue so background network threads do not read stdin.
    $consentFile = Join-Path $logs "$($peerName.ToLower())-consent.txt"
    if (Test-Path $consentFile) {
        Remove-Item $consentFile -Force
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $python
    $psi.Arguments = "-u `"$app`" --name $peerName --password password --port $port"
    $psi.WorkingDirectory = $base
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.EnvironmentVariables["P2P_CONSENT_QUEUE"] = $consentFile

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    $buffer = [System.Text.StringBuilder]::new()

    $handler = {
        if ($EventArgs.Data) {
            [void]$Event.MessageData.AppendLine($EventArgs.Data)
        }
    }

    Register-ObjectEvent -InputObject $process -EventName OutputDataReceived -Action $handler -MessageData $buffer | Out-Null
    Register-ObjectEvent -InputObject $process -EventName ErrorDataReceived -Action $handler -MessageData $buffer | Out-Null

    $process.Start() | Out-Null
    $process.BeginOutputReadLine()
    $process.BeginErrorReadLine()

    return @{
        Process = $process
        Output = $buffer
        Name = $peerName
        ConsentFile = $consentFile
    }
}

function Wait-For($peer, $expected, $sendAfter = $null, $timeoutSec = 15) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        $text = $peer.Output.ToString()
        if ($text -match [regex]::Escape($expected)) {
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

function Queue-Consent($peer, $response) {
    Add-Content -Path $peer.ConsentFile -Value $response -Encoding UTF8
    Write-Host "  [$($peer.Name)] consent <= $response" -ForegroundColor Yellow
}

function Initialize-PeerData($peerName, $password) {
    $peerDir = Join-Path $data $peerName
    $sharedDir = Join-Path $peerDir "shared"
    $storeDir = Join-Path $peerDir "store"
    New-Item -ItemType Directory -Force -Path $sharedDir | Out-Null
    New-Item -ItemType Directory -Force -Path $storeDir | Out-Null

    # this bootstraps a stable identity before the actual app process starts.
    $command = "from crypto.identity import Identity; identity = Identity('$peerName', '$password').load_or_create(); print(identity.fingerprint())"

    $fingerprint = (& $python -c $command).Trim()
    if (-not $fingerprint) {
        throw "Failed to initialize identity for $peerName"
    }

    return $fingerprint
}

function Write-TrustStore($owner, $entries) {
    $trustPath = Join-Path $data "$owner\truststore.json"
    $jsonObject = @{}
    foreach ($entry in $entries) {
        $jsonObject[$entry.Name] = @{
            fingerprint = $entry.Fingerprint
            previous_fingerprints = @()
        }
    }
    $jsonObject | ConvertTo-Json -Depth 4 | Set-Content $trustPath -Encoding UTF8
}

try {
    Write-Host "`n[1] Preparing peer data..." -ForegroundColor Cyan

    New-Item -ItemType Directory -Force -Path "$data\Alice1\shared" | Out-Null
    New-Item -ItemType Directory -Force -Path "$data\Alice2\shared" | Out-Null

    Set-Content "$data\Alice1\shared\secret.txt" "Top secret file from Alice1." -Encoding UTF8
    Set-Content "$data\Alice1\shared\hello.txt" "Hello from Alice1!" -Encoding UTF8
    Set-Content "$data\Alice2\shared\gift.txt" "A gift from Alice2!" -Encoding UTF8

    $alice1Fingerprint = Initialize-PeerData "Alice1" "password"
    $alice2Fingerprint = Initialize-PeerData "Alice2" "password"

    Write-TrustStore "Alice1" @(@{ Name = "Alice2"; Fingerprint = $alice2Fingerprint })
    Write-TrustStore "Alice2" @(@{ Name = "Alice1"; Fingerprint = $alice1Fingerprint })

    Write-Pass "Shared files and trust stores prepared"

    Write-Host "`n[2] Starting Alice1 and Alice2..." -ForegroundColor Cyan
    $alice1 = Start-Peer "Alice1" 6767
    $alice2 = Start-Peer "Alice2" 6768

    Check (Wait-For $alice1 "mDNS registered" $null 20) "Alice1 started" "Alice1 did not start"
    Check (Wait-For $alice2 "mDNS registered" $null 20) "Alice2 started" "Alice2 did not start"

    Write-Host "`n[3] Peer discovery..." -ForegroundColor Cyan
    Start-Sleep -Milliseconds 3500
    Send $alice1 "peers"
    Check (Wait-For $alice1 "Alice2" $null 8) "Alice1 discovers Alice2" "Alice1 did not discover Alice2"

    Write-Host "`n[4] Authenticated connection..." -ForegroundColor Cyan
    Send $alice1 "connect Alice2"
    Check (Wait-For $alice1 "Authenticated with 'Alice2'" $null 12) "Alice1 authenticated with Alice2" "Alice1 handshake failed"
    Check (Wait-For $alice2 "Incoming connection from 'Alice1'" $null 12) "Alice2 saw incoming connection" "Alice2 did not see Alice1 connect"

    Send $alice2 "connect Alice1"
    Check (Wait-For $alice2 "Authenticated with 'Alice1'" $null 12) "Alice2 authenticated with Alice1" "Alice2 handshake back to Alice1 failed"

    Write-Host "`n[5] File listing..." -ForegroundColor Cyan
    Send $alice1 "list Alice2"
    Check (Wait-For $alice1 "gift.txt" $null 8) "Alice1 sees Alice2 file list" "Alice1 file list missing gift.txt"

    Write-Host "`n[6] File send with consent..." -ForegroundColor Cyan
    Queue-Consent $alice2 "y"
    Send $alice1 "send Alice2 data\Alice1\shared\secret.txt"
    Check (Wait-For $alice2 "Accepted file offer for 'secret.txt' from Alice1" $null 12) "Alice2 accepted file offer" "Alice2 consent flow failed"
    Check (Wait-For $alice1 "Sent offered file 'secret.txt' to Alice2" $null 12) "Alice1 sent offered file" "Alice1 did not send offered file"
    Check (Wait-For $alice2 "Received and verified 'secret.txt' from Alice1" $null 12) "Alice2 received and verified offered file" "Alice2 did not receive verified file"

    Write-Host "`n[7] File request with consent..." -ForegroundColor Cyan
    Queue-Consent $alice1 "y"
    Send $alice2 "request Alice1 hello.txt"
    Check (Wait-For $alice1 "Sent 'hello.txt' to Alice2" $null 12) "Alice1 sent requested file" "Alice1 request consent flow failed"
    Check (Wait-For $alice2 "Received and verified 'hello.txt' from Alice1" $null 12) "Alice2 received requested file" "Alice2 request flow failed"

    Write-Host "`n[8] Rejected file request..." -ForegroundColor Cyan
    Queue-Consent $alice2 "n"
    Send $alice1 "request Alice2 gift.txt"
    Check (Wait-For $alice1 "Operation failed: File request rejected for gift.txt" $null 8) "Alice1 saw rejection error" "Alice1 did not see rejection error"

    Write-Host "`n[9] Key migration..." -ForegroundColor Cyan
    Send $alice1 "migrate"
    Check (Wait-For $alice1 "Rotated identity key and notified connected peers" $null 8) "Alice1 completed local key rotation" "Alice1 key rotation did not complete"
    Check (Wait-For $alice2 "Updated trusted key for Alice1" $null 12) "Alice2 accepted Alice1 migration" "Alice2 did not update trusted key"

    Write-Host "`n[10] Contacts..." -ForegroundColor Cyan
    Send $alice1 "contacts"
    Send $alice2 "contacts"
    Start-Sleep -Milliseconds 1200

    Write-Host "`n[11] Shutting down..." -ForegroundColor Cyan
    Send $alice1 "exit"
    Send $alice2 "exit"
    Start-Sleep -Milliseconds 1500

    $alice1Log = $alice1.Output.ToString()
    $alice2Log = $alice2.Output.ToString()
    $alice1Log | Set-Content "$logs\alice1.log" -Encoding UTF8
    $alice2Log | Set-Content "$logs\alice2.log" -Encoding UTF8

    Write-Host "`n========== Alice1 Output ==========" -ForegroundColor Cyan
    $alice1Log -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "  $_" }
    Write-Host "`n========== Alice2 Output ==========" -ForegroundColor Cyan
    $alice2Log -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "  $_" }

    Write-Host "`n=== Done. Logs saved to $logs ===" -ForegroundColor Cyan
}
finally {
    foreach ($peer in @($alice1, $alice2)) {
        if ($peer -and $peer.Process -and -not $peer.Process.HasExited) {
            try { $peer.Process.Kill() } catch {}
        }
    }
    Get-EventSubscriber | Unregister-Event -Force -ErrorAction SilentlyContinue
}
