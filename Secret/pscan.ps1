<#
.SYNOPSIS
    TCP Connect Port Scanner
.DESCRIPTION
    A production-quality, multithreaded TCP connect port scanner for Windows PowerShell 5.1.
    Utilizes a bounded Runspace Pool job queue to limit memory footprint when scanning large port ranges.
#>
[CmdletBinding(DefaultParameterSetName = 'Scan')]
param(
    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Scan')]
    [string]$Target,

    [Parameter(ParameterSetName = 'Scan')]
    [string[]]$Ports = @("1-1024"),

    [Parameter(ParameterSetName = 'Scan')]
    [int]$Threads = 100,

    [Parameter(ParameterSetName = 'Scan')]
    [int]$Timeout = 500,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$Banner,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$ShowTime,

    [Parameter(Mandatory = $true, ParameterSetName = 'Help')]
    [switch]$Help
)

# -----------------------------------------------------------------------------
# Function: Show-Help
# -----------------------------------------------------------------------------
function Show-Help {
    Write-Host "PortScanner.ps1"
    Write-Host ""
    Write-Host "TCP Connect Port Scanner"
    Write-Host ""
    Write-Host "Usage"
    Write-Host ""
    Write-Host "PortScanner.ps1 -Target <IP|Hostname>"
    Write-Host ""
    Write-Host "Options"
    Write-Host ""
    Write-Host "-Target"
    Write-Host "Target IP address or hostname."
    Write-Host "Required."
    Write-Host ""
    Write-Host "-Ports"
    Write-Host "Port list or ranges."
    Write-Host "Default: 1-1024"
    Write-Host ""
    Write-Host "-Threads"
    Write-Host "Number of concurrent threads."
    Write-Host "Default: 100"
    Write-Host ""
    Write-Host "-Timeout"
    Write-Host "Connection timeout (milliseconds)."
    Write-Host "Default: 500"
    Write-Host ""
    Write-Host "-Banner"
    Write-Host "Enable banner grabbing."
    Write-Host ""
    Write-Host "-ShowTime"
    Write-Host "Display elapsed scan time."
    Write-Host ""
    Write-Host "-Help"
    Write-Host "Display this help."
    Write-Host ""
    Write-Host "Examples"
    Write-Host ""
    Write-Host "PortScanner.ps1 -Target 192.168.1.10"
    Write-Host "PortScanner.ps1 -Target server01 -Ports 22,80,443 -ShowTime"
    Write-Host "PortScanner.ps1 -Target google.com -Ports 1-1000,8080 -Threads 200 -Timeout 1000 -Banner"
}

# -----------------------------------------------------------------------------
# Function: Get-ParsedPorts
# -----------------------------------------------------------------------------
function Get-ParsedPorts {
    param(
        [string[]]$PortString
    )

    $parsedPorts = New-Object System.Collections.Generic.List[int]

    # Accept arrays, commas and whitespace
    $tokens = ($PortString -join ',') -split '[,\s]+' | Where-Object { $_ }

    foreach ($token in $tokens) {

        if ($token -match '^(\d+)$') {

            $p = [int]$matches[1]

            if ($p -lt 1 -or $p -gt 65535) {
                Write-Host "Error: Invalid port number '$p'. Must be between 1 and 65535."
                exit 1
            }

            $parsedPorts.Add($p)
        }
        elseif ($token -match '^(\d+)-(\d+)$') {

            $p1 = [int]$matches[1]
            $p2 = [int]$matches[2]

            if ($p1 -lt 1 -or $p2 -gt 65535 -or $p1 -gt $p2) {
                Write-Host "Error: Invalid port range '$token'."
                exit 1
            }

            foreach ($port in $p1..$p2) {
                $parsedPorts.Add($port)
            }
        }
        else {
            Write-Host "Error: Malformed port expression '$token'."
            exit 1
        }
    }

    return $parsedPorts | Sort-Object -Unique
}

# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------

if ($Help) {
    Show-Help
    exit 0
}

if ($Threads -le 0) {
    Write-Host "Error: -Threads must be greater than zero."
    exit 1
}

if ($Timeout -le 0) {
    Write-Host "Error: -Timeout must be greater than zero."
    exit 1
}

# Resolve target hostname/IP
try {
    $ipAddresses = [System.Net.Dns]::GetHostAddresses($Target)
    $ipv4 = $ipAddresses | Where-Object { $_.AddressFamily -eq 'InterNetwork' }
    if (-not $ipv4) {
        throw "No IPv4 address found"
    }
    $ipAddress = $ipv4[0].IPAddressToString
} catch {
    Write-Host "Unable to resolve hostname '$Target'."
    exit 1
}

# Parse and validate ports
$portArray = Get-ParsedPorts -PortString $Ports
if ($portArray.Count -eq 0) {
    Write-Host "Error: No valid ports to scan."
    exit 1
}

# -----------------------------------------------------------------------------
# Worker ScriptBlock (Executed in Runspaces)
# -----------------------------------------------------------------------------
$workerScript = {
    param(
        [string]$IP,
        [int]$Port,
        [int]$Timeout,
        [bool]$GrabBanner
    )

    $result = [PSCustomObject]@{
        Port   = $Port
        IsOpen = $false
        Banner = $null
    }

    $tcpClient = $null
    $asyncResult = $null
    $waitHandle = $null
    $stream = $null

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $tcpClient.BeginConnect($IP, $Port, $null, $null)
        $waitHandle = $asyncResult.AsyncWaitHandle
        
        $success = $waitHandle.WaitOne($Timeout, $false)

        if ($success -and $tcpClient.Connected) {
            $result.IsOpen = $true
            $tcpClient.EndConnect($asyncResult)

            # Banner grabbing logic
            if ($GrabBanner) {
                try {
                    $stream = $tcpClient.GetStream()
                    $stream.ReadTimeout = $Timeout

                    # Wait for initial data (SSH, FTP, SMTP, POP3, IMAP, Telnet often send greetings)
                    $sw = [System.Diagnostics.Stopwatch]::StartNew()
                    while (-not $stream.DataAvailable -and $sw.ElapsedMilliseconds -lt $Timeout) {
                        Start-Sleep -Milliseconds 10
                    }

                    # If no data is available, send a generic HTTP probe
                    if (-not $stream.DataAvailable) {
                        $probe = [System.Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.0`r`n`r`n")
                        $stream.Write($probe, 0, $probe.Length)

                        $sw.Restart()
                        while (-not $stream.DataAvailable -and $sw.ElapsedMilliseconds -lt $Timeout) {
                            Start-Sleep -Milliseconds 10
                        }
                    }

                    # Read and parse the response if available
                    if ($stream.DataAvailable) {
                        $buffer = New-Object byte[] 1024
                        $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
                        $response = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)

                        # Enhanced Service Detection Parsing
                        if ($response -match '(?i)Server:\s*([^\r\n]+)') {
                            $result.Banner = $matches[1].Trim()
                        } elseif ($response -match '^SSH-[\d\.]+-[^\r\n]+') {
                            $result.Banner = $matches[0].Trim()
                        } elseif ($response -match '^\*\s*OK\s*(.*)') {
                            $result.Banner = "IMAP: " + $matches[1].Trim()
                        } elseif ($response -match '^\+OK\s*(.*)') {
                            $result.Banner = "POP3: " + $matches[1].Trim()
                        } elseif ($response -match '^\d{3}[-\s](.*)') {
                            # Covers SMTP (220), FTP (220), etc.
                            $result.Banner = $matches[1].Trim()
                        } else {
                            # Fallback: grab the first non-empty line
                            $lines = $response -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                            if ($lines.Count -gt 0) {
                                $result.Banner = $lines[0].Trim()
                            }
                        }

                        # Strip non-printable ASCII characters (useful for messy Telnet/Binary streams)
                        if (-not [string]::IsNullOrWhiteSpace($result.Banner)) {
                            $result.Banner = $result.Banner -replace '[^\x20-\x7E]', ''
                        }
                    }
                } catch {
                    # Safe to ignore banner parsing errors to continue scan
                }
            }
        }
    } catch {
        # Safe to ignore connection errors
    } finally {
        # Ensure all disposable objects are strictly cleaned up
        if ($null -ne $stream) { try { $stream.Dispose() } catch {} }
        if ($null -ne $waitHandle) { try { $waitHandle.Dispose() } catch {} }
        if ($null -ne $tcpClient) {
            try { $tcpClient.Close() } catch {}
            try { $tcpClient.Dispose() } catch {}
        }
    }

    return $result
}

# -----------------------------------------------------------------------------
# Runspace Pool Execution Engine (Bounded Queue)
# -----------------------------------------------------------------------------
$startTime = Get-Date

Write-Host "Target : $Target"
Write-Host ""
Write-Host "Scanning..."
Write-Host ""

$initialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$pool = [runspacefactory]::CreateRunspacePool(1, $Threads, $initialSessionState, $Host)
$pool.Open()

# Initialize the queue with all target ports
$portQueue = New-Object System.Collections.Generic.Queue[int]
foreach ($p in $portArray) {
    $portQueue.Enqueue($p)
}

$activeJobs = New-Object System.Collections.Generic.List[psobject]
$results = New-Object System.Collections.Generic.List[psobject]

# Producer-Consumer Loop: Process until queue is empty and all jobs are finished
while ($portQueue.Count -gt 0 -or $activeJobs.Count -gt 0) {
    
    # Producer: Enqueue workers up to the defined $Threads limit
    while ($activeJobs.Count -lt $Threads -and $portQueue.Count -gt 0) {
        $portToScan = $portQueue.Dequeue()
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        
        [void]$ps.AddScript($workerScript)
        [void]$ps.AddArgument($ipAddress)
        [void]$ps.AddArgument($portToScan)
        [void]$ps.AddArgument($Timeout)
        [void]$ps.AddArgument([bool]$Banner)

        $jobObj = [PSCustomObject]@{
            PowerShell = $ps
            Handle     = $ps.BeginInvoke()
        }
        $activeJobs.Add($jobObj)
    }

    # Consumer: Identify and process completed jobs
    $jobsToRemove = New-Object System.Collections.Generic.List[psobject]
    foreach ($job in $activeJobs) {
        if ($job.Handle.IsCompleted) {
            try {
                $res = $job.PowerShell.EndInvoke($job.Handle)
                if ($res) {
                    foreach ($r in $res) {
                        $results.Add($r)
                    }
                }
            } catch {
                # Ignore individual thread exceptions
            } finally {
                # Cleanup the individual PowerShell runspace instance
                if ($null -ne $job.PowerShell) {
                    $job.PowerShell.Dispose()
                }
            }
            $jobsToRemove.Add($job)
        }
    }

    # Clean up tracking list
    foreach ($job in $jobsToRemove) {
        [void]$activeJobs.Remove($job)
    }

    # Throttle slightly to prevent high CPU utilization while waiting
    if ($activeJobs.Count -ge $Threads -or ($portQueue.Count -eq 0 -and $activeJobs.Count -gt 0)) {
        Start-Sleep -Milliseconds 10
    }
}

$pool.Close()
$pool.Dispose()

# -----------------------------------------------------------------------------
# Output Formatting
# -----------------------------------------------------------------------------
$openCount = 0
$sortedResults = $results | Where-Object { $_.IsOpen } | Sort-Object Port

foreach ($res in $sortedResults) {
    $openCount++
    if ($Banner) {
        if (-not [string]::IsNullOrWhiteSpace($res.Banner)) {
            $portStr = $res.Port.ToString().PadRight(5)
            Write-Host "${portStr} OPEN    $($res.Banner)"
        } else {
            $portStr = $res.Port.ToString().PadRight(5)
            Write-Host "${portStr} OPEN"
        }
    } else {
        Write-Host "OPEN    $($res.Port)"
    }
}

Write-Host ""
Write-Host "Completed."
Write-Host ""
Write-Host "Open ports : $openCount"

if ($ShowTime) {
    $endTime = Get-Date
    $elapsed = ($endTime - $startTime).TotalSeconds
    $formattedTime = "{0:N2}" -f $elapsed
    Write-Host ""
    Write-Host "Elapsed time : $formattedTime seconds"
}

exit 0
