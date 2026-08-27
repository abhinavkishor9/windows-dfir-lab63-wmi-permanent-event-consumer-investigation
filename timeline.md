# Timeline: WMI Permanent Event Consumer Investigation

## Investigation Timeline

This timeline reconstructs the major stages of the WMI Permanent Event Consumer Investigation using the captured timestamps and observed artifacts.

---

## 27 August 2026 - 07:58:33

### Initial Environment Verification

The Windows endpoint environment was verified using:

```powershell
hostname
whoami
Get-Date
```

Observed values:

```text
Hostname: DESKTOP-9MMM37V
User: desktop-9mmm37v\dell
Timestamp: 27 August 2026 07:58:33
```

This established the initial investigation context.

---

## 27 August 2026 - 07:59

### Investigation Directory Creation

The investigation directory was created:

```text
C:\WMIPermanentEventLab
```

Subdirectories:

```text
C:\WMIPermanentEventLab\Payload
C:\WMIPermanentEventLab\Output
C:\WMIPermanentEventLab\Evidence
```

These directories separated the payload, execution results, and forensic evidence.

---

## 27 August 2026 - 07:59:15

### Initial Filesystem State

The newly created investigation directories were observed.

The directories included:

```text
Evidence
Output
Payload
```

This represented the initial filesystem state before the controlled payload was created.

---

## 27 August 2026 - 08:00:04

### Filesystem Baseline

A filesystem baseline was collected:

```powershell
Get-ChildItem "C:\WMIPermanentEventLab" -Recurse -Force |
Select-Object FullName, Length, CreationTime, LastWriteTime |
Out-File "C:\WMIPermanentEventLab\Evidence\baseline.txt"
```

Evidence file:

```text
C:\WMIPermanentEventLab\Evidence\baseline.txt
```

The baseline recorded the initial paths and timestamps of the investigation directory.

---

## 27 August 2026 - 08:01:07

### Controlled PowerShell Payload Created

The benign PowerShell payload was created:

```text
C:\WMIPermanentEventLab\Payload\wmi-payload.ps1
```

The payload was designed to record:

- Execution time
- Hostname
- User context
- Execution status

Output file:

```text
C:\WMIPermanentEventLab\Output\wmi-event-result.txt
```

The payload file was inspected and hashed.

Captured file size:

```text
479 bytes
```

---

## 27 August 2026 - 08:01:07

### Sysmon Event ID 11

Sysmon Event ID 11 recorded creation of:

```text
C:\WMIPermanentEventLab\Payload\wmi-payload.ps1
```

Relevant details:

```text
Event ID: 11
Image:
C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.5.0_x64__8wekyb3d8bbwe\pwsh.exe

TargetFilename:
C:\WMIPermanentEventLab\Payload\wmi-payload.ps1

User:
DESKTOP-9MMM37V\Dell
```

This provided endpoint evidence for the payload creation stage.

---

## Before Controlled WMI Subscription Creation

### Existing WMI Subscription Enumeration

Existing WMI objects were reviewed before creating the controlled subscription.

The following classes were examined:

```text
__EventFilter
CommandLineEventConsumer
__FilterToConsumerBinding
```

A pre-existing WMI event filter was observed:

```text
Name: SCM Event Log Filter
Query: select * from MSFT_SCMEventLogEvent
Namespace: root\cimv2
```

A pre-existing binding connected the filter with:

```text
NTEventLogEventConsumer
Name: SCM Event Log Consumer
```

This demonstrated that WMI subscriptions may already exist on the endpoint.

---

## WMI Persistence Configuration

### Controlled Event Filter Created

A controlled event filter was created:

```text
Lab_WMI_Event_Filter
```

Configuration:

```text
Namespace: root\cimv2
Query Language: WQL
```

Query:

```sql
SELECT * FROM __InstanceModificationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_OperatingSystem'
```

The filter represented the trigger component.

---

## WMI Persistence Configuration

### Controlled Command-Line Event Consumer Created

A command-line event consumer was created:

```text
Lab_WMI_Command_Consumer
```

Configured command:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\WMIPermanentEventLab\Payload\wmi-payload.ps1"
```

This established the execution action for the controlled subscription.

---

## WMI Persistence Configuration

### Filter-to-Consumer Binding Created

A:

```text
__FilterToConsumerBinding
```

object was created.

The binding connected:

```text
Lab_WMI_Event_Filter
```

to:

```text
Lab_WMI_Command_Consumer
```

This completed the controlled WMI subscription relationship.

The resulting structure was:

```text
Lab_WMI_Event_Filter
        |
        v
__FilterToConsumerBinding
        |
        v
Lab_WMI_Command_Consumer
```

---

## 27 August 2026 - 08:06:56

### Pre-Execution Time Reference

The current time was recorded before checking the execution result.

Observed timestamp:

```text
27 August 2026 08:06:56
```

This provided a temporal reference for subsequent execution evidence.

---

## 27 August 2026 - 08:07:43

### WMI-Triggered Payload Execution Confirmed

The payload output file was found:

```text
C:\WMIPermanentEventLab\Output\wmi-event-result.txt
```

Captured output:

```text
Execution Time: 08/27/2026 08:07:43
Hostname: DESKTOP-9MMM37V
User: nt authority\system
Status: Benign WMI permanent event subscription triggered successfully
```

This confirmed successful execution.

Most significant observation:

```text
Execution Context: NT AUTHORITY\SYSTEM
```

---

## 27 August 2026 - 08:08 to 08:09

### Sysmon Event ID 1 Review

Sysmon Event ID 1 records were reviewed.

PowerShell process creation was observed.

Relevant executable:

```text
C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe
```

Captured context:

```text
User: SYSTEM
Computer: DESKTOP-9MMM37V
```

The process creation evidence supported the PowerShell execution stage.

---

## Post-Execution

### WMI Evidence Export

The three primary WMI subscription components were exported.

Evidence files:

```text
C:\WMIPermanentEventLab\Evidence\event-filters.txt
C:\WMIPermanentEventLab\Evidence\event-consumers.txt
C:\WMIPermanentEventLab\Evidence\bindings.txt
```

These files preserved the WMI configuration for investigation and documentation.

---

## Post-Execution

### Wazuh Agent Verification

The Windows endpoint's Wazuh agent was checked using:

```bash
sudo /var/ossec/bin/agent_control -i 001
```

Observed status:

```text
Agent ID: 001
Agent Name: DESKTOP-9MMM37V
Status: Active
Operating System: Microsoft Windows 11 Pro
Client Version: Wazuh v4.12.0
```

This confirmed active Wazuh connectivity.

---

## Wazuh Monitoring Observation

A Wazuh alert related to listening-port status changes was observed.

The alert described:

```text
Listened ports status (netstat) changed
(new port opened or closed)
```

The available evidence did not establish that the alert was caused by the WMI permanent event subscription.

Therefore, it was treated as a separate monitoring observation.

---

# Final Activity Chain

The investigation reconstructed the following sequence:

```text
Lab Initialization
        |
        v
Endpoint Verification
        |
        v
Investigation Directory Creation
        |
        v
Filesystem Baseline
        |
        v
PowerShell Payload Creation
        |
        v
Sysmon Event ID 11
        |
        v
Existing WMI Subscription Review
        |
        v
__EventFilter Creation
        |
        v
CommandLineEventConsumer Creation
        |
        v
__FilterToConsumerBinding Creation
        |
        v
WMI Event Trigger
        |
        v
PowerShell Execution
        |
        v
Sysmon Event ID 1
        |
        v
Payload Output Created
        |
        v
Execution Context Verified
        |
        v
NT AUTHORITY\SYSTEM
        |
        v
WMI Evidence Export
        |
        v
Wazuh Agent Verification
```

---

# Core Evidence Timeline

| Approx. Time | Activity | Evidence |
|---|---|---|
| 07:58:33 | Endpoint verification | Hostname, user, timestamp |
| 07:59 | Directory creation | `C:\WMIPermanentEventLab` |
| 08:00:04 | Baseline creation | `baseline.txt` |
| 08:01:07 | Payload creation | `wmi-payload.ps1` |
| 08:01:07 | File creation telemetry | Sysmon Event ID 11 |
| Before WMI creation | Existing subscription review | WMI enumeration |
| WMI configuration | Event filter creation | `Lab_WMI_Event_Filter` |
| WMI configuration | Consumer creation | `Lab_WMI_Command_Consumer` |
| WMI configuration | Binding creation | `__FilterToConsumerBinding` |
| 08:06:56 | Pre-execution timestamp | `Get-Date` |
| 08:07:43 | Payload execution | `wmi-event-result.txt` |
| 08:08-08:09 | PowerShell process review | Sysmon Event ID 1 |
| Post-execution | WMI evidence export | Filters, consumers, bindings |
| Post-execution | Wazuh verification | Agent status |
| Post-execution | Separate monitoring observation | Listening-port alert |

---

# Key Timeline Relationship

The most important chronological and analytical relationship was:

```text
Payload Creation
        |
        v
WMI Filter Creation
        |
        v
Consumer Creation
        |
        v
Binding Creation
        |
        v
WMI Event Trigger
        |
        v
PowerShell Execution
        |
        v
Execution Output
        |
        v
Sysmon Process Evidence
        |
        v
Forensic Evidence Export
```

---

# Timeline Conclusion

The timeline demonstrates a progression from environment preparation and baseline collection through payload creation, WMI subscription configuration, execution verification, endpoint telemetry analysis, evidence preservation, and Wazuh monitoring verification.

The central investigative relationship was:

```text
Event Filter
    ->
Filter-to-Consumer Binding
    ->
Command-Line Event Consumer
    ->
PowerShell Payload
    ->
Execution Artifact
```

This relationship formed the core of the WMI permanent event consumer investigation.

The final execution evidence confirmed that the controlled payload executed successfully under:

```text
NT AUTHORITY\SYSTEM
```

while the separate Wazuh listening-port observation was intentionally excluded from the persistence chain because the available evidence did not establish a causal relationship.
