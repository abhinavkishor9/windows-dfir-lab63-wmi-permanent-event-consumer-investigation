# Investigation Notes

## Endpoint Context

```text
Computer: DESKTOP-9MMM37V
Operating System: Microsoft Windows 11 Pro
Initial User: desktop-9mmm37v\dell
PowerShell: 7.6.5
```

Initial environment verification was performed using:

```powershell
hostname
whoami
Get-Date
```

The initial verification timestamp was:

```text
27 August 2026 07:58:33
```

---

## Investigation Directory

The investigation used:

```text
C:\WMIPermanentEventLab
```

Directory structure:

```text
C:\WMIPermanentEventLab
├── Evidence
├── Output
└── Payload
```

The directories separated the payload, execution results, and forensic evidence.

---

## Baseline Collection

A filesystem baseline was collected before the payload and WMI subscription artifacts were created.

Command:

```powershell
Get-ChildItem "C:\WMIPermanentEventLab" -Recurse -Force |
Select-Object FullName, Length, CreationTime, LastWriteTime |
Out-File "C:\WMIPermanentEventLab\Evidence\baseline.txt"
```

The baseline recorded:

- Full path
- File size
- Creation time
- Last-write time

The initial baseline showed the investigation directories and the baseline evidence file.

This provided a reference point for identifying subsequent changes.

---

## Payload Investigation

The controlled payload was created at:

```text
C:\WMIPermanentEventLab\Payload\wmi-payload.ps1
```

The payload collected:

- Execution timestamp
- Hostname
- User context
- Execution status

The payload wrote its output to:

```text
C:\WMIPermanentEventLab\Output\wmi-event-result.txt
```

The payload was inspected and hashed before being used in the WMI subscription.

---

## Sysmon Event ID 11: Payload Creation

Sysmon Event ID 11 recorded creation of:

```text
C:\WMIPermanentEventLab\Payload\wmi-payload.ps1
```

Relevant telemetry included:

```text
Event ID: 11
Logged: 27-08-2026 08:01:07
Image: C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.5.0_x64__8wekyb3d8bbwe\pwsh.exe
TargetFilename: C:\WMIPermanentEventLab\Payload\wmi-payload.ps1
User: DESKTOP-9MMM37V\Dell
```

This established endpoint evidence for the payload creation stage.

The event was useful because it provided:

- Creating process
- Target filename
- Timestamp
- User context

However, the event alone did not demonstrate WMI persistence.

---

## Pre-Existing WMI Subscription Review

Before creating the controlled subscription, the existing WMI subscription objects were enumerated.

### Event Filters

```powershell
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter
```

A pre-existing event filter was observed:

```text
Name: SCM Event Log Filter
EventNamespace: root\cimv2
Query: select * from MSFT_SCMEventLogEvent
QueryLanguage: WQL
```

### Command-Line Event Consumers

```powershell
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer
```

No output was shown for this enumeration in the captured evidence.

### Filter-to-Consumer Bindings

```powershell
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding
```

A pre-existing relationship was observed involving:

```text
Filter: __EventFilter (Name = "SCM Event Log Filter")
Consumer: NTEventLogEventConsumer (Name = "SCM Event Log Consumer")
```

This finding was important because it demonstrated that WMI subscriptions can legitimately exist on a Windows endpoint.

The presence of a WMI subscription should therefore be treated as an investigation lead rather than an automatic malicious verdict.

---

## Controlled Event Filter

The controlled event filter was named:

```text
Lab_WMI_Event_Filter
```

The filter was configured in:

```text
root\cimv2
```

with:

```text
Query Language: WQL
```

The query was:

```sql
SELECT * FROM __InstanceModificationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_OperatingSystem'
```

The filter represented the trigger component.

The investigation question was:

> What system condition is required before the configured execution action occurs?

The answer is defined by the event filter and its WQL query.

---

## Controlled Command-Line Event Consumer

The controlled consumer was named:

```text
Lab_WMI_Command_Consumer
```

The configured command was:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\WMIPermanentEventLab\Payload\wmi-payload.ps1"
```

The consumer represented the execution component.

Important characteristics of the command include:

- `powershell.exe` is used for execution.
- `-NoProfile` prevents normal PowerShell profile loading.
- `-ExecutionPolicy Bypass` overrides the normal PowerShell execution-policy behavior for the launched process.
- `-File` specifies the PowerShell payload.
- The payload resides inside the controlled investigation directory.

The command should be evaluated in context rather than treated as malicious solely because `ExecutionPolicy Bypass` is present.

---

## Filter-to-Consumer Binding

The filter and consumer were connected using:

```text
__FilterToConsumerBinding
```

The captured binding identified:

```text
Filter:
__EventFilter.Name="Lab_WMI_Event_Filter"

Consumer:
CommandLineEventConsumer.Name="Lab_WMI_Command_Consumer"
```

This was the key correlation artifact.

The binding demonstrated the relationship:

```text
Lab_WMI_Event_Filter
        |
        v
__FilterToConsumerBinding
        |
        v
Lab_WMI_Command_Consumer
```

Without this relationship, the event filter and consumer could be identified independently without proving that they form a functioning execution chain.

---

## Persistence Chain Reconstruction

The complete controlled chain was reconstructed as:

```text
WMI Event Condition
        |
        v
Lab_WMI_Event_Filter
        |
        v
__FilterToConsumerBinding
        |
        v
Lab_WMI_Command_Consumer
        |
        v
powershell.exe
        |
        v
wmi-payload.ps1
        |
        v
wmi-event-result.txt
```

This chain demonstrates why WMI persistence investigations require relationship-based analysis.

---

## Execution Verification

The execution result file was:

```text
C:\WMIPermanentEventLab\Output\wmi-event-result.txt
```

The captured output was:

```text
Execution Time: 08/27/2026 08:07:43
Hostname: DESKTOP-9MMM37V
User: nt authority\system
Status: Benign WMI permanent event subscription triggered successfully
```

The output established:

- The payload executed.
- The endpoint was `DESKTOP-9MMM37V`.
- The execution occurred at approximately 08:07:43.
- The execution context was `NT AUTHORITY\SYSTEM`.
- The controlled activity completed successfully.

---

## Execution Context Analysis

The initial lab user was:

```text
desktop-9mmm37v\dell
```

The payload execution context was:

```text
nt authority\system
```

This difference is significant for investigation methodology.

An analyst should not assume that the account that creates or configures an artifact is necessarily the account under which the resulting process executes.

Execution context should be verified through available evidence such as:

- Payload output
- Sysmon process creation
- Windows Security logs
- Process ownership
- Parent process information
- WMI configuration

---

## Sysmon Event ID 1: Process Creation

Sysmon Event ID 1 captured PowerShell process creation during the execution sequence.

Relevant details included:

```text
Event ID: 1
Image: C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe
User: SYSTEM
Computer: DESKTOP-9MMM37V
Logged: 27-08-2026 08:09:00
```

This provided supporting endpoint evidence for the PowerShell execution stage.

The process creation event should be correlated with:

```text
WMI Consumer
+
Configured Command
+
Payload Path
+
Filter-to-Consumer Binding
+
Execution Output
```

rather than interpreted in isolation.

---

## WMI Evidence Collection

The following evidence files were created:

```text
C:\WMIPermanentEventLab\Evidence\event-filters.txt
C:\WMIPermanentEventLab\Evidence\event-consumers.txt
C:\WMIPermanentEventLab\Evidence\bindings.txt
```

The evidence was collected using:

```powershell
Get-CimInstance `
    -Namespace root\subscription `
    -ClassName __EventFilter |
Format-List * |
Out-File "C:\WMIPermanentEventLab\Evidence\event-filters.txt"
```

```powershell
Get-CimInstance `
    -Namespace root\subscription `
    -ClassName CommandLineEventConsumer |
Format-List * |
Out-File "C:\WMIPermanentEventLab\Evidence\event-consumers.txt"
```

```powershell
Get-CimInstance `
    -Namespace root\subscription `
    -ClassName __FilterToConsumerBinding |
Format-List * |
Out-File "C:\WMIPermanentEventLab\Evidence\bindings.txt"
```

Collecting all three components preserves the complete subscription structure.

---

## Wazuh Monitoring

The Wazuh agent associated with the endpoint was verified.

Command:

```bash
sudo /var/ossec/bin/agent_control -i 001
```

Observed status:

```text
Agent ID: 001
Agent Name: DESKTOP-9MMM37V
Status: Active
Operating system: Microsoft Windows 11 Pro
Client version: Wazuh v4.12.0
```

This confirmed active Wazuh connectivity.

However, the primary persistence evidence was obtained from:

- WMI enumeration
- WMI object correlation
- Sysmon Event ID 11
- Sysmon Event ID 1
- Payload execution output
- Evidence exports

---

## Wazuh Listening-Port Alert

A Wazuh alert concerning listening-port status changes was also observed.

The available evidence showed:

```text
Rule description:
Listened ports status (netstat) changed (new port opened or closed).
```

The observed output included listening services such as:

```text
tcp 0.0.0.0:22
tcp6 :::22
tcp 0.0.0.0:443
```

However, the available evidence did not establish that this alert was caused by the WMI permanent event subscription.

Therefore:

```text
Wazuh listening-port alert
        |
        X
        |
WMI persistence activity
```

The alert was treated as a separate monitoring observation.

This avoids introducing unsupported causal relationships into the investigation.

---

## Evidence Correlation

The investigation produced multiple evidence types:

| Evidence | Purpose |
|---|---|
| `baseline.txt` | Establishes initial filesystem state |
| `wmi-payload.ps1` | Controlled execution payload |
| Sysmon Event ID 11 | Payload file creation |
| `__EventFilter` | Defines event trigger |
| `CommandLineEventConsumer` | Defines execution action |
| `__FilterToConsumerBinding` | Connects trigger and action |
| `wmi-event-result.txt` | Confirms execution and context |
| Sysmon Event ID 1 | PowerShell process creation |
| WMI evidence exports | Preserves subscription objects |
| Wazuh agent status | Confirms monitoring connectivity |

---

## Key Findings

### Finding 1: A Controlled WMI Subscription Was Created

The investigation successfully created a controlled permanent WMI event subscription.

### Finding 2: The Subscription Contained Three Core Components

The controlled subscription consisted of:

```text
__EventFilter
CommandLineEventConsumer
__FilterToConsumerBinding
```

### Finding 3: The Consumer Referenced a PowerShell Payload

The consumer executed:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\WMIPermanentEventLab\Payload\wmi-payload.ps1"
```

### Finding 4: The Binding Established the Execution Relationship

The binding connected:

```text
Lab_WMI_Event_Filter
```

with:

```text
Lab_WMI_Command_Consumer
```

### Finding 5: Execution Was Confirmed

The payload created:

```text
C:\WMIPermanentEventLab\Output\wmi-event-result.txt
```

### Finding 6: Execution Occurred as SYSTEM

The output identified:

```text
NT AUTHORITY\SYSTEM
```

### Finding 7: Sysmon Supported the Activity Reconstruction

Sysmon Event ID 11 supported payload creation analysis.

Sysmon Event ID 1 supported process creation analysis.

### Finding 8: Existing WMI Objects Require Context

A pre-existing WMI subscription was observed before the controlled artifacts were created.

This demonstrated why WMI persistence cannot be classified solely from object presence.

### Finding 9: The Wazuh Port Alert Was Not Directly Correlated

The available evidence did not demonstrate that the listening-port alert resulted from the WMI subscription.

---

