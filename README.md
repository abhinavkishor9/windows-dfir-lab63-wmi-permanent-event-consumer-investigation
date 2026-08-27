# Windows DFIR Lab 63: WMI Permanent Event Consumer Investigation

## Overview

This lab investigates a Windows Management Instrumentation (WMI) permanent event subscription and reconstructs how an event condition can be connected to an execution action through WMI subscription objects.

The investigation focuses on three core WMI components:

- `__EventFilter`
- `CommandLineEventConsumer`
- `__FilterToConsumerBinding`

A controlled and benign PowerShell payload was created and configured as the execution action. The investigation then used WMI enumeration, Sysmon telemetry, payload output, forensic evidence collection, and Wazuh monitoring to verify and reconstruct the activity.

The lab demonstrates why WMI persistence investigations require correlation across multiple artifacts rather than relying on a single suspicious object or process event.

> **Note:** All activity in this lab was intentionally created as a controlled and benign simulation for DFIR and threat-hunting practice.

---

## Lab Objectives

- Understand WMI permanent event subscription persistence.
- Establish a filesystem baseline before creating investigation artifacts.
- Create and validate a controlled PowerShell payload.
- Enumerate existing WMI permanent event subscription objects.
- Create a WMI `__EventFilter`.
- Create a `CommandLineEventConsumer`.
- Create a `__FilterToConsumerBinding`.
- Reconstruct the relationship between the trigger and execution action.
- Verify that the configured payload executed.
- Determine the security context of the resulting execution.
- Investigate payload creation using Sysmon Event ID 11.
- Investigate PowerShell process creation using Sysmon Event ID 1.
- Preserve WMI subscription objects as forensic evidence.
- Verify Wazuh agent connectivity.
- Distinguish relevant persistence evidence from unrelated SIEM observations.

---

## Investigation Scenario

A Windows workstation is being investigated for a persistence mechanism that may not be visible through common locations such as Registry Run keys, scheduled tasks, or Windows services.

The analyst suspects that WMI permanent event subscriptions may have been configured to automatically execute a command when a particular system condition occurs.

The investigation must determine:

- Whether a WMI permanent event subscription exists.
- What event condition is being monitored.
- Which WMI event filter defines the trigger.
- What command is configured for execution.
- Which consumer contains the execution action.
- Whether a binding connects the filter and consumer.
- Whether the configured action actually executed.
- Under which security context the execution occurred.

The investigation reconstructs the following chain:

```text
WMI Event Condition
        |
        v
__EventFilter
        |
        v
__FilterToConsumerBinding
        |
        v
CommandLineEventConsumer
        |
        v
PowerShell
        |
        v
wmi-payload.ps1
        |
        v
Execution Output
```

---

## Lab Environment

### Endpoint

- Operating System: Microsoft Windows 11 Pro
- Computer: `DESKTOP-9MMM37V`
- Initial User: `DESKTOP-9MMM37V\dell`
- PowerShell: `PowerShell 7.6.5`

### Monitoring and Investigation Tools

- PowerShell
- WMI / CIM
- Sysmon
- Windows Event Viewer
- Wazuh Agent
- Wazuh Manager

---

## Lab Directory Structure

The investigation used the following directory:

```text
C:\WMIPermanentEventLab
├── Evidence
├── Output
└── Payload
```

### Purpose of Each Directory

| Directory | Purpose |
|---|---|
| `Payload` | Stores the controlled PowerShell payload |
| `Output` | Stores payload execution results |
| `Evidence` | Stores investigation and WMI evidence |

---

## Phase 1: Environment Verification

The endpoint context was established before beginning the investigation.

```powershell
hostname
whoami
Get-Date
```

Observed environment:

```text
Hostname: DESKTOP-9MMM37V
User: desktop-9mmm37v\dell
Date: 27 August 2026
```

Establishing the hostname, user context, and timestamp provides useful context for subsequent evidence correlation.

---

## Phase 2: Directory Creation

The investigation directory structure was created:

```powershell
New-Item -Path "C:\WMIPermanentEventLab" -ItemType Directory -Force
New-Item -Path "C:\WMIPermanentEventLab\Payload" -ItemType Directory -Force
New-Item -Path "C:\WMIPermanentEventLab\Output" -ItemType Directory -Force
New-Item -Path "C:\WMIPermanentEventLab\Evidence" -ItemType Directory -Force
```

The directories were then verified using:

```powershell
Get-ChildItem "C:\WMIPermanentEventLab"
```

---

## Phase 3: Filesystem Baselining

A baseline was collected before creating the payload and WMI persistence artifacts.

```powershell
Get-ChildItem "C:\WMIPermanentEventLab" -Recurse -Force |
Select-Object FullName, Length, CreationTime, LastWriteTime |
Out-File "C:\WMIPermanentEventLab\Evidence\baseline.txt"
```

The baseline recorded:

- File paths
- File sizes
- Creation timestamps
- Last-write timestamps

This provided a reference point for identifying artifacts introduced during later stages.

---

## Phase 4: Payload Creation

A controlled PowerShell payload was created at:

```text
C:\WMIPermanentEventLab\Payload\wmi-payload.ps1
```

The payload collected:

- Execution time
- Hostname
- User context
- Execution status

The output was written to:

```text
C:\WMIPermanentEventLab\Output\wmi-event-result.txt
```

The payload was inspected and hashed before being used in the WMI subscription.

Example payload logic:

```powershell
$timestamp = Get-Date
$hostname = $env:COMPUTERNAME
$user = whoami

"Execution Time: $timestamp" |
Out-File "C:\WMIPermanentEventLab\Output\wmi-event-result.txt"

"Hostname: $hostname" |
Add-Content "C:\WMIPermanentEventLab\Output\wmi-event-result.txt"

"User: $user" |
Add-Content "C:\WMIPermanentEventLab\Output\wmi-event-result.txt"

"Status: Benign WMI permanent event subscription triggered successfully" |
Add-Content "C:\WMIPermanentEventLab\Output\wmi-event-result.txt"
```

---

## Phase 5: Sysmon File Creation Evidence

Sysmon Event ID 11 was reviewed to identify file creation activity.

The payload file was observed in Sysmon:

```text
C:\WMIPermanentEventLab\Payload\wmi-payload.ps1
```

Relevant details included:

```text
Event ID: 11
Image: C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.5.0_x64__8wekyb3d8bbwe\pwsh.exe
TargetFilename: C:\WMIPermanentEventLab\Payload\wmi-payload.ps1
User: DESKTOP-9MMM37V\Dell
Logged: 27-08-2026 08:01:07
```

This provided endpoint telemetry supporting the payload creation stage.

---

## Phase 6: Existing WMI Subscription Enumeration

Before creating the controlled subscription, existing WMI permanent event subscription objects were enumerated.

### Event Filters

```powershell
Get-CimInstance `
    -Namespace root\subscription `
    -ClassName __EventFilter
```

### Event Consumers

```powershell
Get-CimInstance `
    -Namespace root\subscription `
    -ClassName CommandLineEventConsumer
```

### Filter-to-Consumer Bindings

```powershell
Get-CimInstance `
    -Namespace root\subscription `
    -ClassName __FilterToConsumerBinding
```

A pre-existing WMI event filter and consumer relationship was observed.

This was an important finding because the presence of WMI subscription objects does not automatically indicate malicious persistence.

The analyst must examine the object name, namespace, query, consumer type, command, binding, and expectedness within the environment.

---

## Phase 7: WMI Event Filter Creation

A controlled event filter named:

```text
Lab_WMI_Event_Filter
```

was created.

The filter used:

```text
Namespace: root\cimv2
Query Language: WQL
```

The configured query was:

```sql
SELECT * FROM __InstanceModificationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_OperatingSystem'
```

The event filter represents the trigger component of the persistence mechanism.

---

## Phase 8: Command-Line Event Consumer Creation

A controlled command-line event consumer named:

```text
Lab_WMI_Command_Consumer
```

was created.

The configured command was:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\WMIPermanentEventLab\Payload\wmi-payload.ps1"
```

The consumer represents the execution component.

Important investigation points include:

- Executable being launched
- Command-line arguments
- PowerShell usage
- Execution policy configuration
- Referenced payload
- Payload location
- Payload contents
- Expectedness of the activity

---

## Phase 9: Filter-to-Consumer Binding

The filter and consumer were connected using:

```text
__FilterToConsumerBinding
```

The binding connected:

```text
Lab_WMI_Event_Filter
```

to:

```text
Lab_WMI_Command_Consumer
```

This was the key correlation step.

The binding demonstrated that the event condition and execution action were configured to operate together.

Without this relationship, an event filter and a command-line consumer could be investigated independently without establishing a complete persistence chain.

---

## Phase 10: Execution Verification

The payload output was checked after the WMI subscription was configured.

Output file:

```text
C:\WMIPermanentEventLab\Output\wmi-event-result.txt
```

The output contained:

```text
Execution Time: 08/27/2026 08:07:43
Hostname: DESKTOP-9MMM37V
User: nt authority\system
Status: Benign WMI permanent event subscription triggered successfully
```

The result confirmed that the controlled payload executed successfully.

A key finding was the execution context:

```text
NT AUTHORITY\SYSTEM
```

This demonstrated why execution context must be independently verified during persistence investigations.

---

## Sysmon Process Creation Evidence

Sysmon Event ID 1 was reviewed for process creation activity.

PowerShell process creation was observed:

```text
Event ID: 1
Image: C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe
User: SYSTEM
Computer: DESKTOP-9MMM37V
Logged: 27-08-2026 08:09:00
```

This provided supporting endpoint evidence for the PowerShell execution stage.

The process creation event should be correlated with the WMI consumer, binding, payload path, and execution output rather than interpreted in isolation.

---

## Phase 11: WMI Evidence Collection

The three primary WMI subscription components were exported for forensic review.

### Event Filter Evidence

```powershell
Get-CimInstance `
    -Namespace root\subscription `
    -ClassName __EventFilter |
Format-List * |
Out-File "C:\WMIPermanentEventLab\Evidence\event-filters.txt"
```

### Event Consumer Evidence

```powershell
Get-CimInstance `
    -Namespace root\subscription `
    -ClassName CommandLineEventConsumer |
Format-List * |
Out-File "C:\WMIPermanentEventLab\Evidence\event-consumers.txt"
```

### Binding Evidence

```powershell
Get-CimInstance `
    -Namespace root\subscription `
    -ClassName __FilterToConsumerBinding |
Format-List * |
Out-File "C:\WMIPermanentEventLab\Evidence\bindings.txt"
```

The resulting evidence files preserved the WMI subscription structure for offline investigation and documentation.

---

## Phase 12: Wazuh Monitoring Verification

The Wazuh agent associated with the Windows endpoint was checked from the Wazuh environment:

```bash
sudo /var/ossec/bin/agent_control -i 001
```

The agent was reported as active.

Observed information included:

```text
Agent ID: 001
Agent Name: DESKTOP-9MMM37V
Status: Active
Operating System: Microsoft Windows 11 Pro
Client Version: Wazuh v4.12.0
```

This confirmed that the endpoint remained connected to the Wazuh environment during the investigation.

---

## Wazuh Monitoring Observation

A Wazuh alert concerning a listening-port status change was also observed.

The available evidence did not establish that the listening-port change was caused by the WMI permanent event subscription.

Therefore, the alert was treated as a separate monitoring observation rather than direct evidence of the persistence mechanism.

This demonstrates an important SOC investigation principle:

> Temporal proximity does not establish causation.

---

## Key Findings

### Finding 1: WMI Persistence Uses Multiple Objects

The investigation demonstrated that a permanent WMI event subscription is composed of multiple related objects.

### Finding 2: The Event Filter Defines the Trigger

The `__EventFilter` defines the event condition that the WMI subscription monitors.

### Finding 3: The Consumer Defines the Execution Action

The `CommandLineEventConsumer` contains the command that is configured to execute.

### Finding 4: The Binding Establishes the Relationship

The `__FilterToConsumerBinding` connects the event filter and consumer.

### Finding 5: Correlation Is Essential

The complete relationship must be reconstructed as:

```text
Event Filter
    |
    v
Filter-to-Consumer Binding
    |
    v
Command-Line Event Consumer
```

### Finding 6: Execution Context Matters

The resulting payload output identified:

```text
NT AUTHORITY\SYSTEM
```

This showed that the configured action executed under the SYSTEM security context.

### Finding 7: Sysmon Supported the Investigation

Sysmon Event ID 11 provided file creation evidence.

Sysmon Event ID 1 provided process creation evidence.

Together, these events supported the reconstruction of the activity.

### Finding 8: Wazuh Provided Monitoring Context

The Wazuh agent was active during the investigation, but the primary persistence evidence came from endpoint-level WMI and Sysmon investigation.

---

## Investigation Workflow

The investigation followed this sequence:

1. Verify endpoint identity and user context.
2. Create the investigation directory structure.
3. Establish a filesystem baseline.
4. Create and validate the benign payload.
5. Review Sysmon file creation telemetry.
6. Enumerate existing WMI subscriptions.
7. Create the WMI event filter.
8. Create the command-line event consumer.
9. Create the filter-to-consumer binding.
10. Verify payload execution.
11. Determine the execution security context.
12. Review Sysmon process creation telemetry.
13. Export WMI subscription evidence.
14. Verify Wazuh agent connectivity.
15. Separate unrelated monitoring observations from direct evidence.
16. Reconstruct the complete WMI persistence chain.

---

## Investigation Conclusion

The investigation successfully reconstructed a controlled WMI permanent event subscription.

The complete chain was:

```text
Event Condition
      |
      v
__EventFilter
      |
      v
__FilterToConsumerBinding
      |
      v
CommandLineEventConsumer
      |
      v
PowerShell
      |
      v
wmi-payload.ps1
      |
      v
Execution Output
```

The most important lesson is that WMI persistence should not be investigated by looking at a single object in isolation.

An analyst should correlate:

- Event filter
- WMI namespace
- WQL query
- Consumer
- Command line
- Binding
- Payload
- Process creation
- Execution context
- Supporting endpoint telemetry

The lab activity was controlled and benign, but the methodology can be applied to real SOC, DFIR, and threat-hunting investigations involving suspicious WMI persistence.

---

## Skills Demonstrated

- Windows DFIR
- WMI investigation
- Persistence analysis
- PowerShell investigation
- Sysmon Event ID 1 analysis
- Sysmon Event ID 11 analysis
- Evidence collection
- Timeline reconstruction
- Endpoint telemetry correlation
- Wazuh monitoring
- Threat hunting
- SOC investigation methodology
