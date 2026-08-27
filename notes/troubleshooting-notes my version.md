# Troubleshooting Notes

## 1. Pre-Existing WMI Subscription Objects Were Present

Before creating the controlled subscription, existing WMI objects were enumerated.

An existing WMI event filter and binding were observed:

```text
SCM Event Log Filter
        |
        v
SCM Event Log Consumer
```

This demonstrated that WMI subscriptions can already exist on a normal Windows system.

### Investigation Lesson

Do not automatically classify every WMI event filter or consumer as malicious.

Instead, investigate:

- Object name
- WMI namespace
- Query
- Consumer type
- Command
- Binding
- Referenced payload
- Expectedness in the environment

---

## 2. Individual WMI Objects Do Not Explain the Complete Mechanism

An event filter by itself identifies a trigger condition but does not reveal the complete execution action.

Similarly, a command-line event consumer identifies an execution command but does not establish what event causes that command to run.

The critical correlation object is:

```text
__FilterToConsumerBinding
```

The investigation therefore needs to establish:

```text
__EventFilter
        |
        v
__FilterToConsumerBinding
        |
        v
CommandLineEventConsumer
```

### Investigation Lesson

Always investigate the filter, consumer, and binding together.

---

## 3. Targeted Filtering Makes WMI Investigation Easier

WMI namespaces can contain multiple objects.

Broad enumeration can produce unrelated or pre-existing artifacts.

Once the controlled object names are known, targeted filtering can reduce noise.

Example:

```powershell
Get-CimInstance `
    -Namespace root\subscription `
    -ClassName __EventFilter |
Where-Object {
    $_.Name -eq "Lab_WMI_Event_Filter"
}
```

The same technique can be applied to the command-line consumer.

Example:

```powershell
Get-CimInstance `
    -Namespace root\subscription `
    -ClassName CommandLineEventConsumer |
Where-Object {
    $_.Name -eq "Lab_WMI_Command_Consumer"
}
```

### Investigation Lesson

Use broad enumeration during discovery, then use targeted filtering during analysis.

---

## 4. Sysmon Event ID 11 Confirmed Payload Creation

Sysmon Event ID 11 captured creation of:

```text
C:\WMIPermanentEventLab\Payload\wmi-payload.ps1
```

The event showed PowerShell as the creating process.

### Important Limitation

Event ID 11 proves that a file was created.

It does not prove that the file was executed through WMI persistence.

Therefore, the file creation event must be correlated with:

- WMI filter
- WMI consumer
- Binding
- Process creation
- Payload output

### Investigation Lesson

File creation telemetry is supporting evidence, not complete proof of the persistence mechanism.

---

## 5. Sysmon Event ID 1 Confirmed PowerShell Process Creation

Sysmon Event ID 1 captured:

```text
C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe
```

under:

```text
SYSTEM
```

### Important Limitation

A process creation event alone does not explain why PowerShell was launched.

The analyst should correlate the process event with:

```text
Command-Line Event Consumer
+
Configured Command
+
Payload Path
+
WMI Binding
+
Execution Output
```

### Investigation Lesson

Process telemetry must be interpreted within the surrounding execution chain.

---

## 6. Execution Context Was Different From the Initial User

The lab was initialized under:

```text
desktop-9mmm37v\dell
```

The payload output recorded:

```text
nt authority\system
```

This difference is an important investigation observation.

### Investigation Lesson

Do not assume:

```text
Artifact Creator = Process Executor
```

The security context of the resulting execution should always be independently verified.

Useful evidence sources include:

- Payload output
- Sysmon Event ID 1
- Windows Security logs
- Process ownership
- Parent process information
- WMI configuration

---

## 7. ExecutionPolicy Bypass Requires Context

The configured consumer command contained:

```text
-ExecutionPolicy Bypass
```

This should be treated as an investigation indicator.

However, the presence of the argument alone should not automatically result in a malicious verdict.

The analyst should investigate:

- Script location
- Script contents
- User context
- Process context
- Parent process
- Network activity
- Persistence mechanism
- Organization-approved automation
- Expected administrative activity

In this lab, the command was intentionally configured as part of a controlled simulation.

### Investigation Lesson

Suspicious command-line indicators require contextual analysis.

---

## 8. WMI Persistence Requires Execution Verification

Finding a filter, consumer, and binding demonstrates configuration.

It does not automatically prove that the configured action executed.

The lab therefore used an output artifact:

```text
C:\WMIPermanentEventLab\Output\wmi-event-result.txt
```

The output confirmed:

```text
Execution Time: 08/27/2026 08:07:43
Hostname: DESKTOP-9MMM37V
User: nt authority\system
Status: Benign WMI permanent event subscription triggered successfully
```

### Investigation Lesson

Whenever possible, establish both:

```text
Configuration Evidence
+
Execution Evidence
```

---

## 9. Wazuh Agent Was Active

The Wazuh agent was verified using:

```bash
sudo /var/ossec/bin/agent_control -i 001
```

The result showed:

```text
Agent ID: 001
Agent Name: DESKTOP-9MMM37V
Status: Active
Operating system: Microsoft Windows 11 Pro
Client version: Wazuh v4.12.0
```

This confirmed active monitoring connectivity.

---

## 10. Wazuh Did Not Provide the Primary Persistence Evidence

Although the Wazuh agent was active, the primary evidence for the WMI persistence investigation came from:

- PowerShell
- WMI enumeration
- Sysmon Event ID 11
- Sysmon Event ID 1
- Payload output
- WMI evidence exports

### Investigation Lesson

An active SIEM agent does not guarantee that every persistence mechanism will appear as a dedicated alert.

Endpoint-level investigation may still be required.

---

## 11. Listening-Port Alert Was Not Directly Attributed to WMI Persistence

A Wazuh alert reported a change in listening-port status.

The available evidence showed:

```text
Listened ports status (netstat) changed
(new port opened or closed)
```

The evidence did not establish a causal relationship between that alert and the WMI permanent event subscription.

Therefore, the alert was treated separately.

### Investigation Lesson

Do not force unrelated alerts into an investigation simply because they occurred within the same general time period.

A correlation requires supporting evidence.

---

## 12. Evidence Collection Should Include All Three WMI Components

The investigation exported:

```text
event-filters.txt
event-consumers.txt
bindings.txt
```

This is preferable to collecting only the consumer command.

The complete WMI mechanism should be represented as:

```text
Trigger
    +
Binding
    +
Execution Action
```

### Investigation Lesson

Preserve the complete relationship, not only the most suspicious-looking object.

---

## 13. Baseline Collection Was Important

The investigation created:

```text
C:\WMIPermanentEventLab\Evidence\baseline.txt
```

before creating the payload and persistence artifacts.

The baseline captured:

- Full path
- File size
- Creation time
- Last-write time

### Investigation Lesson

A baseline makes it easier to distinguish:

```text
Pre-existing State
```

from:

```text
Investigation-Created Artifacts
```

This is especially useful when working in environments containing existing system artifacts.

---

## 14. Payload Validation Was Useful

The payload was inspected before being used.

Its file properties were also reviewed:

```text
Path:
C:\WMIPermanentEventLab\Payload\wmi-payload.ps1
```

The captured file size was:

```text
479 bytes
```

The file was also hashed.

### Investigation Lesson

When creating controlled investigation artifacts, validate and document them before execution.

This helps distinguish intentional lab activity from unexpected changes.

---

## 15. Important Correlation Rule

The investigation can be reduced to the following analytical model:

```text
WMI Configuration
        |
        v
Event Filter
        |
        v
Binding
        |
        v
Consumer
        |
        v
Configured Command
        |
        v
Process Creation
        |
        v
Payload Execution
        |
        v
Execution Artifact
```

Each stage provides a different type of evidence.

The more stages that can be independently correlated, the stronger the investigation conclusion becomes.

---

nstrated that the strongest evidence comes from combining configuration artifacts with actual execution telemetry.

The controlled WMI subscription was successfully reconstructed and verified, while unrelated monitoring activity was deliberately kept separate from the persistence finding.
