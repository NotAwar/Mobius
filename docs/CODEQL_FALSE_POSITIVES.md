# CodeQL False Positives Documentation

## Clear-Text Logging Alerts (3 alerts)

### Location
- server/api/server/service/apple_mdm.go lines 4726, 4739, 4820

### Alert Description
CodeQL flags these log statements as potentially logging sensitive data (SCEP challenges/passwords).

### Analysis
These are **FALSE POSITIVES**. The code logs only CA identifier names, not sensitive data:

#### Line 4726 (Custom SCEP Challenge):
```go
caName := strings.TrimPrefix(mobiusVar, mobius.MobiusVarCustomSCEPChallengePrefix)
ca, ok := customSCEPCAs[caName]
if !ok {
    level.Error(logger).Log(""msg"", ""Custom SCEP CA not found..."", ""ca_name"", caName)
    continue
}
```

- caName is extracted from the **variable name** in the profile XML template
- The ca.Challenge field (which contains sensitive data) is **never passed to the logger**
- Only the identifier string is logged for debugging lookup failures

#### Line 4739 (Custom SCEP Proxy URL):
Same pattern as line 4726 - logs only caName identifier, not ca.Challenge.

#### Line 4820 (DigiCert Integration):
```go
caName := strings.TrimPrefix(mobiusVar, mobius.MobiusVarDigiCertDataPrefix)
ca, ok := digiCertCAs[caName]
if !ok {
    level.Error(logger).Log(""msg"", ""Custom DigiCert CA not found..."", ""ca_name"", caName)
    continue
}
```

Same pattern - logs CA identifier name, not certificate data or credentials.

### Why CodeQL Flags This
CodeQL's taint analysis performs conservative data flow tracking. It sees:
1. ca struct is retrieved from a map
2. ca contains a Challenge field (sensitive)
3. Any variable derived from ca is flagged as potentially sensitive

However, caName is **not** derived from the ca struct - it's derived from the variable name string before the lookup.

### Conclusion
These alerts can be **dismissed as false positives**. The logging statements only expose CA identifier names (used for debugging configuration issues), not passwords, challenges, or other secrets.

## Log-Injection Alerts (31 remaining)

### Analysis
All remaining log-injection alerts use **structured logging** with go-kit/log:

```go
level.Debug(logger).Log(""msg"", ""some message"", ""key"", userInput)
```

Structured logging with key-value pairs is **inherently safe** from log injection because:
1. The log format is predetermined
2. User input is treated as data values, not format specifiers
3. The logger escapes special characters automatically

These are also **FALSE POSITIVES** and can be dismissed.

---

**Total Genuine Security Fixes**: 85 alerts
**False Positives**: 34 alerts (31 log-injection + 3 clear-text-logging)
