# Test-CloneType.ps1

Verifies that VM clones are **FULL** (independent) rather than **LINKED**
(dependent on a parent disk).

| | |
|---|---|
| **Runs on** | Hypervisor host — the machine where the clone folders live |
| **Requires** | Nothing. No cloud CLI, no credentials |
| **Side effects** | None. Read-only |

---

## Why this exists

A linked clone shares its parent's disk. It breaks the moment the source VM is
moved, modified, or deleted — which makes it worthless as a disaster-recovery
master. A full clone is a standalone copy with no dependency.

VMware's clone wizard puts the full-vs-linked choice on the screen *after* the
one most people stop reading at, so getting a linked clone when you wanted a
full one is easy and silent.

## The test

The only reliable signal is inside the `.vmdk` descriptor:

| Clone type | Descriptor contains |
|---|---|
| Linked | `parentFileNameHint` naming its parent disk |
| Full | No parent hint (`parentCID=ffffffff`) |

**Signals that look conclusive but are not.** Each of these appears on perfectly
healthy full clones and led to a wrong diagnosis during this lab's build:

- Disk files named after the *source* VM (e.g. a `-cl1` suffix)
- A 0 KB snapshot metadata stub in the folder
- A `.vmx.lck` lock folder (usually a stale lock from a forced process kill)
- Folder size alone — useful as a cross-check, not as proof

## Performance note

The descriptor is plain text in the first ~40 lines of the `.vmdk`; the rest of
the file is binary disk data. The script reads only the header
(`Get-Content -TotalCount 40`).

An earlier version summed the whole directory tree and scanned entire disks with
`Select-String`. On ~130 GB of split VMDKs that appeared to hang for over ten
minutes. Correct, but unusable — the fix was recognising the minimum sufficient
check rather than scanning everything.

## Usage

```powershell
powershell -ExecutionPolicy Bypass -File .\Test-CloneType.ps1 -Root "<path to golden clone folder>"
```

`-Root` is required — pass the folder that contains one subfolder per cloned VM.
There is deliberately no default: a hardcoded path would point at whoever wrote
the script rather than at the machine running it.

## Output

```
Checking KALI LINUX... FULL
Checking PFSENSE... FULL
Checking WINDOWS 10... FULL
Checking WINDOWS SERVER 2022... FULL

All clones FULL and independent. Golden set valid.
```

Green `FULL` on every VM means the golden set is valid. Any red `LINKED` entry
must be deleted and re-cloned — clone from a **powered-off** source and select
**Create a full clone** on the second wizard screen.

## When to run it

- After creating any new clone, before trusting it as a master
- Before relying on a golden set for recovery
- Any time you're unsure whether a folder is a real independent copy

## Related

- Golden image build procedure: `runbooks/golden-image-restore.md`
