# WinCkpt: Transparent Checkpoint-Restart for Windows x64

WinCkpt provides user-level checkpoint-restart for Windows x64 processes. A program run
under WinCkpt can be checkpointed to a file mid-execution and later restarted from that
point in a new process.

It follows the split-process design of MANA.

## Building

Visual Studio 2026, x64. From the repo root, in a developer prompt:

```
MSBuild WinCkpt.slnx -p:Configuration=Release -p:Platform=x64
```

Binaries are placed in `build\bin\x64\Release\`.

## Usage

```
winckpt.exe      launch the target program under WinCkpt
dumpckpt.exe     inspect and verify a checkpoint image
```

## Status

WinCkpt currently checkpoints single-threaded C programs. Restart is under active
development, with multithreading and handle support to follow.

## References

- DMTCP: https://github.com/dmtcp/dmtcp
  J. Ansel, K. Arya, G. Cooperman. *DMTCP: Transparent Checkpointing for Cluster
  Computations and the Desktop.* IPDPS 2009.
- MANA: https://github.com/mpickpt/mana
  R. Garg, G. Price, G. Cooperman. *MANA for MPI: MPI-Agnostic Network-Agnostic
  Transparent Checkpointing.* HPDC 2019.
