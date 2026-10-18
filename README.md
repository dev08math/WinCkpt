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
winckpt.exe [-v] [-k] [--ckptdir DIR] [--] <program> [args...]
restarter.exe [-v] [-k] <ckpt.wckpt>
dumpckpt.exe <ckpt.wckpt>

-v               verbose output
-k               exit once the checkpoint is written
--ckptdir DIR    where checkpoints go (env WINCKPT_CHECKPOINT_DIR, default .)
```

The program receives `args` as its own command line. Its checkpoint is
`ckpt_<program>_<pid>.wckpt`; a restarted program writes its next checkpoint to the same
file. A checkpoint, a restart, a second checkpoint and a second restart:

```
cd build\bin\x64\Release
winckpt.exe -k app.exe
restarter.exe -k ckpt_app_<pid>.wckpt
restarter.exe ckpt_app_<pid>.wckpt
```

The combined output is identical to an uninterrupted run.

## Status

WinCkpt checkpoints and restarts single-threaded C programs, including after a reboot; a
restarted program can checkpoint again. Open files and other kernel objects,
multithreading, and an external checkpoint trigger are in progress.

## References

- DMTCP: https://github.com/dmtcp/dmtcp
  J. Ansel, K. Arya, G. Cooperman. *DMTCP: Transparent Checkpointing for Cluster
  Computations and the Desktop.* IPDPS 2009.
- MANA: https://github.com/mpickpt/mana
  R. Garg, G. Price, G. Cooperman. *MANA for MPI: MPI-Agnostic Network-Agnostic
  Transparent Checkpointing.* HPDC 2019.
