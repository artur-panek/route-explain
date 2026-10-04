from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass


class ContextError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    kind: str = "host"
    value: str | None = None

    @property
    def label(self) -> str:
        return "host" if self.kind == "host" else f"{self.kind}:{self.value}"

    def prefix(self) -> list[str]:
        if self.kind == "host":
            return []
        if self.kind == "netns":
            return ["ip", "netns", "exec", str(self.value)]
        if self.kind == "pid":
            if shutil.which("nsenter") is None:
                raise ContextError("nsenter not found; install util-linux for --pid/--container")
            return ["nsenter", "-t", str(self.value), "-n"]
        raise ContextError(f"unsupported execution context: {self.kind}")


def _container_pid(name: str) -> int:
    for engine in ("docker", "podman"):
        if shutil.which(engine) is None:
            continue
        proc = subprocess.run(
            [engine, "inspect", "--format", "{{.State.Pid}}", name],
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            try:
                pid = int(proc.stdout.strip())
            except ValueError:
                continue
            if pid > 0:
                return pid
    raise ContextError(f"could not resolve running container {name!r} via docker or podman")


def resolve_context(*, netns: str | None = None, pid: int | None = None, container: str | None = None) -> ExecutionContext:
    selected = sum(value is not None for value in (netns, pid, container))
    if selected > 1:
        raise ContextError("choose only one of --netns, --pid, or --container")
    if netns is not None:
        return ExecutionContext("netns", netns)
    if pid is not None:
        if pid <= 0:
            raise ContextError("PID must be greater than zero")
        return ExecutionContext("pid", str(pid))
    if container is not None:
        return ExecutionContext("pid", str(_container_pid(container)))
    return ExecutionContext()


def run_text(context: ExecutionContext, argv: list[str], *, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*context.prefix(), *argv],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def run_json(context: ExecutionContext, argv: list[str]) -> object:
    proc = run_text(context, argv)
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"exit code {proc.returncode}"
        raise ContextError(f"{' '.join(argv)} failed in {context.label}: {detail}")
    try:
        return json.loads(proc.stdout or "null")
    except json.JSONDecodeError as exc:
        raise ContextError(f"{' '.join(argv)} returned invalid JSON in {context.label}") from exc
