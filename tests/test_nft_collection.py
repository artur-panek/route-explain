import subprocess
import sys
import time

import pytest

from route_explain import nfttrace
from route_explain.context import ExecutionContext
from route_explain.model import Flow

PACKET = (
    'trace id a123 inet filter output packet: oif "eth0" '
    'ip saddr 192.0.2.1 ip daddr 198.51.100.1 ip protocol tcp '
    'tcp sport 12345 tcp dport 443'
)
RULE = 'trace id a123 inet filter output rule meta mark set 0x42 (verdict continue)'
MARK = 'trace id a123 inet filter output verdict continue mark 0x42'
FLOW = Flow(destination="198.51.100.1", protocol="tcp", destination_port=443)


@pytest.fixture
def producer(monkeypatch):
    real_popen = subprocess.Popen
    children = []

    def install(script):
        def start(argv, **kwargs):
            assert argv == ["nft", "monitor", "trace"]
            child = real_popen([sys.executable, "-u", "-c", script], **kwargs)
            children.append(child)
            return child

        monkeypatch.setattr(nfttrace.shutil, "which", lambda name: "/fake/nft")
        monkeypatch.setattr(nfttrace.subprocess, "Popen", start)
        return children

    yield install
    for child in children:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=1)
        for stream in (child.stdout, child.stderr):
            if stream is not None:
                stream.close()


def test_collects_a_burst_before_the_producer_becomes_idle(producer):
    payload = "\n".join([PACKET, RULE, MARK]) + "\n"
    children = producer(f"import os,time; os.write(1, {payload.encode()!r}); time.sleep(10)")

    events = nfttrace.collect_nft_trace(FLOW, ExecutionContext(), seconds=0.3)

    assert [event["type"] for event in events] == ["packet", "rule", "verdict"]
    assert events[-1]["mark"] == 0x42
    assert children[0].poll() is not None
    assert children[0].stdout.closed
    assert children[0].stderr.closed


def test_drains_output_when_the_producer_exits_immediately(producer):
    payload = "\n".join([PACKET, RULE, MARK])
    producer(f"import os; os.write(1, {payload.encode()!r})")

    events = nfttrace.collect_nft_trace(FLOW, ExecutionContext(), seconds=2)

    assert [event["raw"] for event in events] == [PACKET, RULE, MARK]


def test_reassembles_records_split_across_reads(producer):
    payload = (PACKET + "\n" + MARK + "\n").encode()
    cut = len(PACKET) // 2
    producer(
        f"import os,time; os.write(1, {payload[:cut]!r}); time.sleep(0.05); "
        f"os.write(1, {payload[cut:]!r})"
    )

    events = nfttrace.collect_nft_trace(FLOW, ExecutionContext(), seconds=2)

    assert [event["raw"] for event in events] == [PACKET, MARK]


def test_an_unfinished_line_does_not_block_the_deadline(producer):
    payload = (PACKET + "\ntrace id a123 inet filter output rule meta mark").encode()
    producer(f"import os,time; os.write(1, {payload!r}); time.sleep(10)")
    started = time.monotonic()

    events = nfttrace.collect_nft_trace(FLOW, ExecutionContext(), seconds=0.3)

    assert time.monotonic() - started < 3
    assert [event["raw"] for event in events] == [PACKET]


def test_stderr_is_drained_while_stdout_is_being_collected(producer):
    payload = (PACKET + "\n" + MARK + "\n").encode()
    producer(f"import os; os.write(2, b'x' * 262144); os.write(1, {payload!r})")

    events = nfttrace.collect_nft_trace(FLOW, ExecutionContext(), seconds=2)

    assert [event["raw"] for event in events] == [PACKET, MARK]


@pytest.mark.parametrize("emit_trace", [False, True])
def test_nonzero_exit_reports_stderr_even_after_matching_events(producer, emit_trace):
    payload = (PACKET + "\n").encode() if emit_trace else b""
    producer(f"import os,sys; os.write(1, {payload!r}); os.write(2, b'monitor failed'); sys.exit(2)")

    with pytest.raises(nfttrace.TraceError, match="monitor failed"):
        nfttrace.collect_nft_trace(FLOW, ExecutionContext(), seconds=2)


def test_nonzero_exit_without_stderr_reports_the_exit_code(producer):
    producer("import sys; sys.exit(3)")

    with pytest.raises(nfttrace.TraceError, match="exit code 3"):
        nfttrace.collect_nft_trace(FLOW, ExecutionContext(), seconds=2)


def test_a_producer_ignoring_termination_is_killed_and_reaped(producer):
    payload = (PACKET + "\n").encode()
    children = producer(
        "import os,signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"os.write(1, {payload!r}); time.sleep(10)"
    )
    started = time.monotonic()

    events = nfttrace.collect_nft_trace(FLOW, ExecutionContext(), seconds=0.3)

    assert time.monotonic() - started < 3.5
    assert [event["raw"] for event in events] == [PACKET]
    assert children[0].poll() is not None


@pytest.mark.parametrize("seconds", [0, -1, float("nan"), float("inf"), 61])
def test_invalid_deadlines_are_rejected_before_starting_a_process(seconds):
    with pytest.raises(nfttrace.TraceError, match="seconds must"):
        nfttrace.collect_nft_trace(FLOW, ExecutionContext(), seconds=seconds)
