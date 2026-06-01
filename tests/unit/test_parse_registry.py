"""Unit tests for parse_registry + persistence helpers."""
from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from oath.mcp.evidence_handle import EvidenceHandle
from oath.mcp.tools.parse_registry import (
    PTH_PERSISTENCE_PLUGINS,
    RECMD_VERSION,
    RegistryFinding,
    _hash_plugin_pack,
    filter_persistence_findings,
    find_tarrask_candidates,
    parse_registry,
    reverify,
)
from oath.receipt.notarized import SigningContext, verify_signature


# Five rows mixing high-signal persistence plugins with one benign UserAssist
# entry. The TaskCache row has "orphan" in its description — that's the
# Tarrask signature we detect deterministically below.
SAMPLE_CSV = b"""HivePath,HiveType,Description,Category,KeyPath,ValueName,ValueType,ValueData,Comment,LastWriteTimestamp
C:\\Windows\\System32\\config\\SOFTWARE,SOFTWARE,RunKeys,Persistence,Microsoft\\Windows\\CurrentVersion\\Run,EvilUpdater,RegSz,C:\\Users\\Public\\bad.exe,user-writable path,2026-04-12T14:30:00
C:\\Windows\\System32\\config\\SOFTWARE,SOFTWARE,TaskCache,Persistence,Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\OrphanedTask,,,orphan-no-Tasks-entry-found,Tarrask signature,2026-04-12T14:31:00
C:\\Windows\\System32\\config\\SYSTEM,SYSTEM,Services,Persistence,ControlSet001\\Services\\PSEXESVC,ImagePath,RegSz,%SystemRoot%\\PSEXESVC.exe,PsExec lateral movement service,2026-04-12T14:32:00
C:\\Users\\jdoe\\NTUSER.DAT,NTUSER,UserAssist,Execution,Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count,{F38BF404-1D43-42F2-9305-67DE0B28FC23}\\Microsoft\\Windows\\notepad.exe,RegBinary,run_count=12,benign typical user,2026-04-12T13:55:00
C:\\Users\\jdoe\\NTUSER.DAT,NTUSER,RecentDocs,Other,Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs,Item1,RegBinary,benign-docs-list,not in persistence set,2026-04-12T12:00:00
"""


@dataclass
class FakeExecutor:
    payload: bytes
    calls: list[list[str]] = None

    def __post_init__(self) -> None:
        self.calls = []

    def run(self, argv: list[str], *, capture: bool = True, timeout: float = 300) -> bytes:
        self.calls.append(list(argv))
        # RECmd 2026.5.0 writes to `--csv <dir> --csvf <file>`; mirror that.
        if "--csv" in argv and "--csvf" in argv:
            csv_idx = argv.index("--csv")
            csvf_idx = argv.index("--csvf")
            if csv_idx + 1 < len(argv) and csvf_idx + 1 < len(argv):
                outpath = Path(argv[csv_idx + 1]) / argv[csvf_idx + 1]
                outpath.parent.mkdir(parents=True, exist_ok=True)
                outpath.write_bytes(self.payload)
        return self.payload


@pytest.fixture
def ctx() -> SigningContext:
    with tempfile.TemporaryDirectory() as tmp:
        yield SigningContext.load_or_mint(Path(tmp), run_id="test-registry")


@pytest.fixture
def handle(tmp_path: Path) -> EvidenceHandle:
    img = tmp_path / "dummy.E01"
    img.write_bytes(b"\x00" * 1024)
    return EvidenceHandle(
        image_path=img,
        image_sha256="a" * 64,
        image_size_bytes=1024,
        mount_point=tmp_path,
        mount_tech="raw-file",
        run_id="registry-run",
    )


@pytest.fixture
def hive_file(tmp_path: Path) -> Path:
    p = tmp_path / "SOFTWARE"
    p.write_bytes(b"REGISTRY_PLACEHOLDER" * 8)
    return p


@pytest.fixture
def plugins_dir(tmp_path: Path) -> Path:
    d = tmp_path / "RECmd-Plugins"
    d.mkdir()
    (d / "RunKeys.reb").write_text("Description: RunKeys")
    (d / "TaskCache.reb").write_text("Description: TaskCache")
    return d


# --------------------------------------------------------------------------- #
# Round-trip + envelope provenance                                            #
# --------------------------------------------------------------------------- #


def test_round_trip_verifies(ctx, handle, hive_file, plugins_dir):
    env = parse_registry(
        handle,
        hive_path=hive_file,
        hive_label="SOFTWARE",
        plugins_dir=plugins_dir,
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    assert verify_signature(env, ctx.public_key) is True
    assert env.header.tool_name == "parse_registry"
    assert env.header.tool_version == RECMD_VERSION
    assert env.header.image_sha256 == handle.image_sha256


def test_findings_parsed_with_typed_fields(ctx, handle, hive_file):
    env = parse_registry(
        handle,
        hive_path=hive_file,
        hive_label="SOFTWARE",
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    runkey = next(f for f in env.data if f.plugin == "RunKeys")
    assert runkey.hive == "SOFTWARE"
    assert runkey.value_name == "EvilUpdater"
    assert "bad.exe" in (runkey.value_data or "")
    assert runkey.last_write_ts == "2026-04-12T14:30:00"


def test_plugin_filter_keeps_only_matching(ctx, handle, hive_file):
    env = parse_registry(
        handle,
        hive_path=hive_file,
        hive_label="SOFTWARE",
        plugin_filter=["RunKeys", "Services"],
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    plugins = {f.plugin for f in env.data}
    assert plugins == {"RunKeys", "Services"}


# --------------------------------------------------------------------------- #
# Plugin-pack hashing (RECmd plugins evolve independently)                    #
# --------------------------------------------------------------------------- #


def test_plugin_pack_hash_is_deterministic(plugins_dir):
    h1 = _hash_plugin_pack(plugins_dir)
    h2 = _hash_plugin_pack(plugins_dir)
    assert h1 == h2
    assert len(h1) == 64


def test_plugin_pack_hash_changes_on_modification(plugins_dir):
    h1 = _hash_plugin_pack(plugins_dir)
    (plugins_dir / "Services.reb").write_text("Description: Services")
    h2 = _hash_plugin_pack(plugins_dir)
    assert h1 != h2


def test_reverify_detects_plugin_pack_drift(ctx, handle, hive_file, plugins_dir):
    env = parse_registry(
        handle,
        hive_path=hive_file,
        hive_label="SOFTWARE",
        plugins_dir=plugins_dir,
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    # Operator updates the plugin pack between mint and verify.
    (plugins_dir / "Newplugin.reb").write_text("Description: New")
    ok, reason = reverify(
        env,
        hive_path=hive_file,
        plugins_dir=plugins_dir,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    assert ok is False
    assert "plugin pack" in reason.lower()


def test_reverify_detects_stdout_drift(ctx, handle, hive_file, plugins_dir):
    env = parse_registry(
        handle,
        hive_path=hive_file,
        hive_label="SOFTWARE",
        plugins_dir=plugins_dir,
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    tampered = SAMPLE_CSV.replace(b"bad.exe", b"good.exe")
    ok, reason = reverify(
        env,
        hive_path=hive_file,
        plugins_dir=plugins_dir,
        executor=FakeExecutor(payload=tampered),
    )
    assert ok is False
    assert "drift" in reason.lower()


# --------------------------------------------------------------------------- #
# Persistence + Tarrask helpers                                               #
# --------------------------------------------------------------------------- #


def test_filter_persistence_findings_drops_benign(ctx, handle, hive_file):
    env = parse_registry(
        handle,
        hive_path=hive_file,
        hive_label="SOFTWARE",
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    persistence = filter_persistence_findings(env.data)
    plugins = {f.plugin for f in persistence}
    # RunKeys, TaskCache, Services, UserAssist all in PTH_PERSISTENCE_PLUGINS.
    # RecentDocs is NOT.
    assert "RunKeys" in plugins
    assert "TaskCache" in plugins
    assert "Services" in plugins
    assert "UserAssist" in plugins
    assert "RecentDocs" not in plugins


def test_tarrask_detector_flags_orphaned_taskcache_entries(ctx, handle, hive_file):
    env = parse_registry(
        handle,
        hive_path=hive_file,
        hive_label="SOFTWARE",
        ctx=ctx,
        executor=FakeExecutor(payload=SAMPLE_CSV),
    )
    tarrask = find_tarrask_candidates(env.data)
    # Exactly one TaskCache row in the fixture has the "orphan" sentinel.
    assert len(tarrask) == 1
    assert tarrask[0].plugin == "TaskCache"
    assert "orphan" in tarrask[0].value_data.lower()


def test_pth_persistence_plugins_includes_canonical_set():
    for must_have in ("RunKeys", "Services", "TaskCache", "UserAssist", "BAM"):
        assert must_have in PTH_PERSISTENCE_PLUGINS
