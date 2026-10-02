#!/usr/bin/env python3
"""The full gate admits each phase against the reserve and cancellation margin."""
from __future__ import annotations

import sys
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ci


def main() -> None:
    gib = 1024**3
    assert ci.DISK_FLOOR_BYTES == 5 * gib
    assert ci.DISK_CANCEL_TRIGGER_BYTES == 6 * gib
    assert ci.DISK_CANCELLATION_HEADROOM_BYTES == 1 * gib
    assert ci.DISK_DEFAULT_PHASE_PEAK_BYTES == 1 * gib
    assert ci.DISK_BUILDKIT_BOOTSTRAP_PEAK_BYTES == 2 * gib
    assert ci.DISK_NORMAL_WALLET_PEAK_BYTES == 5 * gib
    assert ci.DISK_HW_WALLET_INCREMENTAL_PEAK_BYTES == 2 * gib
    assert ci.DISK_TOR_IMAGE_PEAK_BYTES == gib + gib // 2
    assert ci.DISK_AUTH_SESSION_PEAK_BYTES == gib // 2
    assert ci.DISK_CADDY_IMAGE_PEAK_BYTES == 3 * gib
    assert ci.DISK_FAIL2BAN_IMAGE_PEAK_BYTES == gib // 2
    assert ci.DISK_IMAGE_SCAN_PEAK_BYTES == gib
    assert ci.DISK_PHASE_ADMISSIONS_BYTES == {
        "builder_bootstrap": 8 * gib,
        "normal_wallet": 11 * gib,
        "hardware_wallet_incremental": 8 * gib,
        "tor": 7 * gib + gib // 2,
        "auth_session": 7 * gib,
        "caddy": 9 * gib,
        "fail2ban": 7 * gib,
        "image_scans": 7 * gib,
        "runtime_acceptance": 8 * gib,
        "sast": 7 * gib,
    }
    assert not hasattr(ci, "DISK_START_BUDGET_BYTES")

    path_values = {"/checkout": 12 * gib, "/docker-root": 9 * gib}
    with patch.dict(ci.os.environ, {"CI_DISK_PATHS": os.pathsep.join(path_values)}, clear=False), \
         patch.object(ci.shutil, "disk_usage", side_effect=lambda path: SimpleNamespace(free=path_values[str(path)])):
        samples = ci.disk_storage_samples()
        assert samples == [{"path": path, "free_bytes": free} for path, free in path_values.items()]
        assert ci.disk_checkpoint("test monitored paths", persist=False) == 9 * gib

    with patch.object(ci.shutil, "disk_usage", return_value=SimpleNamespace(
            free=ci.DISK_BUILDKIT_BOOTSTRAP_ADMISSION_BYTES - 1)):
        try:
            ci.require_build_capacity("test full-gate preflight", initial=True)
        except ci.ValidationError as error:
            assert str(ci.DISK_BUILDKIT_BOOTSTRAP_ADMISSION_BYTES) in str(error)
        else:
            raise AssertionError("builder bootstrap admitted less than its phase budget")

    with patch.object(ci.shutil, "disk_usage", return_value=SimpleNamespace(free=ci.DISK_FLOOR_BYTES)):
        try:
            ci.require_disk_floor("test exact hard floor")
        except ci.ValidationError as error:
            assert "hard floor" in str(error) or "safety floor" in str(error)
        else:
            raise AssertionError("the hard floor must abort at equality, before crossing it")

    print("PASS phase-specific 5-GiB reserve/6-GiB cancel admissions and strict hard-floor checks")


if __name__ == "__main__":
    main()
