from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
CLINGO_DIR = BASE_DIR / "Clingo"
TESTCASE = BASE_DIR / "testCases" / "testCase9_inst.lp"
SECURITY_FEATURES = CLINGO_DIR / "security_features_inst.lp"
TARGET_SYSTEM = CLINGO_DIR / "tgt_system_tc9_inst.lp"
OUTPUT_DZN = BASE_DIR / "minizinc" / "tc9_phase1.dzn"


@dataclass
class Tc9MiniZincData:
    text: str


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _ordered_symbols(text: str, predicate: str) -> list[str]:
    pattern = re.compile(rf"{re.escape(predicate)}\(([^)]+)\)\s*\.")
    return [match.group(1).strip() for match in pattern.finditer(text)]


def _fact3_ints(text: str, predicate: str) -> dict[tuple[str, str], int]:
    pattern = re.compile(rf"{re.escape(predicate)}\(([^,]+),\s*([^,]+),\s*(-?\d+)\)\s*\.")
    return {(m.group(1).strip(), m.group(2).strip()): int(m.group(3)) for m in pattern.finditer(text)}


def _fact2_ints(text: str, predicate: str) -> dict[str, int]:
    pattern = re.compile(rf"{re.escape(predicate)}\(([^,]+),\s*(-?\d+)\)\s*\.")
    return {m.group(1).strip(): int(m.group(2)) for m in pattern.finditer(text)}


def _system_caps(text: str) -> dict[str, int]:
    return _fact2_ints(text, "system_capability")


def _components(testcase_text: str) -> list[str]:
    match = re.search(r"component\(([^)]+)\)\s*\.", testcase_text)
    if not match:
        raise ValueError("component(...) declaration not found")
    return [part.strip() for part in match.group(1).split(";")]


def _per_component_action_values(testcase_text: str, predicate: str, components: list[str]) -> tuple[list[int], list[int]]:
    pattern = re.compile(rf"{re.escape(predicate)}\(([^,]+),\s*(read|write),\s*(-?\d+)\)\s*\.")
    values = {(m.group(1).strip(), m.group(2).strip()): int(m.group(3)) for m in pattern.finditer(testcase_text)}
    read_vals: list[int] = []
    write_vals: list[int] = []
    for comp in components:
        asset = f"{comp}r1"
        read_vals.append(values[(asset, "read")])
        write_vals.append(values[(asset, "write")])
    return read_vals, write_vals


def _group_data(testcase_text: str, components: list[str]) -> tuple[list[int], list[list[int]], list[int]]:
    pattern = re.compile(r"redundant_group\((\d+),\s*([^)]+)\)\s*\.")
    groups: dict[int, list[str]] = {}
    for match in pattern.finditer(testcase_text):
        gid = int(match.group(1))
        comp = match.group(2).strip()
        groups.setdefault(gid, [])
        if comp not in groups[gid]:
            groups[gid].append(comp)
    ordered_group_ids = sorted(groups)
    max_group_size = max((len(groups[gid]) for gid in ordered_group_ids), default=0)
    comp_index = {name: idx + 1 for idx, name in enumerate(components)}
    component_group = [0] * len(components)
    group_sizes: list[int] = []
    group_members: list[list[int]] = []
    for gid_pos, gid in enumerate(ordered_group_ids, start=1):
        members = groups[gid]
        group_sizes.append(len(members))
        row = [comp_index[m] for m in members] + [0] * (max_group_size - len(members))
        group_members.append(row)
        for member in members:
            component_group[comp_index[member] - 1] = gid_pos
    return group_sizes, group_members, component_group


def _resource_arrays(features_text: str, security: list[str], logging: list[str], resource: str) -> dict[str, list[int]]:
    facts = _fact3_ints(features_text, resource)
    sec_asset = [facts.get((name, "byAsset"), 0) for name in security]
    sec_component = [facts.get((name, "byComponent"), 0) for name in security]
    sec_base_raw = [facts.get((name, "base"), 0) for name in security]
    log_base_raw = [facts.get((name, "base"), 0) for name in logging]

    if resource == "luts":
        sec_base_once = [facts.get((name, "base"), 0) if name in {"dynamic_mac", "zero_trust"} else 0 for name in security]
        sec_base_per_use = [0 for _ in security]
        log_base_once = [facts.get((name, "base"), 0) if name == "zero_trust_logger" else 0 for name in logging]
        log_base_per_use = [facts.get((name, "base"), 0) if name == "some_logging" else 0 for name in logging]
    else:
        sec_base_once = [0 for _ in security]
        sec_base_per_use = sec_base_raw
        log_base_once = [0 for _ in logging]
        log_base_per_use = log_base_raw

    return {
        f"sec_{resource}_asset": sec_asset,
        f"sec_{resource}_component": sec_component,
        f"sec_{resource}_base_once": sec_base_once,
        f"sec_{resource}_base_per_use": sec_base_per_use,
        f"log_{resource}_base_once": log_base_once,
        f"log_{resource}_base_per_use": log_base_per_use,
    }


def _power_arrays(features_text: str, security: list[str], logging: list[str]) -> dict[str, list[int]]:
    facts = _fact3_ints(features_text, "power_cost")
    return {
        "sec_power_asset": [facts.get((name, "byAsset"), 0) for name in security],
        "sec_power_component": [facts.get((name, "byComponent"), 0) for name in security],
        "sec_power_base_once": [0 for _ in security],
        "sec_power_base_per_use": [facts.get((name, "base"), 0) for name in security],
        "log_power_base_once": [0 for _ in logging],
        "log_power_base_per_use": [facts.get((name, "base"), 0) for name in logging],
    }


def _emit_array(name: str, values: list[int | str]) -> str:
    if values and isinstance(values[0], str):
        body = ", ".join(f'"{value}"' for value in values)
    else:
        body = ", ".join(str(value) for value in values)
    return f"{name} = [{body}];"


def _emit_array2d(name: str, rows: list[list[int]]) -> str:
    if not rows:
        return f"{name} = array2d(1..0, 1..0, []);"
    flat = [str(item) for row in rows for item in row]
    return f"{name} = array2d(1..{len(rows)}, 1..{len(rows[0])}, [{', '.join(flat)}]);"


def build_tc9_phase1_dzn() -> Tc9MiniZincData:
    testcase_text = _read(TESTCASE)
    features_text = _read(SECURITY_FEATURES)
    target_text = _read(TARGET_SYSTEM)

    components = _components(testcase_text)
    security = _ordered_symbols(features_text, "security_feature")
    logging = _ordered_symbols(features_text, "logging_feature")
    vulnerability = _fact2_ints(features_text, "vulnerability")
    logging_score = _fact2_ints(features_text, "logging")
    latency = _fact2_ints(features_text, "latency_cost")
    caps = _system_caps(target_text)

    impact_read, impact_write = _per_component_action_values(testcase_text, "impact", components)
    allow_read, allow_write = _per_component_action_values(testcase_text, "allowable_latency", components)
    group_sizes, group_members, component_group = _group_data(testcase_text, components)

    arrays: dict[str, list[int] | list[str]] = {
        "component_name": components,
        "security_name": security,
        "logging_name": logging,
        "impact_read": impact_read,
        "impact_write": impact_write,
        "allowable_latency_read": allow_read,
        "allowable_latency_write": allow_write,
        "component_group": component_group,
        "vulnerability": [vulnerability[name] for name in security],
        "security_latency": [latency[name] for name in security],
        "logging_score": [logging_score[name] for name in logging],
        "logging_latency": [latency[name] for name in logging],
    }

    for resource in ["luts", "ffs", "dsps", "lutram", "bufg", "bram"]:
        arrays.update(_resource_arrays(features_text, security, logging, resource))
    arrays.update(_power_arrays(features_text, security, logging))

    lines = [
        "% Auto-generated tc9 Phase 1 data for MiniZinc",
        f"n_components = {len(components)};",
        f"n_security = {len(security)};",
        f"n_logging = {len(logging)};",
        f"n_groups = {len(group_sizes)};",
        f"max_group_size = {max((len(row) for row in group_members), default=0)};",
        "mu = 25;",
        "omega = 1000;",
    ]
    for key in ["component_name", "security_name", "logging_name"]:
        lines.append(_emit_array(key, arrays[key]))  # type: ignore[arg-type]
    for key in [
        "impact_read",
        "impact_write",
        "allowable_latency_read",
        "allowable_latency_write",
        "component_group",
        "vulnerability",
        "security_latency",
        "logging_score",
        "logging_latency",
        "sec_luts_asset",
        "sec_luts_component",
        "sec_luts_base_once",
        "sec_luts_base_per_use",
        "log_luts_base_once",
        "log_luts_base_per_use",
        "sec_ffs_asset",
        "sec_ffs_component",
        "sec_ffs_base_once",
        "sec_ffs_base_per_use",
        "log_ffs_base_once",
        "log_ffs_base_per_use",
        "sec_dsps_asset",
        "sec_dsps_component",
        "sec_dsps_base_once",
        "sec_dsps_base_per_use",
        "log_dsps_base_once",
        "log_dsps_base_per_use",
        "sec_lutram_asset",
        "sec_lutram_component",
        "sec_lutram_base_once",
        "sec_lutram_base_per_use",
        "log_lutram_base_once",
        "log_lutram_base_per_use",
        "sec_bufg_asset",
        "sec_bufg_component",
        "sec_bufg_base_once",
        "sec_bufg_base_per_use",
        "log_bufg_base_once",
        "log_bufg_base_per_use",
        "sec_bram_asset",
        "sec_bram_component",
        "sec_bram_base_once",
        "sec_bram_base_per_use",
        "log_bram_base_once",
        "log_bram_base_per_use",
        "sec_power_asset",
        "sec_power_component",
        "sec_power_base_once",
        "sec_power_base_per_use",
        "log_power_base_once",
        "log_power_base_per_use",
    ]:
        lines.append(_emit_array(key, arrays[key]))  # type: ignore[arg-type]

    lines.append(_emit_array("group_size", group_sizes))
    lines.append(_emit_array2d("group_member", group_members))
    for cap_name in ["max_power", "max_luts", "max_ffs", "max_dsps", "max_lutram", "max_bufg", "max_bram", "max_asset_risk"]:
        lines.append(f"{cap_name} = {caps[cap_name]};")

    return Tc9MiniZincData(text="\n".join(lines) + "\n")


def write_tc9_phase1_dzn(output_path: Path = OUTPUT_DZN) -> Path:
    data = build_tc9_phase1_dzn()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(data.text, encoding="utf-8")
    return output_path


if __name__ == "__main__":
    path = write_tc9_phase1_dzn()
    print(path)
