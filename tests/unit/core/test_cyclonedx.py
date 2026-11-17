import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from nettacker.core.cyclonedx import (
    build_cyclonedx_bom,
    build_purl,
    component_from_event,
    parse_json_event,
    scan_root_ref,
    validate_cyclonedx_bom,
    write_cyclonedx_report,
)

SCHEMA_PATH = Path(__file__).parent / "data" / "bom-1.5.schema.json"


def make_event(module_name="port_scan", target="127.0.0.1", json_event=None):
    return {
        "date": "2024-01-01 00:00:00.000000",
        "target": target,
        "module_name": module_name,
        "scan_id": "scan-id",
        "port": 80,
        "event": "detected",
        "json_event": json.dumps(json_event) if json_event is not None else "{}",
    }


def full_metadata_event(**overrides):
    json_event = {
        "name": "OpenSSL",
        "version": "3.0.2",
        "namespace": "Ubuntu/Debian",
        "purl_type": "deb",
        "type": "library",
    }
    json_event.update(overrides)
    return make_event(module_name="ssl_scan", json_event=json_event)


def test_parse_json_event_handles_string_dict_and_garbage():
    assert parse_json_event(make_event(json_event={"a": 1})) == {"a": 1}
    event = make_event()
    event["json_event"] = {"b": 2}
    assert parse_json_event(event) == {"b": 2}
    event["json_event"] = "not-json{"
    assert parse_json_event(event) == {}
    event["json_event"] = None
    assert parse_json_event(event) == {}


def test_build_purl_preserves_case_and_namespace():
    purl = build_purl("DEB", "Ubuntu/Debian", "OpenSSL", "3.0.2-1ubuntu2.15+esm1")
    assert purl == "pkg:deb/Ubuntu/Debian/OpenSSL@3.0.2-1ubuntu2.15+esm1"


def test_build_purl_quotes_reserved_characters():
    purl = build_purl("generic", None, "pkg name/with?chars", "1.0")
    assert purl == "pkg:generic/pkg%20name%2Fwith%3Fchars@1.0"


def test_component_from_event_full_metadata():
    component, missing_fields, dependencies = component_from_event(full_metadata_event())
    assert component["name"] == "OpenSSL"
    assert component["version"] == "3.0.2"
    assert component["type"] == "library"
    assert component["purl"] == "pkg:deb/Ubuntu/Debian/OpenSSL@3.0.2"
    assert component["group"] == "Ubuntu/Debian"
    assert missing_fields == []
    assert dependencies == []


def test_component_from_event_missing_metadata_degrades_to_unknown():
    component, missing_fields, _ = component_from_event(make_event())
    assert component["name"] == "port_scan"
    assert component["version"] == "unknown"
    assert "version" in missing_fields
    assert component["properties"] == [
        {"name": "nettacker:missing_metadata", "value": ",".join(missing_fields)}
    ]


def test_component_from_event_uses_explicit_purl_verbatim():
    event = make_event(json_event={"name": "Lib", "version": "1", "purl": "pkg:npm/Lib@1"})
    component, _, _ = component_from_event(event)
    assert component["purl"] == "pkg:npm/Lib@1"


def test_build_bom_dedup_uses_name_version_purl_triple():
    events = [
        full_metadata_event(),
        full_metadata_event(),
        full_metadata_event(version="1.1.1w"),
        full_metadata_event(purl="pkg:rpm/CentOS/OpenSSL@3.0.2"),
    ]
    bom = build_cyclonedx_bom(events)
    triples = [(c["name"], c["version"], c["purl"]) for c in bom["components"]]
    assert len(triples) == 3
    assert len(set(triples)) == 3


def test_build_bom_keeps_multiple_versions_separate():
    bom = build_cyclonedx_bom(
        [full_metadata_event(version="3.0.2"), full_metadata_event(version="1.1.1w")]
    )
    versions = [c["version"] for c in bom["components"] if c["name"] == "OpenSSL"]
    assert versions == ["1.1.1w", "3.0.2"]


def test_build_bom_expands_same_target_per_module():
    events = [
        full_metadata_event(),
        make_event(
            module_name="http_scan",
            json_event={
                "name": "OpenSSL",
                "version": "3.0.2",
                "namespace": "Ubuntu/Debian",
                "purl_type": "deb",
                "type": "library",
            },
        ),
    ]
    bom = build_cyclonedx_bom(events)
    dependency_refs = [entry["ref"] for entry in bom["dependencies"]]
    assert "module:ssl_scan" in dependency_refs
    assert "module:http_scan" in dependency_refs
    purl = "pkg:deb/Ubuntu/Debian/OpenSSL@3.0.2"
    for module_ref in ("module:ssl_scan", "module:http_scan"):
        entry = next(e for e in bom["dependencies"] if e["ref"] == module_ref)
        assert entry["dependsOn"] == [purl]
    root = next(e for e in bom["dependencies"] if e["ref"] == scan_root_ref)
    assert root["dependsOn"] == ["module:http_scan", "module:ssl_scan"]


def test_build_bom_transitive_dependencies_are_traceable():
    event = full_metadata_event(dependencies=["pkg:deb/Ubuntu/zlib1g@1.2.11"])
    bom = build_cyclonedx_bom([event])
    component_entry = next(
        e for e in bom["dependencies"] if e["ref"] == "pkg:deb/Ubuntu/Debian/OpenSSL@3.0.2"
    )
    assert component_entry["dependsOn"] == ["pkg:deb/Ubuntu/zlib1g@1.2.11"]


def test_build_bom_counts_missing_metadata():
    bom = build_cyclonedx_bom([make_event(), make_event(module_name="other_scan")])
    count_property = bom["metadata"]["properties"][0]
    assert count_property == {
        "name": "nettacker:components_with_missing_metadata",
        "value": "2",
    }


def test_build_bom_output_is_byte_identical_between_runs(tmp_path):
    events = [full_metadata_event(), make_event(), full_metadata_event(version="1.1.1w")]
    first = tmp_path / "first.cdx.json"
    second = tmp_path / "second.cdx.json"
    write_cyclonedx_report(events, first)
    write_cyclonedx_report(list(reversed(events)), second)
    assert first.read_bytes() == second.read_bytes()


def test_build_bom_escapes_non_ascii_names(tmp_path):
    event = make_event(json_event={"name": "表情パッケージ", "version": "1.0"})
    output = tmp_path / "out.cdx.json"
    write_cyclonedx_report([event], output)
    raw = output.read_bytes()
    assert all(byte < 128 for byte in raw)
    assert b"\\u8868\\u60c5" in raw
    bom = json.loads(raw)
    assert bom["components"][0]["name"] == "表情パッケージ"


def test_write_cyclonedx_report_streams_chunks():
    events = [
        full_metadata_event(name="Component{0}".format(index), version=str(index))
        for index in range(3000)
    ]
    written = []

    class ChunkCountingFile:
        def write(self, chunk):
            written.append(chunk)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    with patch("nettacker.core.cyclonedx.Path") as mock_path:
        mock_path.return_value.open.return_value = ChunkCountingFile()
        write_cyclonedx_report(events, "big.cdx.json")
    assert len(written) > len(events)
    assert json.loads("".join(written))["components"]


def test_validate_cyclonedx_bom_identifies_faulty_component():
    bom = build_cyclonedx_bom([full_metadata_event()])
    assert validate_cyclonedx_bom(bom) == []
    bom["components"][0]["type"] = "not-a-type"
    errors = validate_cyclonedx_bom(bom)
    assert len(errors) == 1
    assert "OpenSSL" in errors[0]
    assert "3.0.2" in errors[0]


def test_write_cyclonedx_report_raises_and_logs_on_invalid_component():
    with patch("nettacker.core.cyclonedx.validate_cyclonedx_bom", return_value=["bad component"]):
        with patch("nettacker.core.cyclonedx.log") as mock_log:
            with pytest.raises(ValueError, match="bad component"):
                write_cyclonedx_report([make_event()], "unused.cdx.json")
            mock_log.error.assert_called_once_with("bad component")


def test_write_cyclonedx_report_logs_and_reraises_oserror(tmp_path):
    with patch("nettacker.core.cyclonedx.log") as mock_log:
        with pytest.raises(OSError):
            write_cyclonedx_report([make_event()], tmp_path / "missing" / "out.cdx.json")
        mock_log.error.assert_called_once()


def test_write_cyclonedx_report_logs_entry_and_exit(tmp_path):
    with patch("nettacker.core.cyclonedx.log") as mock_log:
        write_cyclonedx_report([full_metadata_event()], tmp_path / "out.cdx.json")
    info_messages = [call.args[0] for call in mock_log.info.call_args_list]
    assert any("building CycloneDX" in message for message in info_messages)
    assert any("finish building CycloneDX" in message for message in info_messages)
    assert any("CycloneDX report saved" in message for message in info_messages)


def test_bom_matches_official_cyclonedx_1_5_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    events = [
        full_metadata_event(dependencies=["pkg:deb/Ubuntu/zlib1g@1.2.11"]),
        full_metadata_event(version="1.1.1w"),
        make_event(),
        make_event(module_name="grafana_version_scan", target="10.0.0.2"),
        make_event(json_event={"name": "表情パッケージ", "version": "1.0"}),
    ]
    bom = build_cyclonedx_bom(events)
    validator_class = jsonschema.validators.validator_for(schema)
    validator_class.check_schema(schema)
    errors = list(validator_class(schema).iter_errors(bom))
    assert errors == []


def test_create_report_writes_cyclonedx_only_when_requested(tmp_path):
    from nettacker.core.graph import create_report

    events = [make_event()]
    options = MagicMock()
    options.report_path_filename = str(tmp_path / "report.json")
    options.graph_name = None
    options.cyclonedx_report_path_filename = None

    with (
        patch("nettacker.core.graph.get_logs_by_scan_id", return_value=events),
        patch("nettacker.core.graph.submit_report_to_db"),
        patch("nettacker.core.graph.log"),
    ):
        assert create_report(options, "scan-id") is True
    assert not list(tmp_path.glob("*.cdx.json"))

    cyclonedx_path = tmp_path / "report.cdx.json"
    options.cyclonedx_report_path_filename = str(cyclonedx_path)
    with (
        patch("nettacker.core.graph.get_logs_by_scan_id", return_value=events),
        patch("nettacker.core.graph.submit_report_to_db"),
        patch("nettacker.core.graph.log"),
    ):
        assert create_report(options, "scan-id") is True
    bom = json.loads(cyclonedx_path.read_text(encoding="utf-8"))
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
