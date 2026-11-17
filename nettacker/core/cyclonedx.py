"""
CycloneDX 1.5 SBOM report builder.

Converts Nettacker scan events into a CycloneDX 1.5 JSON BOM. Each scan
event is a module hit on a target; the structured ``json_event`` payload may
carry component metadata (``name``, ``version``, ``type``, ``namespace``,
``purl_type``, ``purl`` and a ``dependencies`` list). Missing metadata is
degraded to ``unknown`` and counted instead of aborting the report.
"""

import json
from pathlib import Path
from urllib.parse import quote

from nettacker import logger
from nettacker.config import version_info
from nettacker.core.messages import messages as _

log = logger.get_logger()

cyclonedx_spec_version = "1.5"
cyclonedx_schema_id = "https://cyclonedx.org/schema/bom-1.5.schema.json"
unknown_value = "unknown"
scan_root_ref = "nettacker-scan"
module_ref_prefix = "module:"

# component "type" enum of the CycloneDX 1.5 schema
valid_component_types = {
    "application",
    "framework",
    "library",
    "container",
    "platform",
    "operating-system",
    "device",
    "device-driver",
    "firmware",
    "file",
    "machine-learning-model",
    "data",
}

# purl spec: name/namespace/version keep their case, only reserved chars are quoted
purl_name_safe_chars = "-._~"
purl_version_safe_chars = "-._~+"


def parse_json_event(event):
    """
    extract the structured json_event payload of a scan event

    Args:
        event: scan event dict

    Returns:
        json_event as a dict, empty dict when absent or unparsable
    """
    json_event = event.get("json_event") or {}
    if isinstance(json_event, str):
        try:
            json_event = json.loads(json_event)
        except ValueError:
            return {}
    return json_event if isinstance(json_event, dict) else {}


def build_purl(purl_type, namespace, name, version):
    """
    build a package URL following the purl spec, preserving the original
    case of the package name and namespace

    Args:
        purl_type: purl type (e.g. generic, deb, npm), lowercased per spec
        namespace: purl namespace, may contain "/" separated segments
        name: package name
        version: package version

    Returns:
        purl string
    """
    purl = "pkg:{0}/".format(str(purl_type).lower())
    if namespace:
        purl += (
            "/".join(
                quote(str(segment), safe=purl_name_safe_chars)
                for segment in str(namespace).split("/")
                if segment
            )
            + "/"
        )
    purl += quote(str(name), safe=purl_name_safe_chars)
    if version:
        purl += "@" + quote(str(version), safe=purl_version_safe_chars)
    return purl


def component_from_event(event):
    """
    convert a scan event into a CycloneDX component

    Args:
        event: scan event dict

    Returns:
        an array [component dict, list of missing metadata fields,
        list of declared dependency refs]
    """
    json_event = parse_json_event(event)
    missing_fields = []

    name = json_event.get("name") or json_event.get("product") or json_event.get("package")
    if not name:
        name = event.get("module_name") or unknown_value
        missing_fields.append("name")

    version = json_event.get("version")
    if not version:
        version = unknown_value
        missing_fields.append("version")

    component_type = json_event.get("type")
    if component_type not in valid_component_types:
        component_type = "application"

    namespace = json_event.get("namespace") or json_event.get("group")
    purl = json_event.get("purl")
    if not purl:
        purl = build_purl(
            json_event.get("purl_type") or "generic",
            namespace,
            name,
            version,
        )
        if not namespace:
            missing_fields.append("source")

    component = {
        "bom-ref": purl,
        "type": component_type,
        "name": str(name),
        "version": str(version),
        "purl": purl,
    }
    if namespace:
        component["group"] = str(namespace)
    if missing_fields:
        component["properties"] = [
            {"name": "nettacker:missing_metadata", "value": ",".join(missing_fields)}
        ]

    dependencies = []
    for dependency in json_event.get("dependencies") or []:
        if isinstance(dependency, dict):
            dependency = dependency.get("purl") or build_purl(
                dependency.get("purl_type") or "generic",
                dependency.get("namespace") or dependency.get("group"),
                dependency.get("name") or unknown_value,
                dependency.get("version") or "",
            )
        dependencies.append(str(dependency))

    return component, missing_fields, dependencies


def build_cyclonedx_bom(events):
    """
    build a deterministic CycloneDX 1.5 BOM from scan events

    Components are deduplicated by the (name, version, purl) triple, sorted
    by the same triple, and grouped under one dependency node per module so
    a target hit by several modules is expanded per module.

    Args:
        events: list of scan events

    Returns:
        BOM as an ordered dict
    """
    log.info(_("build_cyclonedx_report"))

    components = {}
    declared_dependencies = {}
    module_components = {}
    missing_metadata_count = 0

    for event in events:
        component, missing_fields, dependencies = component_from_event(event)
        dedup_key = (component["name"], component["version"], component["purl"])
        if dedup_key not in components:
            components[dedup_key] = component
            declared_dependencies[dedup_key] = dependencies
        if missing_fields:
            missing_metadata_count += 1
        module_name = str(event.get("module_name") or unknown_value)
        module_components.setdefault(module_name, set()).add(dedup_key)

    if missing_metadata_count:
        log.warn(_("cyclonedx_missing_metadata").format(missing_metadata_count))

    sorted_keys = sorted(components)
    bom_refs = {}
    used_refs = set()
    for dedup_key in sorted_keys:
        bom_ref = components[dedup_key]["purl"]
        if bom_ref in used_refs:
            suffix = 2
            while "{0}#{1}".format(bom_ref, suffix) in used_refs:
                suffix += 1
            bom_ref = "{0}#{1}".format(bom_ref, suffix)
        used_refs.add(bom_ref)
        bom_refs[dedup_key] = bom_ref
        components[dedup_key]["bom-ref"] = bom_ref

    dependencies = [
        {
            "ref": scan_root_ref,
            "dependsOn": [module_ref_prefix + name for name in sorted(module_components)],
        }
    ]
    for module_name in sorted(module_components):
        dependencies.append(
            {
                "ref": module_ref_prefix + module_name,
                "dependsOn": sorted(bom_refs[key] for key in module_components[module_name]),
            }
        )
    for dedup_key in sorted_keys:
        dependencies.append(
            {
                "ref": bom_refs[dedup_key],
                "dependsOn": sorted(set(declared_dependencies[dedup_key])),
            }
        )

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": cyclonedx_spec_version,
        "version": 1,
        "metadata": {
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "publisher": "OWASP",
                        "name": "Nettacker",
                        "version": version_info()[0],
                    }
                ]
            },
            "component": {
                "bom-ref": scan_root_ref,
                "type": "application",
                "name": scan_root_ref,
                "version": version_info()[0],
            },
            "properties": [
                {
                    "name": "nettacker:components_with_missing_metadata",
                    "value": str(missing_metadata_count),
                }
            ],
        },
        "components": [components[key] for key in sorted_keys],
        "dependencies": dependencies,
    }

    log.info(_("finish_build_cyclonedx_report"))
    return bom


def validate_cyclonedx_bom(bom):
    """
    sanity check a BOM against the CycloneDX 1.5 required fields

    Args:
        bom: BOM dict

    Returns:
        list of error strings identifying the faulty component,
        empty when the BOM is valid
    """
    errors = []
    for field in ("bomFormat", "specVersion"):
        if not bom.get(field):
            errors.append("bom is missing required field '{0}'".format(field))
    for component in bom.get("components", []):
        component_id = "{0} {1} ({2})".format(
            component.get("name", "?"),
            component.get("version", "?"),
            component.get("bom-ref", "?"),
        )
        if component.get("type") not in valid_component_types:
            errors.append(_("cyclonedx_invalid_component").format(component_id, "invalid 'type'"))
        if not component.get("name"):
            errors.append(_("cyclonedx_invalid_component").format(component_id, "missing 'name'"))
    return errors


def write_cyclonedx_report(events, report_path_filename):
    """
    write scan events as a CycloneDX 1.5 JSON report, streaming the output
    in chunks instead of building one large string

    Args:
        events: list of scan events
        report_path_filename: output file path

    Returns:
        True if success
    """
    bom = build_cyclonedx_bom(events)
    errors = validate_cyclonedx_bom(bom)
    if errors:
        for error in errors:
            log.error(error)
        raise ValueError("; ".join(errors))
    try:
        with Path(report_path_filename).open("w", encoding="utf-8") as report_file:
            encoder = json.JSONEncoder(indent=2, ensure_ascii=True)
            for chunk in encoder.iterencode(bom):
                report_file.write(chunk)
            report_file.write("\n")
    except OSError as error:
        log.error(_("cyclonedx_report_failed").format(report_path_filename, error))
        raise
    log.info(_("cyclonedx_report_saved").format(report_path_filename))
    return True
