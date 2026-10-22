"""A small JSON Schema 2020-12 validator for exactly the keywords docs/intelligence/schemas/file-provenance.schema.json uses (the standard library has none).
It implements $ref, type, enum, const, required, properties, additionalProperties, unevaluatedProperties (with annotation collection through $ref, allOf and if/then),
items, minItems/maxItems, uniqueItems, minLength/maxLength, pattern, minimum, allOf, if/then, not. Unknown keywords are rejected loudly so a schema change cannot pass silently."""
import json
import re

KNOWN = {"$schema", "$id", "$ref", "$defs", "title", "description", "type", "enum", "const", "required", "properties", "additionalProperties", "unevaluatedProperties", "items",
         "minItems", "maxItems", "uniqueItems", "minLength", "maxLength", "pattern", "minimum", "allOf", "if", "then", "not", "format"}
TYPES = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool, "number": (int, float)}
DATE_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")


def _is_type(inst, t):
    if t == "integer":
        return isinstance(inst, int) and not isinstance(inst, bool)
    if t == "number":
        return isinstance(inst, (int, float)) and not isinstance(inst, bool)
    return isinstance(inst, TYPES[t]) and not (t != "boolean" and isinstance(inst, bool) and t in ("object", "array", "string"))


def _resolve(root, ref):
    assert ref.startswith("#/"), ref
    node = root
    for part in ref[2:].split("/"):
        node = node[part]
    return node


def _check(inst, sch, root, path, errs):
    """Returns the set of evaluated property names (only meaningful when inst is an object)."""
    for k in sch:
        if k not in KNOWN:
            raise ValueError("validator does not know the keyword " + k)
    ev = set()
    if "$ref" in sch:
        ev |= _check(inst, _resolve(root, sch["$ref"]), root, path, errs)
    if "type" in sch and not _is_type(inst, sch["type"]):
        errs.append(f"{path}: expected {sch['type']}, got {type(inst).__name__}")
        return ev
    if "enum" in sch and inst not in sch["enum"]:
        errs.append(f"{path}: {inst!r} not in enum {sch['enum']}")
    if "const" in sch and inst != sch["const"]:
        errs.append(f"{path}: {inst!r} != const {sch['const']!r}")
    if isinstance(inst, str):
        if "pattern" in sch and not re.search(sch["pattern"], inst):
            errs.append(f"{path}: {inst!r} does not match {sch['pattern']}")
        if "minLength" in sch and len(inst) < sch["minLength"]:
            errs.append(f"{path}: too short")
        if "maxLength" in sch and len(inst) > sch["maxLength"]:
            errs.append(f"{path}: too long")
        if sch.get("format") == "date-time" and not DATE_TIME.match(inst):
            errs.append(f"{path}: not a date-time")
    if isinstance(inst, (int, float)) and not isinstance(inst, bool) and "minimum" in sch and inst < sch["minimum"]:
        errs.append(f"{path}: below minimum")
    if isinstance(inst, list):
        if "minItems" in sch and len(inst) < sch["minItems"]:
            errs.append(f"{path}: fewer than {sch['minItems']} items")
        if "maxItems" in sch and len(inst) > sch["maxItems"]:
            errs.append(f"{path}: more than {sch['maxItems']} items")
        if sch.get("uniqueItems") and len({json.dumps(x, sort_keys=True) for x in inst}) != len(inst):
            errs.append(f"{path}: items not unique")
        if "items" in sch:
            for i, x in enumerate(inst):
                _check(x, sch["items"], root, f"{path}[{i}]", errs)
    if isinstance(inst, dict):
        for r in sch.get("required", []):
            if r not in inst:
                errs.append(f"{path}: missing required {r}")
        props = sch.get("properties", {})
        for k, sub in props.items():
            if k in inst:
                _check(inst[k], sub, root, f"{path}.{k}", errs)
                ev.add(k)
        if sch.get("additionalProperties") is False:
            for k in inst:
                if k not in props:
                    errs.append(f"{path}: additional property {k}")
        if "additionalProperties" in sch:
            ev |= set(inst)
    for sub in sch.get("allOf", []):
        ev |= _check(inst, sub, root, path, errs)
    if "if" in sch:
        tmp = []
        cond = _check(inst, sch["if"], root, path, tmp)
        if not tmp:
            ev |= cond
            if "then" in sch:
                ev |= _check(inst, sch["then"], root, path, errs)
    if "not" in sch:
        tmp = []
        _check(inst, sch["not"], root, path, tmp)
        if not tmp:
            errs.append(f"{path}: matches a forbidden schema")
    if sch.get("unevaluatedProperties") is False and isinstance(inst, dict):
        for k in inst:
            if k not in ev:
                errs.append(f"{path}: unevaluated property {k}")
    return ev


def validate(instance, schema):
    errs = []
    _check(instance, schema, schema, "$", errs)
    return errs
