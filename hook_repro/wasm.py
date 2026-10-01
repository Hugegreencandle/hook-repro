"""Minimal WASM (MVP binary format) section parser and section/function-level diff.

Only what a binary-custody check needs: section boundaries, imports/exports, function
names, per-function code bodies. Anything that does not parse raises WasmError; the
caller reports it, it never becomes "identical".
"""
import hashlib

SECTION_NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table", 5: "memory",
    6: "global", 7: "export", 8: "start", 9: "element", 10: "code", 11: "data",
    12: "datacount",
}
MAGIC = b"\x00asm"


class WasmError(ValueError):
    pass


def _uleb(b, i):
    result = shift = 0
    while True:
        if i >= len(b):
            raise WasmError("truncated LEB128 at offset %d" % i)
        byte = b[i]
        i += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, i
        shift += 7
        if shift > 35:
            raise WasmError("LEB128 too long at offset %d" % i)


def _name(b, i):
    n, i = _uleb(b, i)
    if i + n > len(b):
        raise WasmError("truncated name at offset %d" % i)
    return b[i:i + n].decode("utf-8", "replace"), i + n


def _limits(b, i):
    flag = b[i]
    i += 1
    _, i = _uleb(b, i)
    if flag & 1:
        _, i = _uleb(b, i)
    return i


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def parse(data):
    """Return a dict describing the module. Raises WasmError on malformed input."""
    data = bytes(data)
    if len(data) < 8 or data[:4] != MAGIC:
        raise WasmError("not a wasm module (bad magic)")
    if data[4:8] != b"\x01\x00\x00\x00":
        raise WasmError("unsupported wasm version %s" % data[4:8].hex())
    sections, i = [], 8
    while i < len(data):
        sid = data[i]
        size, body = _uleb(data, i + 1)
        end = body + size
        if end > len(data):
            raise WasmError("section id %d overruns module (%d > %d)" % (sid, end, len(data)))
        name = SECTION_NAMES.get(sid, "unknown_%d" % sid)
        payload = data[body:end]
        if sid == 0:
            cname, _ = _name(data, body)
            name = "custom:" + cname
        sections.append({"id": sid, "name": name, "offset": i, "size": size,
                         "payload": payload, "sha256": _sha(payload)})
        i = end
    mod = {"size": len(data), "sections": sections, "imports": [], "exports": [], "export_entries": [],
           "functions": [], "n_imported_funcs": 0}
    fnames = {}
    for s in sections:
        p = s["payload"]
        if s["id"] == 2:
            n, j = _uleb(p, 0)
            for _ in range(n):
                m, j = _name(p, j)
                f, j = _name(p, j)
                kind = p[j]
                j += 1
                if kind == 0:
                    _, j = _uleb(p, j)
                    fnames[mod["n_imported_funcs"]] = "%s.%s" % (m, f)
                    mod["n_imported_funcs"] += 1
                elif kind == 1:
                    j = _limits(p, j + 1)
                elif kind == 2:
                    j = _limits(p, j)
                elif kind == 3:
                    j += 2
                else:
                    raise WasmError("unknown import kind %d" % kind)
                mod["imports"].append("%s.%s:%d" % (m, f, kind))
        elif s["id"] == 7:
            n, j = _uleb(p, 0)
            for _ in range(n):
                f, j = _name(p, j)
                kind = p[j]
                idx, j = _uleb(p, j + 1)
                mod["exports"].append("%s:%d:%d" % (f, kind, idx))
                mod["export_entries"].append((f, kind, idx))  # structured: a name may contain ':'
                if kind == 0:
                    fnames.setdefault(idx, f)
        elif s["name"] == "custom:name":
            _, j = _name(p, 0)
            while j < len(p):
                sub = p[j]
                ln, j = _uleb(p, j + 1)
                if sub == 1:
                    n, k = _uleb(p, j)
                    for _ in range(n):
                        idx, k = _uleb(p, k)
                        nm, k = _name(p, k)
                        fnames.setdefault(idx, nm)
                j += ln
    for s in sections:
        if s["id"] == 10:
            p = s["payload"]
            n, j = _uleb(p, 0)
            for k in range(n):
                size, j2 = _uleb(p, j)
                if j2 + size > len(p):
                    raise WasmError("code body %d overruns code section" % k)
                idx = mod["n_imported_funcs"] + k
                body = p[j2:j2 + size]
                mod["functions"].append({"index": idx, "name": fnames.get(idx, "func[%d]" % idx),
                                         "size": size, "sha256": _sha(body)})
                j = j2 + size
    return mod


def _key_sections(sections):
    seen, out = {}, []
    for s in sections:
        k = s["name"]
        seen[k] = seen.get(k, 0) + 1
        out.append(("%s#%d" % (k, seen[k]) if seen[k] > 1 else k, s))
    return out


def diff(a, b, label_a="on_ledger", label_b="rebuilt"):
    """Section- and function-level diff of two modules (bytes). Never raises."""
    a, b = bytes(a), bytes(b)
    out = {"identical": a == b, "size": {label_a: len(a), label_b: len(b)},
           "size_delta": len(b) - len(a)}
    n = min(len(a), len(b))
    first = next((i for i in range(n) if a[i] != b[i]), None)
    if first is None and len(a) != len(b):
        first = n
    out["first_diff_offset"] = first
    if len(a) == len(b):
        out["bytes_differing"] = sum(1 for i in range(n) if a[i] != b[i])
    try:
        ma, mb = parse(a), parse(b)
    except WasmError as e:
        out["parse_error"] = str(e)
        return out
    ka, kb = dict(_key_sections(ma["sections"])), dict(_key_sections(mb["sections"]))
    order = [k for k, _ in _key_sections(ma["sections"])]
    order += [k for k, _ in _key_sections(mb["sections"]) if k not in ka]
    secs = []
    for k in order:
        sa, sb = ka.get(k), kb.get(k)
        if sa and sb:
            status = "same" if sa["sha256"] == sb["sha256"] else "differs"
        else:
            status = "only_" + (label_a if sa else label_b)
        secs.append({"section": k, "status": status,
                     label_a: sa["size"] if sa else None, label_b: sb["size"] if sb else None})
    out["sections"] = secs
    fa = {f["index"]: f for f in ma["functions"]}
    fb = {f["index"]: f for f in mb["functions"]}
    funcs = []
    for idx in sorted(set(fa) | set(fb)):
        x, y = fa.get(idx), fb.get(idx)
        if x and y:
            status = "same" if x["sha256"] == y["sha256"] else "differs"
        else:
            status = "only_" + (label_a if x else label_b)
        funcs.append({"index": idx, "name": (x or y)["name"], "status": status,
                      label_a: x["size"] if x else None, label_b: y["size"] if y else None})
    out["functions"] = funcs
    out["imports_equal"] = ma["imports"] == mb["imports"]
    out["exports_equal"] = ma["exports"] == mb["exports"]
    if not out["imports_equal"]:
        out["imports"] = {label_a: ma["imports"], label_b: mb["imports"]}
    if not out["exports_equal"]:
        out["exports"] = {label_a: ma["exports"], label_b: mb["exports"]}
    return out


def render_diff(d):
    lines = []
    sz = d["size"]
    la, lb = list(sz)
    lines.append("size: %s=%d B, %s=%d B (delta %+d)" % (la, sz[la], lb, sz[lb], d["size_delta"]))
    if d.get("first_diff_offset") is not None:
        lines.append("first differing byte offset: %d" % d["first_diff_offset"])
    if "bytes_differing" in d and not d["identical"]:
        lines.append("bytes differing (same length): %d" % d["bytes_differing"])
    if "parse_error" in d:
        lines.append("WASM PARSE ERROR: %s (no section diff possible)" % d["parse_error"])
        return "\n".join(lines)
    for s in d["sections"]:
        if s["status"] != "same":
            lines.append("  section %-14s %-18s %s=%s %s=%s" % (s["section"], s["status"], la, s[la], lb, s[lb]))
    for f in d["functions"]:
        if f["status"] != "same":
            lines.append("  func[%d] %-20s %-18s %s=%s %s=%s" % (f["index"], f["name"], f["status"], la, f[la], lb, f[lb]))
    if not d["imports_equal"]:
        lines.append("  imports differ")
    if not d["exports_equal"]:
        lines.append("  exports differ")
    return "\n".join(lines)
