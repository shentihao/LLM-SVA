def verify_method(code, sources, sinks, sanitizers):
    source_hits = [s for s in sources if s in code]
    sink_hits = [s for s in sinks if s in code]

    source_valid = bool(source_hits)
    sink_valid = bool(sink_hits)

    if not source_valid or not sink_valid:
        return {
            "source_valid": source_valid,
            "path_valid": False,
            "sink_valid": sink_valid,
            "sanitization_absent": True
        }

    first_source = min(code.find(s) for s in source_hits if code.find(s) >= 0)
    first_sink = min(code.find(s) for s in sink_hits if code.find(s) >= 0)

    # V0.1: same-method lexical order as a conservative proxy.
    # Later versions should replace this with CFG/data-flow propagation.
    path_valid = first_source <= first_sink

    sanitized = any(s in code for s in sanitizers)

    return {
        "source_valid": source_valid,
        "path_valid": path_valid,
        "sink_valid": sink_valid,
        "sanitization_absent": not sanitized
    }
