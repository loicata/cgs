"""Auto-generate API documentation from Flask routes."""


def generate_api_docs(app) -> dict:
    """Auto-generate API documentation from Flask routes."""
    docs = {"title": "CGS API Documentation", "version": "2.2.3", "endpoints": []}

    for rule in app.url_map.iter_rules():
        if not rule.rule.startswith("/api/"):
            continue
        endpoint = app.view_functions.get(rule.endpoint)
        if not endpoint:
            continue

        methods = [m for m in rule.methods if m not in ("HEAD", "OPTIONS")]
        doc = endpoint.__doc__ or ""

        # Detect decorators
        auth = "required"  # assume all /api/ need auth

        docs["endpoints"].append({
            "path": rule.rule,
            "methods": methods,
            "description": doc.strip(),
            "auth": auth,
            "group": _get_group(rule.rule),
        })

    # Sort by group then path
    docs["endpoints"].sort(key=lambda x: (x["group"], x["path"]))
    return docs


def _get_group(path):
    parts = path.split("/")
    if len(parts) >= 4:
        return parts[2]  # e.g. "grc", "admin", "compliance"
    return "general"
