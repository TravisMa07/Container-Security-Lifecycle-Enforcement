"""Check repository-owned Markdown links and foundation invariants, offline."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
errors = []
required = ["HANDOFF.md", "AGENTS.md", "README.md", "docs/architecture.md",
            "docs/sdlc.md", "docs/roadmap.md", "docs/implementation-ledger.md"]
for name in required:
    if not (ROOT / name).is_file():
        errors.append("missing required file: " + name)
for path in sorted(ROOT.rglob("*.md")):
    if any(part.startswith(".") for part in path.relative_to(ROOT).parts):
        continue
    content = path.read_text()
    # Preserve the authoritative supplied specification, including its illustrative TODOs.
    if path.name != "HANDOFF.md" and re.search(r"\{\{[^}]+\}\}|VERIFY_OFFICIAL_REFERENCE_BEFORE_USE", content):
        errors.append(str(path.relative_to(ROOT)) + ": unresolved template marker")
    for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", content):
        if re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*:", target) or target.startswith("#"):
            continue
        target = target.split("#", 1)[0]
        resolved = (path.parent / target).resolve()
        if not resolved.is_relative_to(ROOT) or not resolved.exists():
            errors.append(str(path.relative_to(ROOT)) + ": invalid local link " + target)
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print("Foundation checks passed: required documents, local Markdown links and template markers.")
