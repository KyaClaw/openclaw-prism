---
name: security-bootstrap
description: "Verifies SHA256 integrity of SOUL.md, AGENTS.md, TOOLS.md on agent bootstrap"
metadata:
  openclaw:
    emoji: "🔒"
    events: ["agent:bootstrap"]
    requires:
      bins: ["node"]
---
