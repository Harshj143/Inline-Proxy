"""Allow `python -m mcp_gateway …` without an installed console script."""

from mcp_gateway.cli import main

raise SystemExit(main())
