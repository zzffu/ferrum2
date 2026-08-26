# Qualification Orchestration Guidelines

This module coordinates qualification rows through the explicit external-support interfaces. Keep the
orchestrator responsible for sequencing and final evidence aggregation, not protocol or process details.

Every attempted row must produce one bounded result, and partial success must not conceal a case or
cleanup failure.
