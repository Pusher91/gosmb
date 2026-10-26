# Project preferences

- Defer CI, versioned releases, `--version`, licensing, and release notes for the
  foreseeable future. Do not implement or repeatedly recommend this work unless
  the user explicitly brings it back into scope.
- README restructuring and editorial polish are also deferred. Focus on the
  requested functional work.
- In text and TSV output, the `GUEST` column describes credential fallback.
  Explicit `--guest` scans display `N/A` in that column, including failed or
  timed-out scans. Keep JSON's `guest_fallback` Boolean semantics unchanged.
- The interactive table includes a compact `STATUS` column before `HOSTNAME`.
  Cap every interactive cell to its column's display width, with an ellipsis
  inside that limit. Only the final `HOSTNAME` column is unbounded. Keep all
  status labels within the status column's limit. Preserve the original
  six-column TSV output and full values, and keep the JSON schema unchanged.
  In the interactive table, `STATUS` replaces separate per-host/per-share scan
  diagnostics; retain progress and CLI-level errors. TSV keeps its stderr
  diagnostics, and JSON keeps its existing error fields.
