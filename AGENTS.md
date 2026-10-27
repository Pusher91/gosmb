# Project preferences

- Defer CI, versioned releases, `--version`, licensing, and release notes for the
  foreseeable future. Do not implement or repeatedly recommend this work unless
  the user explicitly brings it back into scope.
- README restructuring and editorial polish are also deferred. Focus on the
  requested functional work.
- In text and TSV output, the `GUEST` column describes credential fallback.
  Explicit `--guest` scans display `N/A` in that column, including failed or
  timed-out scans. Keep JSON's `guest_fallback` Boolean semantics unchanged.
- The default text table is preserved when piped, including through `tee`.
  Table and explicit `--tsv` output include `STATUS` before `HOSTNAME`.
  Cap every table cell to its column's display width, with an ellipsis
  inside that limit. Only the final `HOSTNAME` column is unbounded. Keep all
  status labels within the status column's limit. TSV retains full values;
  keep the JSON schema unchanged.
  In all text output, `STATUS` replaces separate per-host/per-share scan
  diagnostics. Retain CLI-level errors and terminal stderr progress, including
  when stdout is piped through `tee`. Keep progress and terminal controls out
  of stdout, except that interrupted piped default-table output appends one
  plain progress summary unless `--no-progress` is set. Saving that summary is
  best effort because plain `tee` may also exit on Ctrl+C. TSV and JSON keep
  their existing formats. Piped output uses occasional plain progress lines
  on terminal stderr, without cursor-control sequences or terminal setup. Direct
  terminal output keeps its updating progress line. Support plain `tee`
  without special flags, synchronization, or signal handling for the reader.
  Terminal progress ends with a compact stderr summary of host outcomes and
  share permission counts. Honor `--no-progress` for both progress and summary.
  JSON keeps its existing error fields.
