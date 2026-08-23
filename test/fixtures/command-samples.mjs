// Behavioral command samples shared across command/destructive tests.
// These are behavior-level fixtures (representative command shapes), not
// per-denylist-entry cases — denylist entries are covered by rules.test.mjs
// via table-driven generation.

export const LISTING_SAMPLES = [
  'Get-ChildItem .dsh',
  'ls ~/.dsh',
  'Test-Path .dsh',
  'Get-ChildItem .dsh/sessions',
  'dir .git',
  'Get-ChildItem .ssh',
  'Resolve-Path .env',
]

export const NON_LISTING_SAMPLES = [
  'Get-Content .env',
  'Get-ChildItem .dsh > .env',
  'Get-ChildItem $(Get-Content .env)',
  'Get-ChildItem .dsh; Get-Content .env',
  'Get-ChildItem .dsh | Remove-Item',
  'mystery-command .dsh/foo',
  'Get-ChildItem .dsh; echo hi',
]
