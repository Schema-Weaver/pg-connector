/**
 * Errors shared by the non-PostgreSQL drivers.
 *
 * The PostgreSQL classifier predates the driver split and throws
 * `SqlParseError` / `SqlParserUnavailableError` from `execution/sql-parser`.
 * These classes carry the same meaning for the other engines so
 * `PermissionChecker` can fail closed without importing a driver.
 */

/** The engine's grammar could not represent the input. Always a refusal. */
export class DriverParseError extends Error {
  public readonly code = 'parse_error';
  constructor(message: string) {
    super(message);
    this.name = 'DriverParseError';
  }
}

/** The engine's parser is not loaded or not usable. Always a refusal. */
export class DriverParserUnavailableError extends Error {
  public readonly code = 'parser_unavailable';
  constructor(message: string) {
    super(message);
    this.name = 'DriverParserUnavailableError';
  }
}
