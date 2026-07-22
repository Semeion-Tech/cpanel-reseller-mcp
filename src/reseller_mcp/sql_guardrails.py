from __future__ import annotations

import re

import sqlglot
from sqlglot import exp

_QUOTED_SEGMENT = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"")

ALLOWED_WRITE_TYPES: tuple[type[exp.Expression], ...] = (exp.Update, exp.Delete, exp.Insert)


class SQLGuardrailError(ValueError):
    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


def _replace_outside_quotes(sql: str, old: str, new: str) -> str:
    """Replace old with new in sql, but only outside of string literals."""
    parts: list[str] = []
    last_end = 0
    for match in _QUOTED_SEGMENT.finditer(sql):
        parts.append(sql[last_end : match.start()].replace(old, new))
        parts.append(match.group())
        last_end = match.end()
    parts.append(sql[last_end:].replace(old, new))
    return "".join(parts)


def _parse_one(sql: str) -> exp.Expression:
    normalized_sql = _replace_outside_quotes(sql, "%s", "?")
    normalized_sql = _replace_outside_quotes(normalized_sql, "%d", "?")
    normalized_sql = _replace_outside_quotes(normalized_sql, "%i", "?")
    try:
        statements = sqlglot.parse(normalized_sql, dialect="mysql")
    except sqlglot.errors.ParseError as exc:
        raise SQLGuardrailError(f"sql could not be parsed: {exc}", "SQL_PARSE_ERROR") from exc
    non_empty = [statement for statement in statements if statement is not None]
    if len(non_empty) != 1:
        raise SQLGuardrailError(
            "exactly one SQL statement is required per entry", "SQL_MULTIPLE_STATEMENTS"
        )
    return non_empty[0]


def require_single_select(sql: str) -> None:
    statement = _parse_one(sql)
    if not isinstance(statement, exp.Select):
        raise SQLGuardrailError("only SELECT statements are allowed here", "SQL_NOT_SELECT")


def require_safe_write_statements(statements: list[str]) -> list[exp.Expression]:
    if not statements:
        raise SQLGuardrailError("at least one statement is required", "SQL_EMPTY_TRANSACTION")
    parsed: list[exp.Expression] = []
    for sql in statements:
        statement = _parse_one(sql)
        if not isinstance(statement, ALLOWED_WRITE_TYPES):
            raise SQLGuardrailError(
                f"statement type {type(statement).__name__} is not allowed here; "
                "only UPDATE, DELETE, and INSERT are permitted",
                "SQL_FORBIDDEN_STATEMENT",
            )
        parsed.append(statement)
    return parsed


def derive_backup_select(statement: exp.Expression) -> str | None:
    if isinstance(statement, exp.Insert):
        return None
    table = statement.this
    if not isinstance(table, exp.Table) and hasattr(table, "this"):
        table = table.this
    where = statement.args.get("where")
    select = exp.select("*").from_(table.copy())
    if where is not None:
        condition = where.this if hasattr(where, "this") else where
        select = select.where(condition.copy())
    sql_output = select.sql(dialect="mysql")
    # Replace ? placeholders back to %s for MySQL driver (pyformat style)
    return _replace_outside_quotes(sql_output, "?", "%s")
