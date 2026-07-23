from __future__ import annotations

import re

import sqlglot
from sqlglot import exp

_BACKTICK_PATTERN = re.compile(r"`(?:[^`]|``)*`")

ALLOWED_WRITE_TYPES: tuple[type[exp.Expression], ...] = (exp.Update, exp.Delete, exp.Insert)


class SQLGuardrailError(ValueError):
    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


def _reject_comments(sql: str) -> None:
    if "--" in sql or "#" in sql or "/*" in sql:
        raise SQLGuardrailError("SQL comments are not allowed", "SQL_COMMENTS_NOT_ALLOWED")


def _reject_backtick_identifier_conflicts(sql: str) -> None:
    for match in _BACKTICK_PATTERN.finditer(sql):
        identifier = match.group()
        if "%s" in identifier or "%d" in identifier or "%i" in identifier:
            raise SQLGuardrailError(
                "quoted identifiers may not contain %s/%d/%i-like sequences",
                "SQL_IDENTIFIER_PLACEHOLDER_CONFLICT",
            )


def _parse_one(sql: str) -> exp.Expression:
    _reject_comments(sql)
    _reject_backtick_identifier_conflicts(sql)
    normalized_sql = sql.replace("%s", "?").replace("%d", "?").replace("%i", "?")
    try:
        statements = sqlglot.parse(normalized_sql, dialect="mysql")
    except sqlglot.errors.ParseError as exc:
        raise SQLGuardrailError(f"sql could not be parsed: {exc}", "SQL_PARSE_ERROR") from exc
    non_empty = [statement for statement in statements if statement is not None]
    if len(non_empty) != 1:
        raise SQLGuardrailError(
            "exactly one SQL statement is required per entry", "SQL_MULTIPLE_STATEMENTS"
        )
    statement = non_empty[0]
    if not isinstance(statement, exp.Expression):
        raise SQLGuardrailError("sql did not produce an expression", "SQL_PARSE_ERROR")
    return statement


def require_single_select(sql: str) -> None:
    statement = _parse_one(sql)
    if not isinstance(statement, exp.Select):
        raise SQLGuardrailError("only SELECT statements are allowed here", "SQL_NOT_SELECT")
    if statement.args.get("locks"):
        raise SQLGuardrailError("locking SELECT statements are not allowed", "SQL_LOCK_NOT_ALLOWED")


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
        if statement.args.get("limit") is not None:
            raise SQLGuardrailError(
                "LIMIT clauses are not allowed in write statements",
                "SQL_LIMIT_OR_ORDER_NOT_ALLOWED",
            )
        if statement.args.get("order") is not None:
            raise SQLGuardrailError(
                "ORDER BY clauses are not allowed in write statements",
                "SQL_LIMIT_OR_ORDER_NOT_ALLOWED",
            )
        for node in statement.walk():
            if isinstance(node, exp.Literal) and node.is_string:
                raise SQLGuardrailError(
                    "string literals are not allowed in write statements; "
                    "use a %s placeholder and pass the value as a bound parameter instead",
                    "SQL_LITERAL_NOT_ALLOWED",
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
    return sql_output.replace("?", "%s")
