from __future__ import annotations

import re

import sqlglot
from sqlglot import exp

_PROTECTED_PATTERN = re.compile(
    r"'(?:[^'\\]|\\.)*'"        # single-quoted string
    r"|\"(?:[^\"\\]|\\.)*\""     # double-quoted string
    r"|`(?:[^`]|``)*`"           # backtick-quoted identifier
    r"|--[^\n]*"                 # line comment --
    r"|#[^\n]*"                  # line comment #
    r"|/\*(?:[^*]|\*(?!/))*\*/"  # multi-line comment
)

ALLOWED_WRITE_TYPES: tuple[type[exp.Expression], ...] = (exp.Update, exp.Delete, exp.Insert)


class SQLGuardrailError(ValueError):
    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


def _replace_outside_protected_regions(sql: str, old: str, new: str) -> str:
    """
    Replace old with new in sql, but only outside of protected regions
    (string literals, comments, and backtick-quoted identifiers).

    Uses sqlglot's tokenizer for accuracy, with regex fallback.
    """
    # Try tokenizer-based approach first
    tokenizer = sqlglot.Tokenizer(dialect="mysql")

    try:
        token_list = tokenizer.tokenize(sql)
    except Exception:
        # Tokenization failed, use regex approach
        return _replace_with_regex(sql, old, new)

    # Build protected spans from tokens
    protected: list[tuple[int, int]] = []

    for tok in token_list:
        if tok.token_type.name == "EOF":
            continue

        # STRING tokens are protected
        if (
            tok.token_type.name == "STRING"
            and tok.start < len(sql)
            and sql[tok.start] in ("'", '"')
        ):
            # tok.start points to opening quote, tok.end to last content char
            quote_char = sql[tok.start]
            close_idx = tok.end + 1
            # Closing quote should be right after tok.end
            if close_idx < len(sql) and sql[close_idx] == quote_char:
                protected.append((tok.start, close_idx + 1))
            else:
                # Fallback: protect from start to end+1
                protected.append((tok.start, tok.end + 1))

    # Add comment regions using regex
    for match in _PROTECTED_PATTERN.finditer(sql):
        # Skip if this is just matching a STRING token we already have
        tok_type = match.group()
        if tok_type.startswith("'") or tok_type.startswith('"') or tok_type.startswith("`"):
            # These are handled via tokenizer above, skip regex version
            continue
        # Only add comments
        if tok_type.startswith(("--", "#", "/*")):
            protected.append((match.start(), match.end()))

    # Sort and merge overlapping regions
    if not protected:
        return sql.replace(old, new)

    protected.sort()
    merged: list[tuple[int, int]] = [protected[0]]
    for start, end in protected[1:]:
        if start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))

    # Build result by replacing only in unprotected regions
    result: list[str] = []
    last_pos = 0

    for prot_start, prot_end in merged:
        if last_pos < prot_start:
            result.append(sql[last_pos:prot_start].replace(old, new))
        result.append(sql[prot_start:prot_end])
        last_pos = prot_end

    if last_pos < len(sql):
        result.append(sql[last_pos:].replace(old, new))

    return "".join(result)


def _replace_with_regex(sql: str, old: str, new: str) -> str:
    """
    Fallback regex-based replacement for when tokenizer fails.
    Replaces old with new, but only outside of protected regions.
    """
    parts: list[str] = []
    last_end = 0
    for match in _PROTECTED_PATTERN.finditer(sql):
        parts.append(sql[last_end : match.start()].replace(old, new))
        parts.append(match.group())
        last_end = match.end()
    parts.append(sql[last_end:].replace(old, new))
    return "".join(parts)


def _parse_one(sql: str) -> exp.Expression:
    normalized_sql = _replace_outside_protected_regions(sql, "%s", "?")
    normalized_sql = _replace_outside_protected_regions(normalized_sql, "%d", "?")
    normalized_sql = _replace_outside_protected_regions(normalized_sql, "%i", "?")
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
    return _replace_with_regex(sql_output, "?", "%s")
