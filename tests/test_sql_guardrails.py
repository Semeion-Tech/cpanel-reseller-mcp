from __future__ import annotations

import pytest

from reseller_mcp.sql_guardrails import (
	SQLGuardrailError,
	derive_backup_select,
	require_safe_write_statements,
	require_single_select,
)


def test_require_single_select_accepts_plain_select() -> None:
	require_single_select("SELECT id, email FROM users WHERE id = %s")


def test_require_single_select_rejects_non_select() -> None:
	with pytest.raises(SQLGuardrailError) as exc:
		require_single_select("DELETE FROM users WHERE id = 1")
	assert exc.value.code == "SQL_NOT_SELECT"


def test_require_single_select_rejects_multiple_statements() -> None:
	with pytest.raises(SQLGuardrailError) as exc:
		require_single_select("SELECT 1; SELECT 2")
	assert exc.value.code == "SQL_MULTIPLE_STATEMENTS"


def test_require_single_select_rejects_unparseable_sql() -> None:
	with pytest.raises(SQLGuardrailError) as exc:
		require_single_select("SELEKT this is not sql (")
	assert exc.value.code == "SQL_PARSE_ERROR"


def test_require_single_select_rejects_sql_with_comment() -> None:
	with pytest.raises(SQLGuardrailError) as exc:
		require_single_select("SELECT 1 -- comment")
	assert exc.value.code == "SQL_COMMENTS_NOT_ALLOWED"


def test_require_safe_write_statements_accepts_update_delete_insert() -> None:
	parsed = require_safe_write_statements(
		[
			"UPDATE users SET active = 0 WHERE id = %s",
			"DELETE FROM sessions WHERE user_id = %s",
			"INSERT INTO audit_log (event) VALUES (%s)",
		]
	)
	assert len(parsed) == 3


def test_require_safe_write_statements_rejects_ddl() -> None:
	with pytest.raises(SQLGuardrailError) as exc:
		require_safe_write_statements(["DROP TABLE users"])
	assert exc.value.code == "SQL_FORBIDDEN_STATEMENT"


def test_require_safe_write_statements_rejects_grant() -> None:
	with pytest.raises(SQLGuardrailError) as exc:
		require_safe_write_statements(["GRANT ALL ON *.* TO 'x'@'%'"])
	assert exc.value.code in {"SQL_FORBIDDEN_STATEMENT", "SQL_PARSE_ERROR"}


def test_require_safe_write_statements_rejects_empty_list() -> None:
	with pytest.raises(SQLGuardrailError) as exc:
		require_safe_write_statements([])
	assert exc.value.code == "SQL_EMPTY_TRANSACTION"


def test_require_safe_write_statements_rejects_sql_with_comment() -> None:
	with pytest.raises(SQLGuardrailError) as exc:
		require_safe_write_statements(["UPDATE t SET x = 1 -- comment"])
	assert exc.value.code == "SQL_COMMENTS_NOT_ALLOWED"


def test_require_safe_write_statements_rejects_backtick_identifier_conflict() -> None:
	with pytest.raises(SQLGuardrailError) as exc:
		require_safe_write_statements(["UPDATE `discount%stier` SET active = 0 WHERE id = 1"])
	assert exc.value.code == "SQL_IDENTIFIER_PLACEHOLDER_CONFLICT"


def test_require_safe_write_statements_rejects_embedded_string_literal() -> None:
	with pytest.raises(SQLGuardrailError) as exc:
		require_safe_write_statements(["UPDATE users SET status = 'active' WHERE id = %s"])
	assert exc.value.code == "SQL_LITERAL_NOT_ALLOWED"


def test_require_safe_write_statements_allows_numeric_literal() -> None:
	parsed = require_safe_write_statements(["UPDATE users SET active = 0 WHERE id = %s"])
	assert len(parsed) == 1


def test_derive_backup_select_for_update() -> None:
	[statement] = require_safe_write_statements(["UPDATE users SET active = 0 WHERE id = 42"])
	backup_sql = derive_backup_select(statement)
	assert backup_sql is not None
	assert "SELECT" in backup_sql.upper()
	assert "USERS" in backup_sql.upper()
	assert "42" in backup_sql


def test_derive_backup_select_for_delete() -> None:
	[statement] = require_safe_write_statements(["DELETE FROM sessions WHERE user_id = 7"])
	backup_sql = derive_backup_select(statement)
	assert backup_sql is not None
	assert "SESSIONS" in backup_sql.upper()


def test_derive_backup_select_for_insert_is_none() -> None:
	[statement] = require_safe_write_statements(["INSERT INTO audit_log (event) VALUES (%s)"])
	assert derive_backup_select(statement) is None


def test_derive_backup_select_for_update_preserves_placeholder() -> None:
	[statement] = require_safe_write_statements(["UPDATE users SET active = 0 WHERE id = %s"])
	backup_sql = derive_backup_select(statement)
	assert backup_sql is not None
	assert "%s" in backup_sql
	assert "= 1" not in backup_sql


def test_derive_backup_select_for_delete_preserves_placeholder() -> None:
	[statement] = require_safe_write_statements(["DELETE FROM sessions WHERE user_id = %s"])
	backup_sql = derive_backup_select(statement)
	assert backup_sql is not None
	assert "%s" in backup_sql
	assert "= 1" not in backup_sql


def test_require_safe_write_statements_rejects_update_with_limit() -> None:
	with pytest.raises(SQLGuardrailError) as exc:
		require_safe_write_statements(["UPDATE users SET active = 0 WHERE id = %s LIMIT 1"])
	assert exc.value.code == "SQL_LIMIT_OR_ORDER_NOT_ALLOWED"


def test_require_safe_write_statements_rejects_delete_with_limit() -> None:
	with pytest.raises(SQLGuardrailError) as exc:
		require_safe_write_statements(["DELETE FROM sessions WHERE user_id = %s LIMIT 1"])
	assert exc.value.code == "SQL_LIMIT_OR_ORDER_NOT_ALLOWED"


def test_require_safe_write_statements_rejects_update_with_order_by() -> None:
	with pytest.raises(SQLGuardrailError) as exc:
		require_safe_write_statements(
			["UPDATE users SET active = 0 WHERE id = %s ORDER BY id LIMIT 1"]
		)
	assert exc.value.code == "SQL_LIMIT_OR_ORDER_NOT_ALLOWED"


def test_require_safe_write_statements_rejects_parameterized_limit() -> None:
	with pytest.raises(SQLGuardrailError) as exc:
		require_safe_write_statements(["UPDATE users SET active = %s WHERE id = %s LIMIT %s"])
	assert exc.value.code == "SQL_LIMIT_OR_ORDER_NOT_ALLOWED"
