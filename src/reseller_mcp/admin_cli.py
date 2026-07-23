from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from .auth import TokenService
from .catalog import Catalog
from .config import get_settings
from .db import Database
from .models import Role

app = typer.Typer(help="Administration CLI for the cPanel reseller MCP.", no_args_is_help=True)
users = typer.Typer(help="Manage MCP users.")
tokens = typer.Typer(help="Manage per-client bearer tokens.")
catalog = typer.Typer(help="Inspect and synchronize the capability catalog.")
audit = typer.Typer(help="Export sanitized audit events.")
app.add_typer(users, name="users")
app.add_typer(tokens, name="tokens")
app.add_typer(catalog, name="catalog")
app.add_typer(audit, name="audit")


def _db() -> Database:
    return Database(get_settings().db_path)


@users.command("create")
def create_user(
    username: str,
    role: Annotated[Role, typer.Option()] = Role.VIEWER,
    scope: Annotated[
        list[str] | None,
        typer.Option("--scope", help="Repeat per cPanel account; use * globally."),
    ] = None,
) -> None:
    scopes = scope or []
    if not scopes:
        raise typer.BadParameter("at least one --scope is required")
    user_id = _db().create_user(username, role, scopes)
    typer.echo(
        json.dumps({"user_id": user_id, "username": username, "role": role, "scopes": scopes})
    )


@users.command("list")
def users_list() -> None:
    typer.echo(json.dumps({"users": _db().list_users()}, ensure_ascii=False))


@users.command("set-active")
def set_user_active(username: str, active: bool) -> None:
    if not _db().set_user_active(username, active):
        raise typer.BadParameter("unknown user")
    typer.echo(json.dumps({"username": username, "active": active}))


@users.command("set-scopes")
def set_user_scopes(
    username: str,
    scope: Annotated[
        list[str] | None,
        typer.Option("--scope", help="Repeat per account; use * globally."),
    ] = None,
) -> None:
    if not scope:
        raise typer.BadParameter("at least one --scope is required")
    if not _db().replace_user_scopes(username, scope):
        raise typer.BadParameter("unknown user")
    typer.echo(json.dumps({"username": username, "scopes": sorted(set(scope))}))


@tokens.command("issue")
def issue_token(
    username: str,
    client_id: str,
    expires_days: Annotated[int, typer.Option(min=1, max=365)] = 90,
) -> None:
    settings = get_settings()
    settings.ensure_runtime_secrets()
    token = TokenService(_db(), settings.token_pepper.get_secret_value()).issue(
        username, client_id, expires_days
    )
    typer.echo("Token created. It will not be shown again:")
    typer.echo(token)


@tokens.command("revoke")
def revoke_token(key_id: str) -> None:
    if not _db().revoke_token(key_id):
        raise typer.BadParameter("unknown token key ID")
    typer.echo("revoked")


@tokens.command("list")
def tokens_list(username: str | None = None) -> None:
    typer.echo(json.dumps({"tokens": _db().list_tokens(username)}, ensure_ascii=False))


@catalog.command("sync")
def sync_catalog() -> None:
    settings = get_settings()
    capabilities = Catalog(settings.catalog_path).load()
    from .catalog import ALIASES

    _db().sync_capabilities(capabilities, ALIASES)
    typer.echo(json.dumps({"count": len(capabilities), "source": str(settings.catalog_path)}))


@audit.command("export")
def export_audit(
    output: Path,
    limit: Annotated[int, typer.Option(min=1, max=100000)] = 10000,
) -> None:
    rows = _db().audit_rows(None, limit)
    output.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n")
    typer.echo(
        json.dumps(
            {"output": str(output), "events": len(rows), "at": datetime.now(UTC).isoformat()}
        )
    )


@app.command("reap-mysql-grants")
def reap_mysql_grants() -> None:
    import asyncio

    from .cpanel import CPanelClient
    from .mysql_client import reap_expired_grants

    settings = get_settings()
    db = _db()
    cpanel = CPanelClient(settings)

    async def run() -> int:
        try:
            return await reap_expired_grants(cpanel, db, settings)
        finally:
            await cpanel.close()

    revoked = asyncio.run(run())
    typer.echo(json.dumps({"revoked": revoked}))


if __name__ == "__main__":
    app()
