from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

from .audit import scrub_url_userinfo
from .cpanel import CPanelError
from .models import ApiFamily, Capability, Preparation, Risk, Role

if TYPE_CHECKING:
    from .harness import Harness

# GitHub owners whose repositories may be cloned into an account.
ALLOWED_GIT_OWNERS = frozenset({"semeion-tech", "lucioribeiro-ihc", "omc-media-drum-dev"})

_REPO = r"(?P<repo>[A-Za-z0-9][A-Za-z0-9._-]{0,99}?)(?:\.git)?"
_OWNER = r"(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))"
# https and SSH forms of a GitHub remote; no user, password, token, port, query or fragment.
_REMOTE = re.compile(
    rf"^(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/){_OWNER}/{_REPO}/?$"
)
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")


class GitWorkflows:
    """Clone of an allowed GitHub repository into the account's repositories directory.

    Only remotes owned by ALLOWED_GIT_OWNERS are accepted, and never with a user, password or
    token in the URL: a private repository is cloned over SSH with the key already on the
    account, which this service never reads or writes. The clone lands in
    ~/repositories/<name>. Cloning again the same remote into the same directory is a no-op.
    """

    def __init__(self, harness: Harness):
        self.harness = harness

    @staticmethod
    def parse_remote(value: str) -> tuple[str, str]:
        """(owner, repository) of an allowed remote, or a validation error."""
        text = value.strip()
        if scrub_url_userinfo(text) != text or "@" in text.replace("git@github.com", "", 1):
            raise CPanelError(
                "the remote must not carry a user, password or token",
                code="GIT_REMOTE_INVALID",
                category="validation",
            )
        match = _REMOTE.match(text)
        if match is None:
            raise CPanelError(
                "the remote must be https://github.com/<owner>/<repo>, "
                "git@github.com:<owner>/<repo> or ssh://git@github.com/<owner>/<repo>",
                code="GIT_REMOTE_INVALID",
                category="validation",
            )
        owner, repo = match.group("owner"), match.group("repo")
        if owner.casefold() not in ALLOWED_GIT_OWNERS:
            raise CPanelError(
                f"the GitHub owner {owner!r} is not allowed",
                code="GIT_REMOTE_NOT_ALLOWED",
                category="validation",
                details={"allowed_owners": sorted(ALLOWED_GIT_OWNERS)},
            )
        return owner, repo

    async def prepare_clone(self, account: str | None, arguments: dict[str, Any]) -> dict[str, Any]:
        if not account:
            raise CPanelError("git workflows require an account", code="ACCOUNT_REQUIRED")
        url = str(arguments["url"]).strip()
        owner, repo = self.parse_remote(url)
        name = str(arguments.get("name") or repo)
        if not _NAME.match(name) or name in {".", ".."}:
            raise CPanelError(
                f"{name!r} is not a valid repository directory name",
                code="GIT_NAME_INVALID",
                category="validation",
            )
        branch = arguments.get("branch")
        if branch is not None and (not _BRANCH.match(str(branch)) or ".." in str(branch)):
            raise CPanelError(
                f"{branch!r} is not a valid branch name",
                code="GIT_BRANCH_INVALID",
                category="validation",
            )
        home = await self._home(account)
        root = f"{home}/repositories/{name}"
        repositories = await self._repositories(account)
        existing = next((r for r in repositories if r.get("repository_root") == root), None)
        noop = existing is not None and self._same_remote(existing, owner, repo)
        if existing and not noop:
            raise CPanelError(
                f"{root} already holds a repository with a different remote",
                code="GIT_REPOSITORY_EXISTS",
                category="validation",
            )
        return {
            "home": home,
            "repository_root": root,
            "remote": {"owner": owner, "repository": repo, "url": url},
            "repository": existing,
            "noop": noop,
            "repositories": repositories,
        }

    async def execute_clone(self, preparation: Preparation) -> dict[str, Any]:
        account = preparation.account
        before = preparation.before_state or {}
        root = before["repository_root"]
        url = preparation.arguments["url"].strip()
        if before.get("noop"):
            return {
                "data": {"changed": False, "repository_root": root, "noop": True},
                "after_state": before.get("repositories"),
                "verified": True,
                "warnings": [],
            }
        name = root.rsplit("/", 1)[-1]
        parameters: dict[str, Any] = {
            "type": "git",
            "name": name,
            "repository_root": root,
            "source_repository": json.dumps({"remote_name": "origin", "url": url}),
        }
        if preparation.arguments.get("branch"):
            parameters["checkout_branch"] = preparation.arguments["branch"]
        reconciled = False
        try:
            await self.harness.cpanel.call(
                self._capability(), account, parameters, retry_safe=False
            )
        except CPanelError as exc:
            if exc.code != "UPSTREAM_NETWORK_ERROR":
                raise
            after = await self._repositories_after_ambiguous_write(account)
            if not any(r.get("repository_root") == root for r in after):
                raise self._unknown_write_error() from exc
            reconciled = True
        after = await self._repositories(account)
        created = next((r for r in after if r.get("repository_root") == root), None)
        data: dict[str, Any] = {
            "changed": created is not None,
            "repository_root": root,
            "repository": created,
        }
        if reconciled:
            data["reconciled_after_transport_error"] = True
        return {
            "data": data,
            "after_state": after,
            "verified": created is not None,
            "warnings": (
                [] if created is not None else ["the repository is not listed after the clone"]
            ),
        }

    async def _home(self, account: str) -> str:
        capability = self.harness._get_capability("uapi.DomainInfo.domains_data")
        result = await self.harness.cpanel.call(
            capability, account, {"format": "hash"}, retry_safe=True
        )
        data = result.get("data") if isinstance(result, dict) else None
        main = data.get("main_domain") if isinstance(data, dict) else None
        root = main.get("documentroot") if isinstance(main, dict) else None
        home, _, tail = str(root or "").rstrip("/").rpartition("/")
        if not home.startswith("/") or tail != "public_html":
            raise CPanelError(
                "could not determine the account home directory",
                code="GIT_HOME_UNKNOWN",
                category="validation",
            )
        return home

    async def _repositories(self, account: str | None) -> list[dict[str, Any]]:
        capability = self.harness._get_capability("uapi.VersionControl.retrieve")
        result = await self.harness.cpanel.call(capability, account, {}, retry_safe=True)
        data = result.get("data") if isinstance(result, dict) else None
        return [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []

    async def _repositories_after_ambiguous_write(
        self, account: str | None
    ) -> list[dict[str, Any]]:
        try:
            return await self._repositories(account)
        except CPanelError as exc:
            if exc.code != "UPSTREAM_NETWORK_ERROR":
                raise
            raise self._unknown_write_error() from exc

    @staticmethod
    def _same_remote(repository: dict[str, Any], owner: str, repo: str) -> bool:
        source = repository.get("source_repository")
        url = str(
            (source.get("url") if isinstance(source, dict) else None) or repository.get("url") or ""
        )
        match = _REMOTE.match(scrub_url_userinfo(url).strip())
        return bool(
            match
            and match.group("owner").casefold() == owner.casefold()
            and match.group("repo").casefold() == repo.casefold()
        )

    @staticmethod
    def _capability() -> Capability:
        return Capability(
            id="uapi.VersionControl.create",
            api=ApiFamily.UAPI,
            module="VersionControl",
            function="create",
            title="create",
            description="Internal typed workflow operation.",
            risk=Risk.EXTERNAL_SIDE_EFFECT,
            required_role=Role.OPERATOR,
            upstream_profile="operator",
            input_schema={"type": "object", "additionalProperties": True},
            schema_source="official_cpanel_docs",
            curated=True,
        )

    @staticmethod
    def _unknown_write_error() -> CPanelError:
        return CPanelError(
            "git clone outcome could not be reconciled",
            code="GIT_WRITE_STATE_UNKNOWN",
            details={"state_unknown": True},
            retryable=False,
            hint="List the account's Git repositories before retrying the clone.",
        )
