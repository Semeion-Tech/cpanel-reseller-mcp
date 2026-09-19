from __future__ import annotations

import json
import re
from pathlib import Path

from reseller_mcp.catalog import Catalog, classify
from reseller_mcp.models import Risk, Role


def test_live_catalog_blocks_sensitive_operations(tmp_path) -> None:
    path = tmp_path / "catalog.json"
    path.write_text(
        json.dumps(
            {
                "whm": ["version", "api_token_create"],
                "uapi": ["Email::list_pops", "Tokens::create_full_access"],
            }
        )
    )
    capabilities = {item.id: item for item in Catalog(path).load()}
    assert capabilities["whm.api_token_create"].available is False
    assert capabilities["uapi.Tokens.create_full_access"].available is False
    assert capabilities["whm.version"].available is True
    assert capabilities["whm.listaccts"].available is False
    assert capabilities["database.query_readonly"].available is True
    assert capabilities["database.transaction_execute"].available is True
    assert capabilities["workflow.database_migration_apply"].available is True


def test_known_side_effects_and_sensitive_reads_are_not_plain_reads() -> None:
    assert classify("uapi.Backup.fullbackup_to_ftp") == (
        Risk.EXTERNAL_SIDE_EFFECT,
        Role.ADMIN,
        "admin",
    )
    assert classify("uapi.SiteQuality.send_activation_email")[0] == Risk.EXTERNAL_SIDE_EFFECT
    assert classify("uapi.Email.unset_manual_mx_redirects")[0] == Risk.REVERSIBLE_WRITE
    assert classify("uapi.Fileman.get_file_content")[0] == Risk.SENSITIVE_READ
    assert classify("uapi.EmailAuth.fetch_dkim_private_keys")[0] == Risk.PRIVILEGED


def test_curated_email_auth_schema_declares_domain(tmp_path) -> None:
    capabilities = {item.id: item for item in Catalog(tmp_path / "missing.json").load()}
    schema = capabilities["uapi.EmailAuth.validate_current_dkims"].input_schema
    assert schema["required"] == ["domain"]
    assert schema["additionalProperties"] is False


def test_dns_and_mx_capabilities_have_typed_contracts(tmp_path) -> None:
    capabilities = {item.id: item for item in Catalog(tmp_path / "missing.json").load()}

    assert capabilities["uapi.DNS.lookup"].input_schema["required"] == ["domain"]
    assert capabilities["uapi.DNS.parse_zone"].input_schema["required"] == ["zone"]

    mx_schema = capabilities["uapi.Email.change_mx"].input_schema
    assert mx_schema["required"] == ["domain", "exchanger", "oldexchanger", "priority"]
    assert mx_schema["additionalProperties"] is False
    assert mx_schema["properties"]["priority"] == {"type": "integer", "minimum": 0}

    cname_schema = capabilities["workflow.dns_cname_ensure"].input_schema
    assert cname_schema["required"] == ["zone", "name", "target", "ttl"]
    assert cname_schema["additionalProperties"] is False

    txt_schema = capabilities["workflow.dns_txt_ensure"].input_schema
    assert txt_schema["required"] == ["zone", "name", "value", "ttl"]
    assert txt_schema["additionalProperties"] is False

    remove_schema = capabilities["workflow.dns_record_remove"].input_schema
    assert remove_schema["required"] == ["zone", "name", "record_type", "value"]
    assert remove_schema["additionalProperties"] is False


def test_verbs_glued_to_their_object_are_not_plain_reads() -> None:
    assert classify("uapi.SubDomain.addsubdomain")[0] == Risk.REVERSIBLE_WRITE
    assert classify("whm.savemxs")[0] == Risk.REVERSIBLE_WRITE
    assert classify("whm.editzonerecord")[0] == Risk.REVERSIBLE_WRITE
    assert classify("whm.addpkg")[0] == Risk.REVERSIBLE_WRITE
    assert classify("uapi.Mysql.rename_database")[0] == Risk.REVERSIBLE_WRITE
    assert classify("uapi.DNSSEC.import_zone_key")[0] == Risk.REVERSIBLE_WRITE
    assert classify("whm.killpkg")[0] == Risk.DESTRUCTIVE
    assert classify("whm.resetzone")[0] == Risk.DESTRUCTIVE
    assert classify("whm.removezonerecord")[0] == Risk.DESTRUCTIVE
    assert classify("whm.delpkgext")[0] == Risk.DESTRUCTIVE


def test_read_operations_with_mutating_looking_names_stay_reads() -> None:
    assert classify("uapi.SSL.installed_host")[0] == Risk.READ
    assert classify("uapi.SSL.installed_hosts")[0] == Risk.READ
    # "deliver" must not be mistaken for the "del" prefix of a delete operation.
    assert classify("uapi.BoxTrapper.deliver_messages")[0] == Risk.EXTERNAL_SIDE_EFFECT


def test_no_live_operation_starting_with_a_mutating_verb_is_classified_as_read() -> None:
    live_path = Path(__file__).resolve().parents[1] / "data" / "live_operations.json"
    mutating = re.compile(
        r"^(add|del|delete|set|unset|save|create|remove|kill|park|unpark|edit|change|enable"
        r"|disable|install|upload|rename|restore|reset|import|activate|deactivate|rebuild"
        r"|generate|toggle|cancel|clear|expunge|empty|process|enqueue|swap|configure|recreate"
        r"|reorder|store|ignore|blacklist|whitelist|convert|resize|repair|register|unregister"
        r"|publish|reinstate|dismiss|merge|nvset|dispatch)",
        re.IGNORECASE,
    )
    read_only_names = {"installed_host", "installed_hosts", "configured_modules", "poll_publish"}
    reads = [
        item.id
        for item in Catalog(live_path).load()
        if not item.curated
        and item.risk == Risk.READ
        and item.function not in read_only_names
        and mutating.search(item.function)
    ]
    assert reads == []


def test_redirect_and_domain_read_capabilities_are_typed_reads(tmp_path) -> None:
    capabilities = {item.id: item for item in Catalog(tmp_path / "missing.json").load()}

    redirects = capabilities["uapi.Mime.list_redirects"]
    assert redirects.curated is True
    assert redirects.risk == Risk.READ
    assert redirects.required_role == Role.VIEWER
    assert set(redirects.input_schema["properties"]) == {"destination", "regex"}
    assert redirects.input_schema["additionalProperties"] is False

    domains = capabilities["uapi.DomainInfo.domains_data"]
    assert domains.curated is True
    assert domains.risk == Risk.READ
    assert domains.input_schema["properties"]["format"]["enum"] == ["hash", "list"]
    assert domains.input_schema["additionalProperties"] is False


SSL_READS = [
    "uapi.SSL.installed_hosts",
    "uapi.SSL.list_certs",
    "uapi.SSL.get_autossl_problems",
    "uapi.SSL.get_autossl_excluded_domains",
    "uapi.SSL.get_autossl_pending_queue",
    "uapi.SSL.is_autossl_check_in_progress",
    "uapi.SSL.is_sni_supported",
    "uapi.WebVhosts.list_ssl_capable_domains",
]


def test_ssl_inventory_and_autossl_reads_are_typed_viewer_reads(tmp_path) -> None:
    capabilities = {item.id: item for item in Catalog(tmp_path / "missing.json").load()}

    for operation in SSL_READS:
        capability = capabilities[operation]
        assert capability.curated is True, operation
        assert capability.risk == Risk.READ, operation
        assert capability.required_role == Role.VIEWER, operation
        assert capability.sensitive_output is False, operation
        assert capability.input_schema["additionalProperties"] is False, operation


KEY_EXPOSING_OPERATIONS = [
    "uapi.SSL.show_key",
    "uapi.SSL.fetch_key_and_cabundle_for_certificate",
    "uapi.SSL.generate_key",
    "uapi.SSL.upload_key",
    "uapi.SSL.install_ssl",
    "uapi.SSL.list_keys",
    "uapi.GPG.export_secret_key",
    "uapi.GPG.generate_key",
    "uapi.DNSSEC.export_zone_key",
    "whm.export_zone_key",
    "whm.fetch_vhost_ssl_components",
    "whm.fetchsslinfo",
    "whm.generatessl",
    "whm.installssl",
    "uapi.Batch.strict",
]


def test_operations_that_expose_or_accept_private_keys_are_blocked() -> None:
    live_path = Path(__file__).resolve().parents[1] / "data" / "live_operations.json"
    capabilities = {item.id: item for item in Catalog(live_path).load()}

    for operation in KEY_EXPOSING_OPERATIONS:
        capability = capabilities[operation]
        assert capability.available is False, operation
        assert capability.risk == Risk.PRIVILEGED, operation


def test_public_ssl_reads_stay_available() -> None:
    live_path = Path(__file__).resolve().parents[1] / "data" / "live_operations.json"
    capabilities = {item.id: item for item in Catalog(live_path).load()}

    for operation in [
        "uapi.SSL.installed_hosts",
        "uapi.SSL.list_certs",
        "uapi.SSL.fetch_cert_info",
        "uapi.SSL.get_autossl_problems",
        "uapi.SSL.list_ssl_items",
        "uapi.DNSSEC.export_zone_dnskey",
    ]:
        assert capabilities[operation].available is True, operation
        assert capabilities[operation].risk == Risk.READ, operation


def test_mutations_that_lack_a_verb_from_the_old_list_are_not_reads() -> None:
    assert classify("uapi.Market.cancel_pending_ssl_certificate")[0] == Risk.DESTRUCTIVE
    assert classify("uapi.Fileman.empty_trash")[0] == Risk.DESTRUCTIVE
    assert classify("uapi.Mailboxes.expunge_mailbox_messages")[0] == Risk.DESTRUCTIVE
    assert classify("uapi.SpamAssassin.clear_spam_box")[0] == Risk.DESTRUCTIVE
    assert classify("uapi.Market.process_ssl_pending_queue")[0] == Risk.REVERSIBLE_WRITE
    assert classify("whm.enqueue_deferred_ssl_installations")[0] == Risk.REVERSIBLE_WRITE
    assert classify("uapi.DNS.swap_ip_in_zones")[0] == Risk.REVERSIBLE_WRITE
    assert classify("uapi.CSVImport.doimport")[0] == Risk.REVERSIBLE_WRITE
    assert classify("uapi.Email.fts_rescan_mailbox")[0] == Risk.REVERSIBLE_WRITE
    assert classify("uapi.Email.dispatch_client_settings")[0] == Risk.EXTERNAL_SIDE_EFFECT
    assert classify("whm.nvset")[0] == Risk.REVERSIBLE_WRITE


def test_status_reads_named_like_mutations_stay_reads() -> None:
    assert classify("uapi.Sitejet.poll_publish")[0] == Risk.READ
    assert classify("uapi.ExternalAuthentication.configured_modules")[0] == Risk.READ
