from py_ad_principal.py_ad_principal import (
    ActiveDirectoryPrincipal,
    _default_role_mapper,
)


def test_default_role_mapper():
    # Test with an empty list
    result = _default_role_mapper([])
    assert result == []

    # Test with None
    result = _default_role_mapper(None)
    assert result == []

    # Test with a list of roles with an embedded None
    result = _default_role_mapper(
        ["App Admin Group", "App View Group", None, "App Edit Group"]
    )
    assert result and len(result) == 3
    assert "app_admin_group" in result
    assert "app_view_group" in result
    assert "app_edit_group" in result


def test_principal_properties():
    # Test basic properties with "good" values
    principal = ActiveDirectoryPrincipal(
        "test_user@test_domain", "test_user", "test_user@testdomain.local", "Test User"
    )
    assert principal.principal_name == "test_user@test_domain"
    assert principal.sam_account_name == "test_user"
    assert principal.user_principal_name == "test_user@testdomain.local"
    assert principal.display_name == "Test User"
    assert principal.groups == []
    assert principal.roles == []

    # Test init with malformed principal name only
    principal = ActiveDirectoryPrincipal("test_user@test_domain")
    assert principal.principal_name == "test_user@test_domain"
    assert principal.sam_account_name == "test_user"
    assert principal.user_principal_name == "test_user"
    assert principal.display_name == "test_user"

    # Test init with malformed principal name only
    principal = ActiveDirectoryPrincipal("test_user")
    assert principal.principal_name == "test_user"
    assert principal.sam_account_name == "test_user"
    assert principal.user_principal_name == "test_user"
    assert principal.display_name == "test_user"


def test_role_mapping():
    # Test the default role mapper
    principal = ActiveDirectoryPrincipal(
        "test_user@test_domain",
        groups=["App Admin Group", "App View Group", "App Edit Group"],
    )

    assert principal.groups and len(principal.groups) == 3
    assert (
        "App Admin Group" in principal.groups
        and "App View Group" in principal.groups
        and "App Edit Group" in principal.groups
    )

    assert principal.roles and len(principal.roles) == 3
    assert (
        "app_admin_group" in principal.roles
        and "app_view_group" in principal.roles
        and "app_edit_group" in principal.roles
    )
    assert (
        principal.has_role("app_admin_group")
        and principal.has_role("app_view_group")
        and principal.has_role("app_edit_group")
    )

    # Test a custom role mapper
    def custom_role_mapper(roles):
        return ["DEFAULT-ROLE"] + [
            role.upper().replace(" ", "-")
            for role in roles
            if role != "App Admin Group"
        ]

    principal = ActiveDirectoryPrincipal(
        "test_user@test_domain",
        groups=["App Admin Group", "App View Group", "App Edit Group"],
        role_mapper=custom_role_mapper,
    )

    assert principal.roles and len(principal.roles) == 3
    assert (
        "DEFAULT-ROLE" in principal.roles
        and "APP-VIEW-GROUP" in principal.roles
        and "APP-EDIT-GROUP" in principal.roles
    )
    assert (
        principal.has_role("DEFAULT-ROLE")
        and principal.has_role("APP-VIEW-GROUP")
        and principal.has_role("APP-EDIT-GROUP")
    )
