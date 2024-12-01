import pytest
from py_ad_principal.py_ad_principal import (
    ActiveDirectoryError,
    AuthenticationContextConfig,
)

def test_config_with_missing_config_file():
    with pytest.raises(ActiveDirectoryError):
        AuthenticationContextConfig("my_bogus_config_file.toml")

    config = AuthenticationContextConfig()
    assert config.config_source == "environment variables"

def test_config_with_environment_variables(monkeypatch):
    # Validate kerberos configuration
    monkeypatch.setenv("AD_KRB5_SERVICE", "TEST-SERVICE")    
    monkeypatch.setenv("AD_KRB5_HOSTNAME", "host.domain.local")
    monkeypatch.setenv("AD_KRB5_KEYTAB", "test-service.keytab")

    config = AuthenticationContextConfig()
    assert config.krb5_service == "TEST-SERVICE"
    assert config.krb5_hostname == "host.domain.local"
    assert config.krb5_keytab == "test-service.keytab"    
    assert config.is_krb5_configured

    # Validate LDAP configuration
    monkeypatch.setenv("AD_LDAP_SERVER", "dc.domain.local")
    monkeypatch.setenv("AD_LDAP_USE_TLS", "True")
    monkeypatch.setenv("AD_LDAP_ANONYMOUS_BIND", "False")    
    monkeypatch.setenv("AD_LDAP_BIND_USER", "testuser")
    monkeypatch.setenv("AD_LDAP_BIND_PASSWORD", "testpassword")
    monkeypatch.setenv("AD_LDAP_SEARCH_BASE", "dc=domain,dc=local")
    monkeypatch.setenv("AD_LDAP_NESTED_GROUPS", "True")
    
    assert config.ldap_server == "dc.domain.local"
    assert config.ldap_use_tls
    assert not config.ldap_anonymous_bind
    assert config.ldap_bind_user == "testuser"
    assert config.ldap_bind_password == "testpassword"
    assert config.ldap_search_base == "dc=domain,dc=local"
    assert config.ldap_nested_groups
    assert config.is_ldap_configured

def test_config_from_file():
    config = AuthenticationContextConfig("tests/ad_principal_test_config.toml")
    assert config.config_source == "tests/ad_principal_test_config.toml"

    # Validate kerberos configuration
    assert config.krb5_service == "TEST-SERVICE"
    assert config.krb5_hostname == "host.domain.local"
    assert config.krb5_keytab == "test-service.keytab"    
    assert config.is_krb5_configured

    # Validate LDAP configuration
    assert config.ldap_server == "dc.domain.local"
    assert config.ldap_use_tls
    assert not config.ldap_anonymous_bind
    assert config.ldap_bind_user == "DOMAIN\\Administrator"
    assert config.ldap_bind_password == "MySecretPassword"
    assert config.ldap_search_base == "CN=Users,DC=domain,DC=local"
    assert config.ldap_nested_groups
    assert config.is_ldap_configured    