# Copyright 2024 Jason Hallford

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import logging
import base64
import os
import re
import tomllib
from typing import Callable

from gssapi import Name, NameType, SecurityContext
from gssapi.creds import Credentials
from gssapi.exceptions import GSSError
from socket import gethostname
from ldap3 import (
    ANONYMOUS,
    AUTO_BIND_NO_TLS,
    AUTO_BIND_TLS_BEFORE_BIND,
    RESTARTABLE,
    SIMPLE,
    Connection,
)

_logger = logging.getLogger(__name__)


def _default_role_mapper(group: str) -> str:
    """Default role mapper function that normalizes group names to lowercase and replaces spaces with underscores."""
    if group:
        return group.lower().replace(" ", "_")

    return group


class AuthenticationContextConfig:
    """Configuration for an Active Directory authentication context. This class encapsulated logic to read
    configuration settings from a TOML file or selectively override them via environment variables.
    """

    def __init__(self, config_file: str = "py_ad_principal.toml"):
        """Initializes a new Active Directory authentication context configuration.

        Args:
            config_file (str, optional): A TOML file from which to read configuration values. Defaults to "ad_principal.toml".

        Raises:
            ActiveDirectoryError: Raised when an error occurs loading or processing the configuration file.
        """
        if config_file:
            _logger.debug(
                "Loading base Active Directory configuration from %s.", config_file
            )
            try:
                with open(config_file, "rb") as f:
                    self._config = tomllib.load(f)

                self._config_source = config_file
            except Exception as e:
                raise ActiveDirectoryError(
                    "Unable to load Active Directory configuration from %s!",
                    config_file,
                ) from e
        else:
            _logger.warning(
                "No configuration file provided; values must be provided via environment variables."
            )
            self._config = {}
            self._config_source = "environment variables"

    @property
    def config_source(self) -> str:
        """The source of the configuration settings.

        Returns:
            str: A path to the configuration file or 'environment variables'.
        """
        return self._config_source

    @property
    def krb5_service(self) -> str:
        """The Kerberos 5 (WNA) service name as read from the configuration file or overridden by the AD_KRB5_SERVICE
        environment variable. Defaults to 'HTTP'.

        Returns:
            str: The Kerberos 5 service name.
        """
        return (
            os.getenv("AD_KRB5_SERVICE")
            if "AD_KRB5_SERVICE" in os.environ
            else self._config.get("krb5", {}).get("service", "HTTP")
        )

    @property
    def krb5_hostname(self) -> str:
        """The Kerberos 5 (WNA) hostname as read from the configuration file or overridden by the AD_KRB5_HOSTNAME
        environment variable. Defaults to the hostname of the local machine.

        Returns:
            str: The Kerberos 5 hostname.
        """
        return (
            os.getenv("AD_KRB5_HOSTNAME")
            if "AD_KRB5_HOSTNAME" in os.environ
            else self._config.get("krb5", {}).get("hostname", gethostname())
        )

    @property
    def krb5_keytab(self) -> str:
        """The path to the Kerberos 5 keytab file as read from the configuration file or overridden by the AD_KRB5_KEYTAB
        environment variable. Defaults to '/etc/krb5.keytab'.

        Returns:
            str: The path to the Kerberos 5 keytab file.
        """
        return (
            os.getenv("AD_KRB5_KEYTAB")
            if "AD_KRB5_KEYTAB" in os.environ
            else self._config.get("krb5", {}).get("keytab", "/etc/krb5.keytab")
        )

    @property
    def is_krb5_configured(self) -> bool:
        """Check if the Kerberos 5 configuration is complete.

        Returns:
            bool: True if the Kerberos 5 configuration is complete; otherwise, False.
        """
        return self.krb5_service and self.krb5_hostname and self.krb5_keytab

    @property
    def ldap_server(self) -> str:
        """The LDAP server hostname as read from the configuration file or overridden by the AD_LDAP_SERVER
        environment variable. Defaults to None.

        Returns:
            str: The LDAP server hostname.
        """
        return (
            os.getenv("AD_LDAP_SERVER")
            if "AD_LDAP_SERVER" in os.environ
            else self._config.get("ldap", {}).get("server", None)
        )

    @property
    def ldap_use_tls(self) -> bool:
        """The LDAP server TLS setting as read from the configuration file or overridden by the AD_LDAP_USE_TLS
        environment variable. Defaults to False.

        Returns:
            bool: True if the LDAP server uses TLS; otherwise, False.
        """
        return (
            os.getenv("AD_LDAP_USE_TLS")
            if "AD_LDAP_USE_TLS" in os.environ
            else self._config.get("ldap", {}).get("use_tls", False)
        )

    @property
    def ldap_anonymous_bind(self) -> bool:
        """The LDAP server anonymous bind setting as read from the configuration file or overridden by the AD_LDAP_ANONYMOUS_BIND
        environment variable. Defaults to False.

        Returns:
            bool: True if the LDAP server support an anonymous bind; otherwise, False.
        """
        return (
            os.getenv("AD_LDAP_ANONYMOUS_BIND")
            if "AD_LDAP_ANONYMOUS_BIND" in os.environ
            else self._config.get("ldap", {}).get("anonymous_bind", False)
        )

    @property
    def ldap_bind_user(self) -> str:
        """The LDAP server bind user as read from the configuration file or overridden by the AD_LDAP_BIND_USER
        environment variable. Defaults to None, but this is an error if the LDAP doesn't support anonymous binds.

        Returns:
            str: The LDAP server bind user.
        """
        return (
            os.getenv("AD_LDAP_BIND_USER")
            if "AD_LDAP_BIND_USER" in os.environ
            else self._config.get("ldap", {}).get("bind_user", None)
        )

    @property
    def ldap_bind_password(self) -> str:
        """The LDAP server bind password as read from the configuration file or overridden by the AD_LDAP_BIND_PASSWORD
        environment variable. Defaults to None, but this is an error if the LDAP doesn't support anonymous binds.

        Returns:
            str: The LDAP server bind password.
        """
        return (
            os.getenv("AD_LDAP_BIND_PASSWORD")
            if "AD_LDAP_BIND_PASSWORD" in os.environ
            else self._config.get("ldap", {}).get("bind_password", None)
        )

    @property
    def ldap_search_base(self) -> str:
        """The LDAP server search base (e.g., "DC=Org Unit, DC=Org") as read from the configuration file or overridden
        by the AD_LDAP_SEARCH_BASE environment variable. Defaults to None.

        Returns:
            str: The LDAP server search base.
        """
        return (
            os.getenv("AD_LDAP_SEARCH_BASE")
            if "AD_LDAP_SEARCH_BASE" in os.environ
            else self._config.get("ldap", {}).get("search_base", None)
        )

    @property
    def ldap_nested_groups(self) -> bool:
        """The LDAP server nested groups setting as read from the configuration file or overridden by the AD_LDAP_NESTED_GROUPS
        environment variable. If True, then one level of nested groups will be included in the principal's memberships.
        Defaults to False.

        Returns:
            bool: True if nested groups are included; otherwise, False.
        """
        return (
            os.getenv("AD_LDAP_NESTED_GROUPS")
            if "AD_LDAP_NESTED_GROUPS" in os.environ
            else self._config.get("ldap", {}).get("nested_groups", False)
        )

    @property
    def is_ldap_configured(self) -> bool:
        """Check if the LDAP configuration is complete, here defined as having a server, bind user, bind password, and search base.
        The bind user and password may be omitted if the LDAP server supports anonymous binds.

        Returns:
            bool: True if the LDAP configuration is complete; otherwise, False.
        """
        return (
            self.ldap_server
            and (
                self.ldap_anonymous_bind
                or (self.ldap_bind_user and self.ldap_bind_password)
            )
            and self.ldap_search_base
        )


class ActiveDirectoryError(Exception):
    """Raised when an error occurs in any Active Directory operation. Here, these include communication
    with the KDC (via GSSAPI) and LDAP operations.

    Args:
        Exception (_type_): This error is a subclass of the built-in Exception class.
    """

    def __init__(self, message: str):
        """Initializes a new Active Directory error.

        Args:
            message (str): The error message.
        """
        super().__init__(message)


class ActiveDirectoryPrincipal:
    """An authenticated Active Directory user principal with an optional list of roles."""

    def __init__(
        self,
        principal: str,
        sam_account_name: str = None,
        user_principal_name: str = None,
        display_name: str = None,
        groups: list[str] = [],
        role_mapper: Callable[[str], str] = _default_role_mapper,
    ):
        """Initializes a new Active Directory principal.

        Args:
            principal (str): The fully qualified principal name (e.g., "user@REALM").
            sam_account_name (str, optional): The principal's unique sAMAccountName. Defaults to None.
            user_principal_name (str, optional): The principal's unique userPrincipalName. Defaults to None.
            groups (list, optional): A list of active directory group memberships. Limit names to the
                                     value of the CN attribute. Defaults to an empty list.
            role_mapper (Callable, optional): A function that maps a AD group to an application-specific
                                     role. Defaults to None.
        """
        self._principal_name = principal
        self._sam_account_name = (
            sam_account_name if sam_account_name else principal.split("@")[0].strip()
        )
        self._user_principal_name = (
            user_principal_name if user_principal_name else sam_account_name
        )
        self._display_name = display_name
        self._groups = groups.copy() if (groups and len(groups) > 0) else groups
        self._roles = [role_mapper(group) for group in self._groups]

    def __repr__(self):
        return f"<User {self._principal_name}>"

    @property
    def principal_name(self) -> str:
        """The fully qualified principal name (e.g., "user@REALM").

        Returns:
            str: The qualified principal name.
        """
        return self._principal_name

    @property
    def sam_account_name(self) -> str:
        """The value of the principal's sAMAccountName attribute.

        Returns:
            str: The sam account name.
        """
        return self._friendly_name

    @property
    def user_principal_name(self) -> str:
        """The value of the principal's userPrincipalName attribute or sAMAccountName, in unavailable.

        Returns:
            str: The user principal name.
        """
        return self._user_principal_name

    @property
    def display_name(self) -> str:
        """The display name of the principal. If not available, the friendly name is used instead.

        Returns:
            str: The display name.
        """
        return self._display_name

    @property
    def groups(self) -> list[str]:
        """The principal's group memberships. Names are limited to the value of the CN attribute.

        Returns:
            list[str]: The principal's group memberships.
        """
        return self._groups.copy()

    @property
    def roles(self) -> list[str]:
        """The principal's application-specific roles.

        Returns:
            list[str]: The principal's roles.
        """
        return self._roles.copy()

    def has_role(self, role: str) -> bool:
        """Check if the principal has a specific role.

        Args:
            role (str): The role to check.

        Returns:
            bool: True if the principal has the role; otherwise, False.
        """
        return role in self._roles


class AuthenticationResult:
    """Encapsulates the result of an authentication attempt."""

    def __init__(
        self,
        server_token: str = None,
        principal: ActiveDirectoryPrincipal = None,
        error: ActiveDirectoryError = None,
    ):
        """Initializes a new authentication result.

        Args:
            auth_token (str, optional): An optional service principal-generated authentication token.
                                        Defaults to None.
            principal (ActiveDirectoryPrincipal, optional): An initialized, authenticated Active Directory principal.
                                                            Defaults to None.
            error (Exception, optional): An error generated and captured during authentication or group resolution.
                                        Defaults to None.
        """
        self._server_token = server_token
        self._principal = principal
        self._error = error

    @property
    def server_token(self) -> str:
        """An optional, service principal-generated authentication token.

        Returns:
            str: The base64-encoded authentication token.
        """
        return self._server_token

    @property
    def principal(self) -> ActiveDirectoryPrincipal:
        """An optional, initialized and authenticated Active Directory principal.

        Returns:
            ActiveDirectoryPrincipal: The authenticated principal.
        """
        return self._principal

    @property
    def error(self) -> Exception:
        """An optional error generated and captured during authentication or group resolution.

        Returns:
            Exception: The error.
        """
        return self._error


class AuthenticationContext:
    """An Active Directory authentication context that uses GSSAPI to authenticate users and LDAP to resolve group memberships."""

    def __init__(self, config: AuthenticationContextConfig):
        """Initializes a new Active Directory authentication context.

        Args:
            config (AuthenticationContextConfig): An initialized Active Directory authentication context configuration.

        Raises:
            ValueError: If no configuration is provided or if the configuration is incomplete.
            ActiveDirectoryError: If an error occurs during GSSAPI authentication or LDAP group resolution.
        """
        if not config:
            raise ValueError(
                "No configuration provided for Active Directory authentication context."
            )
        elif not config.is_krb5_configured:
            raise ActiveDirectoryError(
                "Kerberos 5 configuration is incomplete; ensure that the service, hostname, and keytab are provided."
            )
        elif not config.is_ldap_configured:
            _logger.warning(
                "LDAP configuration is incomplete; group resolution will not be available."
            )

        try:
            self._gss_spn = Name(
                f"{config.krb5_service}@{config.krb5_hostname}",
                name_type=NameType.hostbased_service,
            )
            _logger.info("SPN: %s", self._gss_spn)
            self._gss_creds = self._init_service_credentials(self._gss_spn, config)

            _logger.debug("Loading LDAP configuration from %s.", config.config_source)
            if config.is_ldap_configured:
                self._ldap_conn = self._init_ldap_connection(config)
                self._ldap_search_base = config.ldap_search_base
                self._ldap_nested_groups = config.ldap_nested_groups
                _logger.debug(
                    "Successfully connected to LDAP server; search base: %s",
                    self._ldap_search_base,
                )

        except Exception as e:
            raise ActiveDirectoryError(
                "Unable to initializing Active Directory authentication context!"
            ) from e

    def _init_service_credentials(
        self, spn: Name, config: AuthenticationContextConfig
    ) -> Credentials:
        try:
            _logger.debug(
                "Acquiring credentials for SPN %s from keytab %s.",
                spn,
                config.krb5_keytab,
            )
            creds = Credentials(
                name=self._gss_spn,
                usage="accept",
                store={"keytab": config.krb5_keytab},
            )
            _logger.debug("Credentials for SPN %s acquired successfully.", creds.name)

            return creds
        except Exception as e:
            raise ActiveDirectoryError(
                "GSSAPI was unable to acquire the service credentials."
            ) from e

    def _init_ldap_connection(self, config: AuthenticationContextConfig) -> None:
        try:
            _logger.debug(
                "Connecting to LDAP server %s.",
                config.ldap_server,
            )

            if config.ldap_anonymous_bind:
                ldap_conn = Connection(
                    config.ldap_server,
                    auto_bind=AUTO_BIND_TLS_BEFORE_BIND
                    if config.ldap_use_tls
                    else AUTO_BIND_NO_TLS,
                    client_strategy=RESTARTABLE,
                    authentication=ANONYMOUS,
                    check_names=True,
                    read_only=True,
                )
            else:
                ldap_conn = Connection(
                    config.ldap_server,
                    auto_bind=AUTO_BIND_TLS_BEFORE_BIND
                    if config.ldap_use_tls
                    else AUTO_BIND_NO_TLS,
                    client_strategy=RESTARTABLE,
                    authentication=SIMPLE,
                    check_names=True,
                    read_only=True,
                    user=config.ldap_bind_user,
                    password=config.ldap_bind_password,
                )

            if not ldap_conn.bound:
                raise ActiveDirectoryError(
                    "Unable to bind to LDAP server using provided credentials."
                )
            else:
                return ldap_conn

        except Exception as e:
            raise ActiveDirectoryError(
                "Unable to establish connection to LDAP server %s.", config.ldap_server
            ) from e

    def is_valid_token(self, auth_token: str) -> bool:
        """Check if a client-provided authentication token is a Kerberos 5 ticket-granting ticket as recognized
        by Active Directory.

        Args:
            auth_token (str): A base64-encoded authentication token. This token may be prefixed with 'Negotiate ',
                              which is stripped before decoding.

        Returns:
            bool: True if the token is a Kerberos 5 ticket-granting ticket; otherwise, False.
        """
        is_ad_token = False

        if auth_token:
            try:
                _logger.debug("Validating authorization token: %s", auth_token)

                spnego_token = self._decode_auth_token(auth_token)

                # By convention, Kerberos 5 tokens (as employed by Active Directory) start
                # with 0x82 or 0x60.
                is_ad_token = spnego_token.startswith(
                    b"\x82"
                ) or spnego_token.startswith(b"\x60")
                _logger.debug("Token recognized as Kerberos 5 TGT: %s", is_ad_token)
            except Exception as e:
                _logger.error("Error validating authorization token: %s", e)
        else:
            _logger.debug("auth_token is empty; validation will not occur.")

        return is_ad_token

    def authenticate_principal(
        self,
        auth_token: str,
        resolve_groups: bool = False,
        role_mapper: Callable[[str], str] = None,
    ) -> AuthenticationResult:
        """Authenticate a user principal via a client-provided Kerberos 5 ticket-granting ticket authentication token,
         optionally resolving group memberships and mapping them to application roles.

        Args:
            auth_token (str): A base64-encoded authentication token, optionally prefixed with 'Negotiate '.
            resolve_groups (bool, optional): If True, resolve group memberships and map them to application roles.
                                             Defaults to False.
            role_mapper (Callable, optional): A function that maps an AD group's common name to an application-specific role.

        Returns:
            AuthenticationResult: An authentication result object containing the principal or any errors encountered.
        """

        principal = None
        b64_server_token = None

        try:
            client_token = self._decode_auth_token(auth_token)
            server_ctx = SecurityContext(creds=self._gss_creds, usage="accept")
            server_token = server_ctx.step(client_token)

            if server_ctx.complete:
                sam_account_name = str(server_ctx.initiator_name).split("@")[0].strip()
                user_principal_name, display_name = self._resolve_user_attributes(
                    sam_account_name
                )

                if resolve_groups:
                    ldap_groups = self._resolve_user_groups(sam_account_name)
                else:
                    ldap_groups = []

                principal = ActiveDirectoryPrincipal(
                    principal=str(server_ctx.initiator_name),
                    sam_account_name=sam_account_name,
                    user_principal_name=user_principal_name,
                    display_name=display_name,
                    groups=ldap_groups,
                    role_mapper=role_mapper,
                )
                _logger.info(
                    "User %s successfully authenticated via GSS API.", principal.name
                )
            elif server_token:
                b64_server_token = base64.b64encode(server_token).decode("utf-8")
                _logger.debug("Server token generated: %s", b64_server_token)

            return AuthenticationResult(
                server_token=b64_server_token, principal=principal
            )

        except GSSError as gse:
            _logger.error("Error acquiring client credentials: %s", gse)
            return AuthenticationResult(error=gse)
        except Exception as e:
            _logger.error("Unexpected error: %s", e)
            return AuthenticationResult(error=e)

    def _resolve_user_attributes(self, sam_account_name: str) -> tuple[str, str]:
        """Load the user's userPrincipalName and displayName from LDAP."""
        user_principal_name = None
        display_name = None

        try:
            _logger.debug(
                "Retrieving userPrincipalName and displayName for sAMAccountName %s.",
                sam_account_name,
            )
            search_filter = f"(&(objectClass=user)(sAMAccountName={sam_account_name}))"
            self._ldap_conn.search(
                search_base=self._ldap_search_base,
                search_filter=search_filter,
                attributes=["userPrincipalName", "displayName"],
            )

            if self._ldap_conn.entries:
                user_principal_name = self._ldap_conn.entries[0].userPrincipalName.value
                display_name = self._ldap_conn.entries[0].displayName.value
                _logger.debug(
                    "User %s has UPN %s and display name %s.",
                    sam_account_name,
                    user_principal_name,
                    display_name,
                )
            else:
                _logger.debug("No user attributes found for user %s.", sam_account_name)

        except Exception as e:
            raise ActiveDirectoryError(
                f"Error loading user attributes for user {sam_account_name}: {e}"
            ) from e

        return user_principal_name, display_name

    def _resolve_user_groups(self, sam_account_name: str) -> list[dict[str, str]]:
        """Load the groups for a user from LDAP."""
        groups = []

        try:
            _logger.debug(
                "Retrieving DN and top-level group memberships for user %s.",
                sam_account_name,
            )
            search_filter = f"(&(objectClass=user)(sAMAccountName={sam_account_name}))"
            self._ldap_conn.search(
                search_base=self._ldap_search_base,
                search_filter=search_filter,
                attributes=["memberOf", "distinguishedName", "cn"],
            )

            if self._ldap_conn.entries:
                cn = self._ldap_conn.entries[0].cn.value
                dn = self._ldap_conn.entries[0].distinguishedName.value
                _logger.debug("User %s has CN %s and DN %s.", sam_account_name, cn, dn)

                for entry in self._ldap_conn.entries:
                    for group in entry.memberOf.values:
                        group_cn = re.search(r"CN=(.*?),", group).group(1)
                        groups.append({"cn": group_cn, "dn": group})
                        _logger.debug(
                            "User %s is a member of group %s.", sam_account_name, group
                        )
            else:
                _logger.debug("No groups found for user %s.", sam_account_name)

            # This module supports one level of nested groups. This feature support the common use
            # case where a "global group" (usually aligned to a org function) contains user principals
            # and they are member of "local groups" that map to application-specific roles.
            nested_groups = []
            if self._ldap_nested_groups:
                _logger.debug(
                    "Resolving nested group memberships for user %s.", sam_account_name
                )
                for group in groups:
                    search_filter = f"(&(objectClass=group)(member={group['dn']}))"
                    self._ldap_conn.search(
                        search_base=self._ldap_search_base,
                        search_filter=search_filter,
                        attributes=["distinguishedName", "cn"],
                    )

                    if self._ldap_conn.entries:
                        for entry in self._ldap_conn.entries:
                            nested_groups.append(
                                {
                                    "cn": entry.cn.value,
                                    "dn": entry.distinguishedName.value,
                                }
                            )
                    else:
                        _logger.debug(
                            "No nested groups found for group %s.", group["dn"]
                        )

            groups.extend(nested_groups)

        except Exception as e:
            _logger.error("Error loading groups for user %s: %s", sam_account_name, e)

        return groups

    def _decode_auth_token(self, auth_token: str) -> bytes:
        if auth_token:
            _logger.debug("Decoding authorization token: %s", auth_token)

            if auth_token.startswith("Negotiate "):
                encoded_token = auth_token[len("Negotiate ") :]
                _logger.debug("Negotiate header stripped from encoded token.")
            else:
                encoded_token = auth_token
                _logger.debug("No Negotiate header found; decoding token as-is.")

            return base64.b64decode(encoded_token)

        return None
