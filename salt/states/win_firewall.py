"""
State for configuring Windows Firewall
"""

from salt.exceptions import CommandExecutionError, SaltInvocationError


def __virtual__():
    """
    Load if the module firewall is loaded
    """
    if "firewall.get_config" in __salt__:
        return "win_firewall"
    return (False, "firewall module could not be loaded")


def disabled(name="allprofiles"):
    """
    Disable all the firewall profiles (Windows only)

    Args:
        profile (Optional[str]): The name of the profile to disable. Default is
            ``allprofiles``. Valid options are:

            - allprofiles
            - domainprofile
            - privateprofile
            - publicprofile

    Example:

    .. code-block:: yaml

        # To disable the domain profile
        disable_domain:
          win_firewall.disabled:
            - name: domainprofile

        # To disable all profiles
        disable_all:
          win_firewall.disabled:
            - name: allprofiles
    """
    ret = {"name": name, "result": True, "changes": {}, "comment": ""}

    profile_map = {
        "domainprofile": "Domain",
        "privateprofile": "Private",
        "publicprofile": "Public",
        "allprofiles": "All",
    }

    # Make sure the profile name is valid
    if name not in profile_map:
        raise SaltInvocationError(f"Invalid profile name: {name}")

    current_config = __salt__["firewall.get_config"]()
    if name != "allprofiles" and profile_map[name] not in current_config:
        ret["result"] = False
        ret["comment"] = f"Profile {name} does not exist in firewall.get_config"
        return ret

    for key in current_config:
        if current_config[key]:
            if name == "allprofiles" or key == profile_map[name]:
                ret["changes"][key] = "disabled"

    if __opts__["test"]:
        ret["result"] = not ret["changes"] or None
        ret["comment"] = ret["changes"]
        ret["changes"] = {}
        return ret

    # Disable it
    if ret["changes"]:
        try:
            ret["result"] = __salt__["firewall.disable"](name)
        except CommandExecutionError:
            ret["comment"] = "Firewall Profile {} could not be disabled".format(
                profile_map[name]
            )
    else:
        if name == "allprofiles":
            msg = "All the firewall profiles are disabled"
        else:
            msg = f"Firewall profile {name} is disabled"
        ret["comment"] = msg

    return ret


def delete_rule(name=None, rule_name=None, group=None, localport=None, protocol=None, dir=None, remoteip=None, log_only=False):
    """
    Delete an existing firewall rule identified by name and optionally by ports,
    protocols, direction, and remote IP.

    Args:

        rule_name (str):
            The name of the rule to delete. If the name ``all`` is used, you
            must specify additional parameters. Cannot be used with group.

        group (str):
            The group name of the rule to delete. Cannot be used with name.

        localport (:obj:`str`, optional):
            The port of the rule. If protocol is not specified, protocol will be
            set to ``tcp``. Default is ``None``.

        protocol (:obj:`str`, optional):
            The protocol of the rule. Default is ``tcp`` when ``localport`` is
            specified. Default is ``None``.

        dir (:obj:`str`, optional):
            The direction of the rule. Default is ``None``.

        remoteip (:obj:`str`, optional):
            The remote IP of the rule. Default is ``None``.

    Example:

    .. code-block:: yaml

        delete_smb_port:
          win_firewall.delete_rule:
            - name: SMB (445)
    """
    ret = {"name": name, "result": True, "changes": {}, "comment": ""}

    # Check if rule exists
    if __salt__["firewall.rule_exists"]( rule_name if rule_name else group ):
        ret["changes"] = {"deleted rule": rule_name if rule_name else group}

    if __opts__["test"] or log_only:
        ret["result"] = not ret["changes"] or None
        ret["comment"] = ret["changes"]
        ret["changes"] = {}
        return ret

    # Add rule
    try:
        __salt__["firewall.delete_rule"](rule_name, group, localport, protocol, dir, remoteip)
        ret["changes"] = {"deleted rule": name}
    except CommandExecutionError as err:
        ret["changes"] = {}
        ret["result"] = False
        ret["comment"] = f"Could not delete rule {rule_name}, {group}: {err}"
        ret["error"] = f"{err}"

    return ret


def add_rule(name, localport, protocol="tcp", action="allow", dir="in", remoteip="any", remoteport="any", program=None, service=None):
    """
    Add a new inbound or outbound rule to the firewall policy

    Args:

        name (str): The name of the rule. Must be unique and cannot be "all".
            Required.

        localport (int): The port the rule applies to. Must be a number between
            0 and 65535. Can be a range. Can specify multiple ports separated by
            commas. Required.

        protocol (Optional[str]): The protocol. Can be any of the following:

            - A number between 0 and 255
            - icmpv4
            - icmpv6
            - tcp
            - udp
            - any

        action (Optional[str]): The action the rule performs. Can be any of the
            following:

            - allow
            - block
            - bypass

        dir (Optional[str]): The direction. Can be ``in`` or ``out``.

        remoteip (Optional [str]): The remote IP. Can be any of the following:

            - any
            - localsubnet
            - dns
            - dhcp
            - wins
            - defaultgateway
            - Any valid IPv4 address (192.168.0.12)
            - Any valid IPv6 address (2002:9b3b:1a31:4:208:74ff:fe39:6c43)
            - Any valid subnet (192.168.1.0/24)
            - Any valid range of IP addresses (192.168.0.1-192.168.0.12)
            - A list of valid IP addresses

            Can be combinations of the above separated by commas.

        program (Optional [str]): The full path to an executable. Examples are:
        
            - %systemroot%\\system32\\svchost.exe
            - c:\\progam files\\application\\binary.exe

        service (Optional [str]): The shortname of a service. Examples are:
        
            - eventlog
            - rpcss


            .. versionadded:: 2016.11.6

    Example:

    .. code-block:: yaml

        open_smb_port:
          win_firewall.add_rule:
            - name: SMB (445)
            - localport: 445
            - protocol: tcp
            - action: allow
    """
    ret = {"name": name, "result": True, "changes": {}, "comment": ""}

    # Check if rule exists
    if not __salt__["firewall.rule_exists"](name):
        ret["changes"] = {"new rule": name}
    else:
        ret["comment"] = "A rule with that name already exists"
        return ret

    if __opts__["test"]:
        ret["result"] = not ret["changes"] or None
        ret["comment"] = ret["changes"]
        ret["changes"] = {}
        return ret

    # Add rule
    try:
        __salt__["firewall.add_rule"](name, localport, protocol, action, dir, remoteip, remoteport, program, service)
    except CommandExecutionError:
        ret["result"] = False
        ret["changes"] = {}
        ret["comment"] = "Could not add rule"

    return ret


def enabled(name="allprofiles"):
    """
    Enable all the firewall profiles (Windows only)

    Args:
        profile (Optional[str]): The name of the profile to enable. Default is
            ``allprofiles``. Valid options are:

            - allprofiles
            - domainprofile
            - privateprofile
            - publicprofile

    Example:

    .. code-block:: yaml

        # To enable the domain profile
        enable_domain:
          win_firewall.enabled:
            - name: domainprofile

        # To enable all profiles
        enable_all:
          win_firewall.enabled:
            - name: allprofiles
    """
    ret = {"name": name, "result": True, "changes": {}, "comment": ""}

    profile_map = {
        "domainprofile": "Domain",
        "privateprofile": "Private",
        "publicprofile": "Public",
        "allprofiles": "All",
    }

    # Make sure the profile name is valid
    if name not in profile_map:
        raise SaltInvocationError(f"Invalid profile name: {name}")

    current_config = __salt__["firewall.get_config"]()
    if name != "allprofiles" and profile_map[name] not in current_config:
        ret["result"] = False
        ret["comment"] = f"Profile {name} does not exist in firewall.get_config"
        return ret

    for key in current_config:
        if not current_config[key]:
            if name == "allprofiles" or key == profile_map[name]:
                ret["changes"][key] = "enabled"

    if __opts__["test"]:
        ret["result"] = not ret["changes"] or None
        ret["comment"] = ret["changes"]
        ret["changes"] = {}
        return ret

    # Enable it
    if ret["changes"]:
        try:
            ret["result"] = __salt__["firewall.enable"](name)
        except CommandExecutionError:
            ret["result"]: False
            ret["comment"] = "Firewall Profile {} could not be enabled".format(
                profile_map[name]
            )
    else:
        if name == "allprofiles":
            msg = "All the firewall profiles are enabled"
        else:
            msg = f"Firewall profile {name} is enabled"
        ret["comment"] = msg

    return ret

def set_setting(profile,  store="local", **settings):
    ret = {"result": True, "changes": {}, "comment": "", 'name': ""}
    settings_map = {
        "inbound": "Inbound",
        "outbound": "Outbound",
        "allowedconnections": "LogAllowedConnections",
        "droppedconnections": "LogDroppedConnections",
        "filename": "FileName",
        "maxfilesize": "MaxFileSize",
        "localfirewallrules": "LocalFirewallRules",
        "localconsecrules": "LocalConSecRules",
        "inboundusernotification": "InboundUserNotification",
        "unicastresponsetomulticast": "UnicastResponseToMulticast",
        "on": "On",
        "state": "State"
    }

    section_map = {
        "inbound": "firewallpolicy",
        "outbound": "firewallpolicy",
        "allowedconnections": "firewallpolicy", 
        "droppedconnections": "firewallpolicy",
        "filename": "logging",
        "maxfilesize": "logging",
        "allowedconnections": "logging", 
        "droppedconnections": "logging", 
        "localfirewallrules": "settings", 
        "localconsecrules": "settings", 
        "inboundusernotification": "settings", 
        "unicastresponsetomulticast": "settings",
        "state": "state"
    }

    firewall_map = {
        "state": "firewall.set_state",
        "firewallpolicy": "firewall.set_firewall_settings",
        "logging": "firewall.set_logging_settings",
        "settings": "firewall.set_settings"
    }

    updates = {}
    try:
        current_settings = __salt__["firewall.get_all_settings"](profile)
    except CommandExecutionError:
        ret["comment"] = f"Firewall Profile {profile} could not be loaded"
        return ret

    for setting, value in settings['settings'].items():
        section = section_map[setting]
        if str(value).lower() != current_settings[settings_map[setting]].lower():
            if section not in updates:
                updates[section] = {}
            updates[section][setting] = value
            ret["changes"][f"{section}-{setting}"] = f"{current_settings[settings_map[setting]]} -> {value}"

    for section, settings in updates.items():
        if section == 'state':
            if 'state' not in settings:
                ret['error'] = "Missing required argument: state"
            else:
                res = __salt__[firewall_map[section]](profile, settings['state'], store)
                ret['comment'] += f"{section}: {res}\n"
        if section == 'firewallpolicy':
            if 'inbound' not in settings and 'outbound' not in settings:
                ret['error'] = "Missing required argument: [inbound|outbound]"
            else:
                for key in ['outbound', 'inbound']:
                    if key not in settings:
                        settings[key] = None
            res = __salt__[firewall_map[section]](profile, settings['inbound'], settings['outbound'], store)
            ret['comment'] += f"{section}: {res}\n"
        if section in ["logging", "settings"]:
            for setting,value in settings.items():
                res = __salt__[firewall_map[section]](profile, setting, value, store)
                ret['comment'] += f"{section} - {setting}: {res}\n"

    return ret

