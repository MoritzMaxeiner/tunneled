module tunneled.net;

struct Routing
{
    ubyte    table      = 100;
    ubyte    mark       = 100;
    ubyte    classid    = 100;
    string   nameserver = "127.0.0.1";
}

void toggleRoutingPolicy(Routing routing, bool enable)
{
    import std.process : escapeShellCommand, spawnShell, wait;
    import std.conv : to;
	import std.exception: enforce;

    import capability = tunneled.capability;

    auto restore = capability.State.getProcess();
    scope (exit) restore.setProcess();

    auto inherit = restore;
    inherit
        .setFlag(capability.Flag.Inheritable, ["cap_net_admin"], capability.FlagValue.Set)
        .setProcess();

    int failed;

    failed = escapeShellCommand(
        "/bin/ip", "-4", "rule", enable? "add" : "del",
        "fwmark", routing.mark.to!string, "table", routing.table.to!string, "priority", "100").spawnShell.wait;
    enforce(!failed, "Failed to toggle IPv4 routing policy rule");

    failed = escapeShellCommand(
        "/bin/ip", "-4", "rule", enable? "add" : "del",
        "fwmark", routing.mark.to!string, "table", "main", "unreachable", "priority", "100").spawnShell.wait;
    enforce(!failed, "Failed to toggle IPv4 routing policy rule");
}

void toggleNft(Routing routing, bool enable)
{
    import std.process : escapeShellCommand, spawnShell, wait;
    import std.conv : to;
	import std.exception : enforce;
    import std.format : format;

    import capability = tunneled.capability;

    auto restore = capability.State.getProcess();
    scope (exit) restore.setProcess();

    auto inherit = restore;
    inherit
        .setFlag(capability.Flag.Inheritable, ["cap_net_admin"], capability.FlagValue.Set)
        .setProcess();

    int failed;

    if (enable)
    {
        failed = escapeShellCommand("/sbin/nft", "add", "table", "ip", "tunneled_mangle", `{ chain output { type route hook output priority -150; policy accept; meta cgroup %1$s ip daddr != %3$s meta mark set %2$s; }; }`.format(routing.classid, routing.mark, routing.nameserver)).spawnShell.wait;
        enforce(!failed);

        failed = escapeShellCommand("/sbin/nft", "add", "table", "ip", "tunned_nat", `{ chain output { type nat hook output priority -100; policy accept; meta cgroup %1$s udp dport == 53 dnat %3$s; }; chain postrouting { type nat hook postrouting priority 100; policy accept; meta mark %2$s masquerade; }; }`.format(routing.classid, routing.mark, routing.nameserver)).spawnShell.wait;
        enforce(!failed);

        failed = escapeShellCommand("/sbin/nft", "add", "table", "ip6", "tunneled_filter", `{ chain output { type filter hook output priority 0; policy accept; meta cgroup %1$s reject; }; }`.format(routing.classid)).spawnShell.wait;
        enforce(!failed);
    }
    else
    {
        failed = escapeShellCommand("/sbin/nft", "delete", "table", "ip", "tunneled_mangle").spawnShell.wait;
        enforce(!failed);

        failed = escapeShellCommand("/sbin/nft", "delete", "table", "ip", "tunned_nat").spawnShell.wait;
        enforce(!failed);

        failed = escapeShellCommand("/sbin/nft", "delete", "table", "ip6", "tunneled_filter").spawnShell.wait;
        enforce(!failed);
    }
}
