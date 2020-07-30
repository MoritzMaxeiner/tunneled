module tunneled.cgroup;

void toggleCGroup(string name, ubyte classid, bool enable)
{
	import std.exception : enforce;
	import std.process : execvp, execvpe, spawnShell, wait, escapeShellCommand;
	import std.stdio : File;
	import std.format : format;

	import capability = tunneled.capability;

	auto restore = capability.State.getProcess();
	scope (exit) restore.setProcess();

	auto inherit = restore;
	inherit
		.setFlag(capability.Flag.Inheritable, ["cap_dac_override"], capability.FlagValue.Set)
		.setProcess();

	auto cgroup = "tunneled_" ~ name;

	if (enable) {
		auto failed = escapeShellCommand("/usr/bin/cgcreate", "-g", "net_cls:" ~ cgroup).spawnShell.wait;
		enforce(!failed, "Failed to create control group");

		File("/sys/fs/cgroup/net_cls/%s/net_cls.classid".format(cgroup), "w").writeln(classid);
	} else {
		auto failed = escapeShellCommand("/usr/bin/cgdelete", "-r", "-g", "net_cls:" ~ cgroup).spawnShell.wait;
		enforce(!failed, "Failed to delete control group");
	}
}
