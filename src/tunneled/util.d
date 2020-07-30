module tunneled.util;

string runtimeDir;
static this()
{
	runtimeDir = (){
		auto xdg = getenv("XDG_RUNTIME_DIR");
		if (xdg)
			return "%s/tunneled".format(xdg.fromStringz);

		return "/tmp/tunneled";
	}();
}

import core.sys.posix.stdlib : getenv;

import std.string : fromStringz;
import std.format : format;
