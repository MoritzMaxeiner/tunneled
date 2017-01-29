module tunneled;

struct Settings
{
    string name;
    Routing routing;
    OpenVPN openvpn;

    struct OpenVPN
    {
        string[] args;
    }

    struct Routing
    {
        ubyte table   = 100;
        ubyte mark    = 100;
        ubyte classid = 100;
        IPv4Dest nameserver = { "127.0.0.1", 53 };
    }

    struct IPv4Dest
    {
        string address;
        ushort port;
    }
}

void main(string[] args)
{
    int failed;

    if (getenv("SUDO_USER")) {
        dropSudoToSuid();
    }

    uid_t ruid, euid, suid;
    failed = getresuid(&ruid, &euid, &suid);
    assert(!failed);

    enforce(euid == 0 && suid == 0, "tunneled requires effective and saved user root privileges");

    enforce(args.length >= 3);

    auto settings = args[1].File.byChunk(4096).parseJson.deserialize!Settings;

    auto connection = new OpenVPNConnection(settings);
    connection.acquire();

    auto pid = fork();
    if (pid != 0) {
        // std.process.wait
        siginfo_t info;
        waitid(idtype_t.P_PID, pid, &info, WEXITED);

        scope(exit) destroy(connection);
        connection.release();
    } else {
        {
            auto taskFile = File("/sys/fs/cgroup/net_cls/tunneled_%s/tasks".format(settings.name), "a");
            taskFile.writeln(getpid());
            // std.process.thisProcessID
        }

        failed = setresuid(ruid, ruid, ruid);
        enforce(!failed, "Failed to drop user privileges");

        execvp(args[2], args[2..$]);
    }
}

void dropSudoToSuid()
{
    int failed;
    auto pwdEntry = getpwnam(getenv("SUDO_USER"));

    failed = setresgid(pwdEntry.pw_gid, pwdEntry.pw_gid, pwdEntry.pw_gid);
    errnoEnforce(!failed, "Failed to drop group privileges");

    uid_t ruid, euid, suid;
    failed = getresuid(&ruid, &euid, &suid);
    assert(!failed);

    failed = setresuid(pwdEntry.pw_uid, euid, euid);
    errnoEnforce(!failed, "Failed to drop user privileges");
}

class OpenVPNConnection
{
public:
    this(Settings settings)
    {
        int failed;

        this.settings = settings;
        asprintf(&sharedName, "%s.%s", "/org.ucworks.tunneled".toStringz, settings.name.toStringz);

        sem = sem_open(sharedName, O_CREAT, octal!644, 1);
        errnoEnforce(sem != SEM_FAILED, "Failed to open named semaphore");
        scope(failure) sem_close(sem);

        sem_wait(sem);
        scope(exit) sem_post(sem);

        auto sharedState = shm_open(sharedName, O_CREAT | O_RDWR, octal!644);
        errnoEnforce(sharedState != -1, "Failed to open shared memory");
        scope(exit) close(sharedState);

        stat_t sharedStateStat;
        failed = fstat(sharedState, &sharedStateStat);
        errnoEnforce(!failed, "Failed to get status of shared memory");

        if (sharedStateStat.st_size != State.sizeof) {
            // Initializes with zero bytes
            failed = ftruncate(sharedState, State.sizeof);
            errnoEnforce(!failed, "Failed to grow shared memory");
        }

        state = cast(State*) mmap(null, State.sizeof, PROT_READ | PROT_WRITE, MAP_SHARED, sharedState, 0);
        errnoEnforce(state != MAP_FAILED, "Failed to map shared memory");
    }

    ~this()
    {
        scope(exit) free(sharedName);

        scope(exit) sem_close(sem);

        sem_wait(sem);
        scope(exit) sem_post(sem);

        if (state.useCount == 0) {
            shm_unlink(sharedName);
        }

        munmap(state, State.sizeof);
    }

    void acquire()
    {
        sem_wait(sem);
        scope(exit) sem_post(sem);

        if (!state.process) {
            createRouteUp();

            int failed;
            int[2] stdoutPipe;

            failed = pipe(stdoutPipe);
            errnoEnforce(!failed, "Failed to create stdout pipe");

            auto pid = fork();
            if (pid != 0) {
                settings.toggleCGroup(true);
                scope(failure) settings.toggleCGroup(false);

                settings.toggleRoutingPolicy(true);
                scope(failure) settings.toggleRoutingPolicy(false);

                settings.togglePacketFiltering(true);
                scope(failure) settings.togglePacketFiltering(false);

                close(stdoutPipe[1]);

                File stdout;
                stdout.fdopen(stdoutPipe[0], "r");
                foreach (line; stdout.byLine) {
                    //stderr.writeln(line);
                    if (line.canFind("Initialization Sequence Completed")) {
                        state.process = pid;
                        state.useCount += 1;
                        return;
                    }
                }
                enforce(false, "Failed to spawn OpenVPN");
            } else {
                {
                    scope(exit) {
                        close(stdoutPipe[0]);
                        close(stdoutPipe[1]);
                    }
                    auto fd = dup2(stdoutPipe[1], STDOUT_FILENO);
                    errnoEnforce(fd != -1, "Failed to redirect child stdout to pipe");
                }

                auto args = [ "/usr/sbin/openvpn" ]
                    ~ settings.openvpn.args
                    ~ [ "--route-noexec",
                        "--script-security", "2",
                        "--route-up", "/tmp/tunneled/route-up.sh " ~ settings.routing.table.to!string ];

                setsid(); // Detach child process

                changePrivileges!("euid", "euid", "suid");

                execvp(args[0], args);
                errnoEnforce(false, "Failed to spawn OpenVPN");
            }
        } else {
            state.useCount += 1;
        }
    }

    void release()
    {
        sem_wait(sem);
        scope(exit) sem_post(sem);

        assert(state.useCount > 0);
        state.useCount -= 1;

        if (state.useCount == 0) {
            settings.toggleCGroup(false);
            settings.toggleRoutingPolicy(false);
            settings.togglePacketFiltering(false);

            changePrivileges!("euid", "euid", "ruid");
            scope (exit) changePrivileges!("suid", "euid", "euid");

            kill(state.process, SIGTERM);
        }
    }
private:
    Settings settings;
    char* sharedName;
    sem_t* sem;
    State* state;

    struct State
    {
        pid_t process;
        ubyte useCount;
    }
}

void changePrivileges(string ruid, string euid, string suid)()
{
    uid_t _ruid, _euid, _suid;

    auto failed = getresuid(&_ruid, &_euid, &_suid);
    assert(!failed);

    failed = setresuid(mixin("_" ~ ruid), mixin("_" ~ euid), mixin("_" ~ suid));
    errnoEnforce(!failed, "Failed to change privileges");

    /*stderr.writefln("Privileges changed: (%d,%d,%d) -> (%d,%d,%d)",
                    _ruid, _euid, _suid,
                    mixin("_" ~ ruid), mixin("_" ~ euid), mixin("_" ~ suid));
    stderr.flush;*/
}

void createRouteUp()
{
    static immutable routeUp = `#! /bin/sh

    ip route flush table $1
    ip route add default via "${route_vpn_gateway}" dev "${dev}" table $1
    sysctl net.ipv4.conf."${dev}".rp_filter=2`;

    if (!exists("/tmp/tunneled")) {
        mkdir("/tmp/tunneled");
    }

    auto f = File("/tmp/tunneled/route-up.sh", "w");
    f.write(routeUp);
    fchmod(f.fileno, octal!500);
}


void toggleCGroup(Settings settings, bool enable)
{
    int failed;

    changePrivileges!("euid", "euid", "ruid");
    scope (exit) changePrivileges!("suid", "euid", "euid");

    auto cgroup = "tunneled_" ~ settings.name;

    if (enable) {
        failed = escapeShellCommand("cgcreate", "-g", "net_cls:" ~ cgroup).spawnShell.wait;
        enforce(!failed, "Failed to create control group");

        File("/sys/fs/cgroup/net_cls/%s/net_cls.classid".format(cgroup), "w").writeln(settings.routing.classid);
    } else {
        failed = escapeShellCommand("cgdelete", "-r", "-g", "net_cls:" ~ cgroup).spawnShell.wait;
        enforce(!failed, "Failed to delete control group");
    }
}

void toggleRoutingPolicy(Settings settings, bool enable)
{
    int failed;

    changePrivileges!("euid", "euid", "ruid");
    scope (exit) changePrivileges!("suid", "euid", "euid");

    failed = escapeShellCommand(
        "/sbin/ip", "-4", "rule", enable? "add" : "del",
        "fwmark", settings.routing.mark.to!string, "table", settings.routing.table.to!string, "priority", "100").spawnShell.wait;
    enforce(!failed, "Failed to toggle IPv4 routing policy rule");

    failed = escapeShellCommand(
        "/sbin/ip", "-4", "rule", enable? "add" : "del",
        "fwmark", settings.routing.mark.to!string, "table", "main", "unreachable", "priority", "100").spawnShell.wait;
    enforce(!failed, "Failed to toggle IPv4 routing policy rule");
}

void togglePacketFiltering(Settings settings, bool enable)
{
    int failed;

    changePrivileges!("euid", "euid", "ruid");
    scope (exit) changePrivileges!("suid", "euid", "euid");

    failed = escapeShellCommand(
        "/sbin/iptables", "-t", "mangle", enable? "-A": "-D", "OUTPUT",
        "-m", "cgroup", "--cgroup", settings.routing.classid.to!string,
        "-j", "MARK", "--set-mark", settings.routing.mark.to!string
    ).spawnShell.wait;
    enforce(!failed, "Failed to toggle IPv4 packet filter rule");

    failed = escapeShellCommand(
        "/sbin/iptables", "-t", "mangle", enable? "-A": "-D", "OUTPUT",
        "-m", "mark", "--mark", settings.routing.mark.to!string,
        "-p", "udp", "--dport", "53",
        "-j", "MARK", "--set-mark", "0/" ~ settings.routing.mark.to!string
    ).spawnShell.wait;
    enforce(!failed, "Failed to toggle IPv4 packet filter rule");

    failed = escapeShellCommand(
        "/sbin/iptables", "-t", "nat", enable? "-A": "-D", "POSTROUTING",
        "-m", "mark", "--mark", settings.routing.mark.to!string,
        "-j", "MASQUERADE"
    ).spawnShell.wait;
    enforce(!failed, "Failed to toggle IPv4 packet filter rule");

    failed = escapeShellCommand(
        "/sbin/iptables", "-t", "nat", enable? "-A": "-D", "OUTPUT",
        "-m", "cgroup", "--cgroup", settings.routing.classid.to!string,
        "-p", "udp", "--dport", "53",
        "-j", "DNAT", "--to", settings.routing.nameserver.address ~ ":" ~ settings.routing.nameserver.port.to!string
    ).spawnShell.wait;
    enforce(!failed, "Failed to toggle IPv4 packet filter rule");

    failed = escapeShellCommand(
        "/sbin/ip6tables", "-t", "filter", enable? "-A": "-D", "OUTPUT",
        "-m", "cgroup", "--cgroup", settings.routing.classid.to!string,
        "-j", "REJECT"
    ).spawnShell.wait;
    enforce(!failed, "Failed to toggle IPv6 packet filter rule");
}

import core.sys.posix.sys.types : uid_t, gid_t, pid_t;
import core.sys.posix.fcntl : O_CREAT, O_RDWR;
import core.sys.posix.semaphore :
    sem_t, SEM_FAILED,
    sem_open, sem_close,
    sem_wait, sem_post, sem_getvalue;
import core.sys.posix.sys.mman :
    shm_open, shm_unlink,
    mmap, munmap,
    PROT_READ, PROT_WRITE,
    MAP_SHARED, MAP_FAILED;
import core.sys.posix.signal : kill, SIGTERM, siginfo_t;
import core.sys.posix.sys.stat : stat_t, fstat, fchmod;
import core.sys.posix.sys.wait : waitid, idtype_t, WEXITED;
import core.sys.posix.unistd :
    close,
    ftruncate,
    pipe,
    fork,
    dup2,
    STDOUT_FILENO,
    setsid,
    execvp,
    getpid;
import core.sys.posix.stdlib : calloc, free, getenv;
import core.sys.posix.pwd : getpwnam, getpwuid;

import std.conv : octal, to;
import std.string : toStringz, fromStringz;
import std.format : format;
import std.exception : enforce, errnoEnforce;
import std.stdio : File, stderr;
import std.file : mkdir, exists;
import std.algorithm : canFind;
import std.process : execvp, execvpe, spawnShell, wait, escapeShellCommand;

import asdf;


__gshared extern (C):

int setresuid(uid_t ruid, uid_t euid, uid_t suid);
int setresgid(gid_t rgid, gid_t egid, gid_t sgid);

int getresuid(uid_t* ruid, uid_t* euid, uid_t* suid);
int getresgid(gid_t* rgid, gid_t* egid, gid_t* sgid);

int asprintf(char** strp, const char* fmt, ...);
