module tunneled.client;

import tunneled.util;

import core.sys.posix.sys.types : pid_t;
import core.sys.posix.fcntl : O_CREAT, O_RDWR;
import core.sys.posix.semaphore :
    sem_t, SEM_FAILED,
    sem_open, sem_close,
    sem_wait, sem_post, sem_getvalue, sem_unlink;
import core.sys.posix.sys.mman :
    shm_open, shm_unlink,
    mmap, munmap,
    PROT_READ, PROT_WRITE,
    MAP_SHARED, MAP_FAILED;
import core.sys.posix.signal : kill, SIGTERM, siginfo_t;
import core.sys.posix.sys.stat : stat_t, fstat;
import core.sys.posix.sys.wait : waitid, idtype_t, WEXITED;
import core.sys.posix.unistd :
    close,
    ftruncate,
    pipe,
    fork,
    dup2,
    STDIN_FILENO,
    STDOUT_FILENO,
    setsid,
    getpid;
import core.sys.posix.stdlib : free;
import std.process : thisProcessID;
import std.exception : errnoEnforce;
import std.conv : to;

import capability = tunneled.capability;
import net = tunneled.net;

class Client
{
public:

    this(net.Routing routing, string[] args)
    {
        this.routing = routing;
        this.args = args;

        errnoEnforce(pipe(stdinPipe) == 0);
        errnoEnforce(pipe(stdoutPipe) == 0);

        pid = fork();
        if (pid == 0)
        {
            {
                scope (exit)
                {
                    close(stdinPipe[0]);
                    close(stdinPipe[1]);
                }
                auto fd = dup2(stdinPipe[0], STDIN_FILENO);
                errnoEnforce(fd >= 0);
            }

            {
                scope (exit)
                {
                    close(stdoutPipe[0]);
                    close(stdoutPipe[1]);
                }
                auto fd = dup2(stdoutPipe[1], STDOUT_FILENO);
                errnoEnforce(fd >= 0);
            }

            setsid();

            capability.State
                    .getProcess()
                    .setFlag(capability.Flag.Inheritable, ["cap_net_admin"], capability.FlagValue.Set)
                    .setProcess();
            
            exec();
            assert(false);
        }

        close(stdinPipe[0]);
        close(stdoutPipe[1]);

        stdin.fdopen(stdinPipe[1], "a");
        stdout.fdopen(stdoutPipe[0], "r");
    }

    abstract void wait();

protected:

    abstract void exec();

    net.Routing routing;
    string[]    args;

    int[2] stdinPipe;
    int[2] stdoutPipe;

public:

    immutable pid_t pid;

    File   stdin;
    File   stdout;
}

class OpenVPN : Client
{
    string routeUp;

    this(net.Routing routing, string[] args)
    {
        if (!exists(runtimeDir)) {
            mkdir(runtimeDir);
        }

        routeUp = "%s/openvpn-route-up.sh".format(runtimeDir);

        {
            auto f = File(routeUp, "w");
            f.write(`#! /bin/sh
    /bin/ip route flush table $1
    /bin/ip route add default via "${route_vpn_gateway}" dev "${dev}" table $1
    /usr/sbin/sysctl net.ipv4.conf."${dev}".rp_filter=2
    `);
            fchmod(f.fileno, octal!700);
        }

        super(routing, args);
    }

    override void wait()
    {
        foreach (line; stdout.byLine)
        {
            if (line.canFind("Initialization Sequence Completed"))
                return;
        }
    }

protected:

    override void exec()
    {
        args = [ "/usr/sbin/openvpn" ]
             ~ args
             ~ [ "--route-noexec",
                 "--script-security", "2",
                 "--route-up", routeUp ~ " " ~ routing.table.to!string ];
        execvp(args[0], args);
        errnoEnforce(false);
    }
}

class OpenConnect : Client
{
    string script;

    this(net.Routing routing, string[] args, string password)
    {
        if (!exists(runtimeDir)) {
            mkdir(runtimeDir);
        }

        script = "%s/openconnect-script.sh".format(runtimeDir);

        {
            auto f = File(script, "w");
            f.write(`#! /bin/sh
case "${reason}" in
pre-init)
    ;;
connect)
    /bin/ip route flush table $1
    /bin/ip link set dev "${TUNDEV}" up
    /bin/ip addr add "${INTERNAL_IP4_ADDRESS}/32" peer "${INTERNAL_IP4_ADDRESS}" dev "${TUNDEV}"
    /bin/ip route add default dev "${TUNDEV}" table $1
    /bin/ip route add "${INTERNAL_IP4_NETADDR}/${INTERNAL_IP4_NETMASKLEN}" dev "${TUNDEV}" table $1
    /usr/sbin/sysctl net.ipv4.conf."${TUNDEV}".rp_filter=2
    ;;
disconnect)
    /bin/ip route flush table $1
    ;;
attempt-reconnect)
    ;;
reconnect)
    ;;
*)
    echo "unknown reason '$reason'. Maybe openconnect-script is out of date" 1>&2
    exit 1
    ;;
esac
    `);
            fchmod(f.fileno, octal!700);
        }

        super(routing, args);

        stdin.write(password);
        stdin.close();
    }

    override void wait()
    {
        foreach (line; stdout.byLine)
        {
            if (line.canFind("Established"))
                return;
        }
    }

protected:

    override void exec()
    {
        args = [ "/usr/sbin/openconnect" ]
             ~ [ "--passwd-on-stdin",
                 "--script", script ~ " " ~ routing.table.to!string]
             ~ args;
        import std.stdio;
        stderr.writeln(args);
        execvp(args[0], args);
        errnoEnforce(false);
    }
}

import std.process : execvp;
import core.sys.posix.sys.stat : fchmod;

import std.conv : octal;
import std.stdio : File, writeln;
import std.format : format;
import std.file : mkdir, exists;
import std.algorithm : canFind;
