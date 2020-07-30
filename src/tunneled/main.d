module tunneled.main;

class Session
{
public:
    struct Settings
    {
        import tunneled.net : Routing;

        string  name;
        Client  client;
        Routing routing;

        struct Client
        {
            enum Type
            {
                OpenVPN
            }

            Type     type;
            string[] args;
        }
    }

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

    void join()
    {
        import capability = tunneled.capability;
        import vpn = tunneled.vpn;

        sem_wait(sem);
        scope(exit) sem_post(sem);

        if (!state.process) {

            toggleCGroup(settings.name, settings.routing.classid, true);
            scope(failure) toggleCGroup(settings.name, settings.routing.classid, false);

            toggleRoutingPolicy(settings.routing, true);
            scope(failure) toggleRoutingPolicy(settings.routing, false);

            toggleNft(settings.routing, true);
            scope(failure) toggleNft(settings.routing, false);

            auto client = (){
                final switch (settings.client.type)
                {
                case Settings.Client.Type.OpenVPN:
                    return cast(vpn.Client) new vpn.OpenVPN(settings.routing, settings.client.args);
                }
            }();

            client.wait();
            state.process = client.pid;
        }
        state.useCount += 1;
    }

    void leave()
    {
        sem_wait(sem);
        scope(exit) sem_post(sem);

        assert(state.useCount > 0);
        state.useCount -= 1;

        if (state.useCount == 0) {
            toggleCGroup(settings.name, settings.routing.classid, false);
            toggleRoutingPolicy(settings.routing, false);
            toggleNft(settings.routing, false);

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

void main(string[] args)
{
    int failed;

    enforce(args.length >= 3, "usage: tunneled session.json program [args...]");

    auto settings = args[1].File.byChunk(4096).parseJson.deserialize!(Session.Settings);

    auto session = new Session(settings);
    session.join();

    auto pid = fork();
    if (pid != 0) {
        // std.process.wait
        siginfo_t info;
        waitid(idtype_t.P_PID, pid, &info, WEXITED);

        scope(exit) destroy(session);
        session.leave();
    } else {
        {
            auto taskFile = File("/sys/fs/cgroup/net_cls/tunneled_%s/tasks".format(settings.name), "a");
            taskFile.writeln(getpid());
            // std.process.thisProcessID
        }

        execvp(args[2], args[2..$]);
    }
}

import tunneled.cgroup : toggleCGroup;
import tunneled.net : toggleRoutingPolicy, toggleNft;

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
    STDOUT_FILENO,
    setsid,
    getpid;
import core.sys.posix.stdlib : free;

import std.conv : octal, to;
import std.string : toStringz;
import std.format : format;
import std.exception : enforce, errnoEnforce;
import std.stdio : File;
import std.process : execvp;

import asdf;

__gshared extern (C):

int asprintf(char** strp, const char* fmt, ...);
