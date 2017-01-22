module tunneled;

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

    int argc = 1;
    if (args.length >= 4 && args[3] == "--") {
        argc += args.length - 4;
    }

    char** argv = cast(char**) calloc(argc + 1, (char*).sizeof);
    argv[0] = cast(char*) args[1].toStringz;
    if (argc > 1) for (auto i = 4; i <= args.length; i++) {
        argv[i] = cast(char*) args[i].toStringz;
    }

    auto connection = new OpenVPNConnection(args[2]);
    connection.acquire();

    auto pid = fork();
    if (pid != 0) {
        siginfo_t info;
        waitid(idtype_t.P_PID, pid, &info, WEXITED);

        scope(exit) destroy(connection);
        connection.release();
    } else {
        failed = setresuid(ruid, ruid, ruid);
        enforce(!failed, "Failed to drop user privileges");

        {
            auto taskFile = File("/sys/fs/cgroup/net_cls/tunneled/%s/tasks".format(args[2]), "a");
            taskFile.writeln(getpid());
        }

        execvp(argv[0], argv);
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
    this(string name)
    {
        int failed;

        this.name = name;
        this.sharedName = "%s.%s".format("/org.ucworks.tunneled", name);

        sem = sem_open(sharedName.toStringz, O_CREAT, octal!644, 1);
        errnoEnforce(sem != SEM_FAILED, "Failed to open named semaphore");
        scope(failure) sem_close(sem);

        sem_wait(sem);
        scope(exit) sem_post(sem);

        auto sharedState = shm_open(sharedName.toStringz, O_CREAT | O_RDWR, octal!644);
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
        scope(exit) sem_close(sem);

        sem_wait(sem);
        scope(exit) sem_post(sem);

        if (state.useCount == 0) {
            shm_unlink(sharedName.toStringz);
        }

        munmap(state, State.sizeof);
    }

    void acquire()
    {
        sem_wait(sem);
        scope(exit) sem_post(sem);

        if (!state.process) {
            int failed;
            int[2] stdoutPipe;

            failed = pipe(stdoutPipe);
            errnoEnforce(!failed, "Failed to create stdout pipe");

            auto pid = fork();
            if (pid != 0) {
                close(stdoutPipe[1]);

                File stdout;
                stdout.fdopen(stdoutPipe[0], "r");
                foreach (line; stdout.byLine) {
                    stderr.writeln(line);
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

                char** argv = cast(char**) calloc(9, (char*).sizeof);

                argv[0] = cast(char*) "/usr/sbin/openvpn".toStringz;
                argv[1] = cast(char*) "--config".toStringz;
                asprintf(&argv[2], "%s/.config/tunneled/%s.conf", getenv("HOME"), name.toStringz);
                argv[3] = cast(char*) "--route-noexec".toStringz;
                argv[4] = cast(char*) "--script-security".toStringz;
                argv[5] = cast(char*) "2".toStringz;
                argv[6] = cast(char*) "--route-up".toStringz;
                argv[7] = cast(char*) "/etc/openvpn/tunneled-route-up.sh".toStringz;

                setsid(); // Detach child process

                uid_t ruid, euid, suid;

                failed = getresuid(&ruid, &euid, &suid);
                assert(!failed);

                failed = setresuid(euid, euid, suid);
                errnoEnforce(!failed, "Failed to elevate privileges");

                execvp(argv[0], argv);
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
            int failed;
            uid_t ruid, euid, suid;

            failed = getresuid(&ruid, &euid, &suid);
            assert(!failed);

            failed = setresuid(euid, euid, suid);
            errnoEnforce(!failed, "Failed to elevate privileges");

            scope (exit) {
                failed = setresuid(ruid, euid, suid);
                errnoEnforce(!failed, "Failed to drop privileges");
            }

            kill(state.process, SIGTERM);
        }
    }
private:
    string name, sharedName;
    sem_t* sem;
    State* state;

    struct State
    {
        pid_t process;
        ubyte useCount;
    }
}

import core.sys.posix.sys.types : uid_t, gid_t, pid_t;
import core.sys.posix.fcntl : O_CREAT, O_RDWR;
import core.sys.posix.semaphore :
    sem_t, SEM_FAILED,
    sem_open, sem_close,
    sem_wait, sem_post;
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
    execvp,
    getpid;
import core.sys.posix.stdlib : calloc, getenv;
import core.sys.posix.pwd : getpwnam;

import std.conv : octal;
import std.string : toStringz;
import std.format : format;
import std.exception : enforce, errnoEnforce;
import std.stdio : File, stderr;
import std.algorithm : canFind;


__gshared extern (C):

int setresuid(uid_t ruid, uid_t euid, uid_t suid);
int setresgid(gid_t rgid, gid_t egid, gid_t sgid);

int getresuid(uid_t* ruid, uid_t* euid, uid_t* suid);
int getresgid(gid_t* rgid, gid_t* egid, gid_t* sgid);

int asprintf(char** strp, const char* fmt, ...);
