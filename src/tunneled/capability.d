module tunneled.capability;

struct State
{
public:
    this(cap_t handle)
    {
        this.handle = handle;
    }

    this(this)
    {
        handle = cap_dup(handle);
    }

    ~this()
    {
        cap_free(handle);
    }

    static State getProcess()
    {
        auto h = cap_get_proc();
        errnoEnforce(h);
        return State(h);
    }

    ref State setFlag(Flag flag, string[] capabilities, FlagValue flagValue)
    {
        scope array = new cap_value_t[capabilities.length];

        foreach (i, c; capabilities)
        {
            if (!(c in internal))
            {
                cap_value_t v;
                errnoEnforce(cap_from_name(c.toStringz, &v) == 0);
                internal[c] = v;         
            }

            array[i] = internal[c];
        }

        errnoEnforce(cap_set_flag(handle, flag, cast(int) array.length, &array[0], flagValue) == 0);

        return this;
    }

    void setProcess()
    {
        errnoEnforce(cap_set_proc(handle) == 0);
    }

    string toString()
    {
        ssize_t len;
        auto str = cap_to_text(handle, &len);
        scope (exit) cap_free(str);

        return str[0..len].idup;
    }

private:
    cap_t               handle;
    cap_value_t[string] internal;
}

enum Flag
{
    Effective   = 0,
    Permitted   = 1,
    Inheritable = 2
}

enum FlagValue
{
    Clear = 0,
    Set   = 1
}

private:

import core.sys.posix.sys.types : ssize_t;

import std.exception : errnoEnforce;
import std.string : toStringz;

__gshared extern (C):

struct _cap_struct; alias cap_t = _cap_struct*;

cap_t cap_dup(cap_t cap_p);
int cap_free(void* obj_d);

cap_t cap_get_proc();
int   cap_set_proc(cap_t cap_p);

int cap_from_name(const(char)* name, cap_value_t* cap_p);

char* cap_to_text(cap_t caps, ssize_t* length_p);

int cap_set_flag(cap_t cap_p, Flag flag, int ncap, const(cap_value_t)* caps, FlagValue value);

alias cap_value_t = int;
