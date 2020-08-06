module tunneled.nftables;

import std.string : toStringz;
import std.exception : enforce;

struct Context
{
public:
	this(uint flags)
	{
		handle = nft_ctx_new(flags);
		enforce(handle);
	}

	~this()
	{
		nft_ctx_free(handle);
	}

	@disable
	this(this);

	void runCommandFromBuffer(string buf)
	{
		enforce(0 == nft_run_cmd_from_buffer(handle, &buf[0], buf.length));
	}

private:
	nft_ctx* handle;
}


__gshared extern (C) private:

struct nft_ctx;

nft_ctx* nft_ctx_new(uint flags);
void nft_ctx_free(nft_ctx* ctx);

int nft_run_cmd_from_buffer(nft_ctx* nft, const(char)* buf, size_t buf_len);
