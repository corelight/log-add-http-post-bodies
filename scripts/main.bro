##! Add an excerpt of HTTP POST bodies into the HTTP log.

@load base/protocols/http

module Corelight;

export {
	## The length of POST bodies to extract.
	const http_post_body_length = 100 &redef;
}

redef record HTTP::Info += {
	post_body: string &log &optional;
};

event log_post_bodies(f: fa_file, data: string)
	{
	for ( cid in f$conns )
		{
		local c: connection = f$conns[cid];
		if ( ! c$http?$post_body )
			c$http$post_body = "";

		c$http$post_body = c$http$post_body + data;
		if ( |c$http$post_body| > extract_length )
			{
			c$http$post_body = c$http$post_body[0:extract_length] + "...";
			Files::remove_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=log_post_bodies]);
			}
		}
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	if ( is_orig && c?$http && c$http?$method && c$http$method == "POST" )
		{
		Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=log_post_bodies]);
		}
	}
