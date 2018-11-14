##! Add an excerpt of HTTP POST bodies into the HTTP log.

module Corelight;

export {
	## The length of POST bodies to extract.
	option http_post_body_length = 200;
}

redef record HTTP::Info += {
	post_body: string &log &optional;
};

global log_post_bodies: event(f: fa_file, data: string);
const log_event = Files::AnalyzerArgs($stream_event=log_post_bodies);

event log_post_bodies(f: fa_file, data: string)
	{
	for ( _, c in f$conns )
		{
		local http = c$http;

		if ( http?$post_body )
			{
			if ( |http$post_body| > http_post_body_length )
				return; # already above the maximum size
			http$post_body += data;
			}
		else
			http$post_body = data;

		if ( |http$post_body| <= http_post_body_length )
			next; # keep accruing

		# Finalize.
		http$post_body =
			http$post_body[0:http_post_body_length] + "...";

		Files::remove_analyzer(f, Files::ANALYZER_DATA_EVENT, log_event);
		}
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	if ( ! is_orig || ! c?$http || ! c$http?$method )
		return;

	Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, log_event);
	}
