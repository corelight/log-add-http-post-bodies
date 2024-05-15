Add POST body excerpt to the HTTP log
-------------------------------------

This script gives analysts the ability to peek into what is being sent in HTTP
POST bodies.  It provides this by simply extending the HTTP log.

Installation
------------

::

  zkg refresh
  zkg install corelight/log-add-http-post-bodies

Usage
-----

The HTTP log will have a new field named *post_body* which will be populated 
with a configurable amount of data from the beginning of every seen POST body.
