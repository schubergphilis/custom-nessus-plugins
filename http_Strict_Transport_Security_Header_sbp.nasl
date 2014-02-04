#
# (C) Glenn ten Cate, Mission Critical Security Engineer @ Schuberg Philis
#

include("compat.inc");

if(description)
{
 script_id(1337001);
 script_version ("$Revision: 0.1 $");
 script_cvs_date("$Date: 2014/01/29 13:37:00 $");

 script_name(english: "HTTP Strict-Transport-Security: Response Header Usage");

 script_set_attribute(attribute:"synopsis", value:
"The remote web-application takes no steps to mitigate a class of web
application vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote web-application sets no Strict-Transport-Security response header.

HTTP Strict-Transport-Security (HSTS) enforces secure (HTTP over SSL/TLS) connections to the server. 
This reduces impact of bugs in web applications leaking session data through cookies and external 
links and defends against Man-in-the-middle attacks. HSTS also disables the ability for user's to ignore
SSL negotiation warnings." );
  script_set_attribute(attribute:"solution", value:
"The following header needs to be set on all the pages of the web-application:

Strict-Transport-Security: max-age=16070400;");
 script_set_attribute(attribute:"risk_factor", value: "Medium" );

 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Strict-Transport-Security");
 script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc6797");
 script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/29");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_summary(english: "Reports web-application that don't use Strict-Transport-Security: header");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) SBP");
 script_family(english: "CGI abuses");
 script_dependencie("webmirror.nasl");
 script_require_ports("Services/www");
 exit(0);
}


include("http_func.inc");

port = get_http_port(default:80);
host = get_host_name();

soc = http_open_socket(port);
if (! soc) exit(0);

req = string("HEAD / HTTP/1.0\r\n\r\n");
send(socket:soc, data: req);
r = http_recv(socket: soc);
http_close_socket(soc);

if(eregmatch(pattern:'Strict-Transport-Security: (.*)', string:r))
 exit(0,"Correct Strict-Transport-Security found!\n\n");
 else
 resNessus = "Strict-Transport-Security NOT found

"+r;

 security_hole(port: port, extra: resNessus);
 exit(0,"Incorrect Strict-Transport-Security\r\n");

