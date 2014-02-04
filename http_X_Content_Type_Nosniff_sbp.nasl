#
# (C) Glenn ten Cate, Mission Critical Security Engineer @ Schuberg Philis
#

include("compat.inc");

if(description)
{
 script_id(1337002);
 script_version ("$Revision: 0.1 $");
 script_cvs_date("$Date: 2014/01/29 13:37:00 $");

 script_name(english: "HTTP X-Content-Options: nosniff Response Header Usage");

 script_set_attribute(attribute:"synopsis", value:
"The remote web-application takes no steps to mitigate a class of web
application vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote web-application sets no X-Content-Options response header.

X-Content-Options has been proposed by Microsoft as a way to mitigate
MIME-type attacks and has also been implemented in Chrome and Safari." );
  script_set_attribute(attribute:"solution", value:
"The following header needs to be set on all the pages of the web-application:

X-Content-Type-Options: nosniff
");
 script_set_attribute(attribute:"risk_factor", value: "Medium" );

 script_set_attribute(attribute:"see_also", value:"http://blogs.msdn.com/b/ie/archive/2008/07/02/ie8-security-part-v-comprehensive-protection.aspx");
 script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/29");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_summary(english: "Reports web-application that don't use X-Content-Options: nosniff header");
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

if(eregmatch(pattern:'X-Content-Type-Options: nosniff', string:r))
 exit(0,"Correct X-Content-Type-Options found!\n\n");
 else
 resNessus = "X-Content-Type-Options NOT found
 
"+r;

 security_hole(port: port, extra: resNessus);
 exit(0,"Incorrect X-Content-Type-Options NOT found\r\n");

