Custom Nessus Plugins
=====================

Nessus custom plugins for SBP

In this Repo you can find specific Nessus *.nasl plugin files.
These Nasl plugins are custom build for and by SBP for extra security checks.

How to test your Nasl plugin:

`# /opt/nessus/bin/nasl -T - -t localhost http_X_Content_Security_Policy_header.nasl`


How to use custom Nasl plugins:

First you need to stop the nessus deamon:

`# /etc/init.d/nessusd stop`

Copy the Nasl plugin file you want to use to the Nessus plugin dir:

`# cp custom-plugin.nasl /opt/nessus/lib/nessus/plugins/`

Then run the plugin rebuild script:

`# /opt/nessus/sbin/nessusd -R`

Now the custom plugin is reconized by Nessus and we can start Nessus deamon again:

`# /etc/init.d/nessusd start`

Now login into the Nessus web-application and edit the web-scan policy.
Find the plugin in the pull down and activate it.

Now you scan policy will also run the custom Nasl Plugin
