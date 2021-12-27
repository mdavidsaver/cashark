Wireshark dissector plugin for EPICS protocols
==============================================

Tested with wireshark 1.2.11, 1.8.2, 1.10.8, 2.2.6, 2.6.0, and 3.4.10.
Works on RHEL 7.4 (wireshark 1.10.14).

Using
-----

Only the file ca.lua is needed.  Then start wireshark with

    wireshark -X lua_script:/path/to/ca.lua

Status
------

This plugin does general decoding of CA UDP and TCP traffic on the standard
ports (5064 and 5065).  It does TCP segment reassembly for large messages.

The CA protocol provides no easy way to distinguish client and server
messages without observing the start of the connection.  Thus this plugin
can not fully decode all messages.  Currently only some messages are fully decoded.
Others decode with only generic field names.

Reporting bugs
--------------

Bug reports are welcome (and patches more so).

Send to "Michael Davidsaver" <mdavidsaver@gmail.com>
or open a [github] issue.
Please mention both the wireshark and lua versions.

If possible, please include a packet capture file which will trigger the error.

Note that the PVA dissector triggers [bug 10233][bug10233] with wireshark 1.12.1,
which is known to be fixed with 2.0.

[github]: https://github.com/mdavidsaver/cashark/issues
[bug10233]: https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=10233

Setup
-----

To automatically load the CA dissector *instead* of using the -X argument.

On RHEL systems, the wireshark config directory is at /usr/share/wireshark/.
If the file /usr/share/wireshark/init.lua doesn't exist,
install the package wireshark-devel.

Edit /etc/wireshark/init.lua and remove or comment out the line about
disabling LUA support ("`disable_lua = true`").  You may also need
to change the line "`run_user_scripts_when_superuser = false`"
depending on how you run wireshark.

Next copy the file ca.lua from this repository to /etc/wireshark/.

Then add a line to the end of init.lua.

    dofile("ca.lua")

If all goes well the string "Loaded CA" will be printed to the console
when wireshark starts.

To install this for a single user create `$HOME/.wireshark/init.lua` with
a single line "`dofile("ca.lua")`" and place ca.lua in this directory.

tshark
------

Dissectors may also be used with the CLI interface `tshark`.
For example, the following prints all CA decode information
in `test/cabeacon.cap`.

```sh
tshark -r test/cabeacon.cap \
 -X lua_script:ca.lua \
 -PO ca \
 'ca'
```

And with PVA:

```sh
tshark -r test/pva-beacon.pcapng.gz \
 -X lua_script:ca.lua \
 -PO pva \
 'pva'
```

Note that both decoders can be loaded simultaneously:

```sh
tshark \
 ...
 -X lua_script:ca.lua \
 -X lua_script:pva.lua \
 -PO ca,pva \
 'ca || pva'
```
