To use this script with Wireshark just copy the file coap18.lua into the "plugins" folder of Wireshark (e.g. ~/.wireshark/plugins for Ubuntu). After the next start of Wireshark it is ready to use.

Supported protocol and extension versions:

- CoAP Protocol (Draft 18)
- CoAP Observe (Draft 11)
- CoAP Blockwise Transfer (Draft 14)

Type "coap18" in the filter field of Wireshark to filter all CoAP messages using this script. However, you can use "coap18.*" as prefix for a huge number of other (more advanced) filters, e.g.

- coap18.msgid == 123 for all messages with message ID 123, or
- coap18.options.uripath == "test" for all messages that contain an URI-Path option with value "test".
 
Note: This script needs LUA 5.2 (which for sure is available in Wireshark 1.10.5)
