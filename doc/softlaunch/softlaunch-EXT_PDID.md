extended PDID

the ID command gets an argument.
The response is a 59 not a 58.
the response payload is a multi-part message that
you have to parse.

# Status #

- libosdp-conformance can send an id request for a
extended PDID.
- osdpdump can parse it at least one level down.

# Usage #

to request an extended PDID:

``
ident pdid-blocktype=1
```


