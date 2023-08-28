---
title: OSDP Capture Format
author: Rodney Thayer
date: August 27, 2023
---

Introduction
============

This specification describes the OSDP protocol capture format used with libosdp-conformace.  It uses the file extension (and simplified name) "OSDPCAP".
This documents format version 1.  Hyphens were removed and switched to 'camelcase' to be more parser-friendly.  This version is implemented in libosdp-conformance 0.9 forward.

Purpose
=======

To capture an OSDP byte stream for analysis.

Format
======

This is "JSONL" - JSON formed as a one line text JSON object, in a stream.

Fields
======

Field 'data'
------------

data

bytes, in hex, with interspersed spaces.  These are the bytes right off the wire.  Usually but not always a whole OSDP message.  Might include the marking bytes (ff) in front of the SOM.

Field 'io'
----------

io

form of trace source, values are "input", "output", and "trace".

Field 'osdpSource'
------------------

osdpSource

the tool that created this record.

Field 'osdpTraceVersion'
------------------------

osdpTraceVersion

what version of the format this record was written to follow.  This document describes version "1" (one.)

Fields 'timeSec' and 'timeNano'
-------------------------------

timeSec, timeNano

In Linux, the 'struct timespec' time returned by clock_gettime.

Example
=======

{ "timeSec" : "1580342115", "timeNano" : "984691851", "io" : "trace", "data" : " ff ff 53 80 08 00 01 4b 01 d8", "osdpTraceVersion":"1", "osdpSource":"libosdp-conformance 0.91-5" }

