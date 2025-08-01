So anyway, my point was...
=========================

It has taken me almost 2 years to complete this component. At least a few
people were probably convinced that I would never finish go-i2p's
implementation of NTCP2. However, what I really, really wanted to do was build
the protocol library within the correct constraints to produce a library which
leverages the key super power of my favorite programming language, Go. In Go,
design is typically done interface-first. However, there was no Noise library
that cleanly mapped the Noise protocol onto the intuitive interface to apply it
to, a connection-oriented socket between 2 communicating parties. Instead the
libraries present a very low-level view of the Noise protocol, giving you access
to the handshake and the state machine but forcing you to build your system
around it.

Moreover, modifications to the Noise handshake were never considered by any Go
library. No documentation of how to do the preprocessing steps involved in the
NTCP2 protocol existed, or were forthcoming. This isn't wierd, not modifying
standard crypto is generally good advice, in fact NTCP2's modifications to the
Noise protocol do not actually change the Noise cryptography, they are merely
preprocessing steps required to derive the real keys from obfuscated
transmissions. This is at best intimidating to people, and at worst leads to
duplicating a lot of work. In a nutshell:

*There actually isn't a good reason to need to have a different AES obuscation*
*subsystem from NTCP2 to SSU2 in Go. There isn't a good reason to have a*
*different padding subsystem from NTCP2 to SSU2 in Go either. These subsystems,*
*if carefully designed, can absolutely be shared.*

So the real bulk of the work I saw that needed to be done was to:

 1. Create an interface type and concrete struct that applies a Noise protocol
  handshake and cryptography to a net.Conn and net.Listener which implements
  a net.Conn and a net.Listener interface.
 2. Create a middleware which implements a custom interface capable of modifying
  arbitrary handshake steps in the Noise handshake by applying preprocessing.

The first one is kind of hard because the documentation for Go noise libraries
has not always been awesome(Another problem we like to think this repo is
solving). That second one is **really** hard, though. Noise handshakes are
surprisingly different from eachother, in spite of sharing a name. Mostly the
tough part is designing a handshake modifier pattern that can be applied to a
specific step of an already configured handshake, regardless of the number of 
steps in that specific Noise handshake, whether you are the initiator or the
responder, which ultimately interfaces with the underlying library that
actually exposes the Noise state machine

BUT if you do this successfully...
---------------------------------

If you manage to do this successfully and build a Noise handshake modification
framework(As I have largely accomplished here), then you can re-use it. For
instance in the case of NTCP2 and SSU2, we will be able to re-use the entire
Noise socket subsystem as the basis. We don't have to write any more code to do
Noise-XK over UDP if we can make an interface compatible with a
connection-oriented pattern, that is already done. We also don't need to write
a new siphash length obfuscator at all. We only need to write a minor extension
to the NTCP2 AES obfuscator to support SSU2 by revising it to use ChaCha20
instead. We can re-use most of the code that already exists in this repository
to make life much easier.

Moreover, we also have a clear path to finish the additional features of parts
of SSU2. SSU2 implements peer testing, NAT traversal, and connection migration.
Each of these in go-i2p will be a layered set of concrete implementations of
yet another net.Addr, net.Conn, and net.Listener for each aspect of the
protocol. These simply get nested inside the Noise connection/listener.