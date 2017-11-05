# Sack Protocol (Secure access Key Protocol)

Some name needs every protocol.

The goal of this protocol is to be open and don’t have a need of a transport encryption. The Sack Protocol should ensure that there is no replay attack possible and the key life times on both ends are in your control.

This protocol will be handled by a client-installed-service like parity from the etherium blockchain. This service will be install on the customer side and has an external side which implements these protocol.

On the internal side it has a way simpler interface which is currently not part of the specification.

The protocol implementation should be able to run as a standalone service or run within the “users application”.

This service should implemented on the web platform which has supports asm.js or webassembly or any actual browser like chrome/firefox/edge. The first implementation should run within electron or headless chromes like phantomjs.

The protocol implementation should be build on an abstraction to run the software with nashorn within actual jvms and utilise the jvm given crypto functions. The communication Protocol should not use http req-res pattern, instead there will used:

 “https://tools.ietf.org/html/rfc6455”

so enable a fully bidirectional communication. If this communication is not possible there should be a http based protocol pattern with degraded functionality implemented. WebSocket tokenizer/controlblock protocol should like this:

 https://github.com/mabels/clavator/blob/master/src/model/message.ts


## 1. Service Dispatch Protocol (SDP)

The Service Dispatch is to protect against DDoS and Protect against the real discovery of the service endpoint. The Service Discovery should be able without any dns service if ipv6 protocol is used. There will be ipv4 mapping which enable the discovery via tls and dns, but this is deprecated from the first day on.

The purpose of this call is to discover the current valid api endpoint of an specified ApiVersion and the ServiceDomain.

A ServiceEndpoint is a number between 2^16 and 2^64.

##### Request:  GET //sdp.<domain>/?block=<number>&seed=str

Service Dispatch Map for fixed known Endpoint For ApiUsersBlock.

An Api Users Block responses with a static amount of Nouces. It should be more than 64 and less equal 1024 per Block. If the are less assigned nouces these the missing nouces are fill with dummy once.
The Order of the nouces has to be randomized.

###### Response

```
JWT With a Certificated from the Request a Sha256 the Usage Data.
  // JWT Encoding?
  // Patent?
	interface Nouce {
		Nouce: base64-string // 256Bitvalue (msb-lsb)
		Loops: number,  // 1 < 2^24
		PrefixBits: number  // 16-64
	}
	class ServiceDiscover {
      Version: 1
      ApiUsersBlock: number
      ServerSeeed: string
      ServiceDomain: string
      DomainSuffixs: string[]
      Ipv6Networks: string[]
      UsedLoops: number[]
      	Nouces: Nouce[]
      }
   }

   function getNouce() {
     let sha: string = SHA256(PubKeyOfApiUser,
        ApiVersionPubkey,
        ServerSeed,
        ApiUserblock,
        ServiceDomain,
        [ReqSeed]);
     for (i = 1; i < loops; ++i) {
       sha = SHA256(sha);
     }
     // ServiceEndPointId in N where < 2^PrefixBits
     return sha + ServiceEndPointId;
   }
```

The Requestor has to create match nouces with the ReqSeed included and without. This is need if the public service of the sdp is been attacked and a DDoS attack is on going. In this case the service provider try so scale its avaiblity with pushing static content of this into CDN's.

The Requestor pre calculates his nouces with the SHA256(PubKeyOfApiUser, ApiVersionPubkey, ServerSeed, ApiUserblock, ServiceDomain, [ReqSeed]) by using the UsedLoops array. This precalculated-nouces he matches to the
given transfered nouces by doing a prefixmatch like with ipaddress (network/host). If he find a match he extracts the unmatched part and uses that for the serviceEndPointId.
If he uses Ipv6 he adds the discovered serviceEndPointId to the given Ipv6Networks and access the calculated IP Address. On Ipv4 he adds the serviceEndPointId as Base37Coded (a-z0-9-) to the given domain suffixes and try to resolve the created FQDN with a public dns service, and try to access the given FQDN. If DomainSuffixs and Ipv6Networks are multiple the client has to ensure to order the given names/ipaddress in an random order before access the given service endpoints.

# 2. ServiceSessionBlock Control Channel Protocol (SSBCCP)

To open a SSBCCP you should found the Endpoint with the Service Discover Protocol (1. SDP).

```
		class GCMStartMessage {
			Session: uuid
			HashKey: 0-(2^64-2^32)
			Data: { mypubkey, otherpubkey }
			CipherText: sha256(cryptorandom)
			Usefor: number <= 2^16
			ValidUntil: ISOtime; UTC max 1hour future
		}
REQ:
	Signed + Encrypted Message with Requestor PK which was used on 1.
	// check patents
	Class GCMSessions {
		sessions: GCMStartMessage[];
	}
RES: 	
  Class GCMSessions {
		sessions: GCMStartMessage[];
  } | Class ServiceDiscover
```
First every call could be redirected to the servicediscovery. These Sync Key Exchange setup both side to exchange trusted and encrypted messages for the UseFor or the ValidUntil time. Both sides have to ensure that the this sync key exchange will be invalidated within the given time or the it has been used more than usefor. By Requesting <64 Sessions you will get the same amount of sessions back. The requested has to ensure that the used uuid and ciphertext are distinct and the validuntil is no longer than 60minutes or 65536 uses.
The Requested has to ensure that he only issues 1 GCMStartMessage per time so if he have an active one and gets an new SSBCCP he invalidates the running one an sets the Override flag to true. If the client discovers that his SSBCCP was invalid he could reissue a GCMStartMessage but this could be also an induction that somebody tried to send an not authicated GCMStartMessage.

### 3. Message Sequence Protocol (MSP)

The MSP Starts after an successful SSBCCP.
```
	class Message {
		Session: uuid,
		Type: string // PUSH/ACK/NAK
		Seq: number
		NextCipherText: string
		Message: string
	}
```

The Seq number pre decrements to zero from (Usefor). NextCipherText is a sha256(cryptorandom) and message is the payload. The first Message is encrypted with ciphertext from the 2. SSBCCP and this ciphertext is sha256(ciphertext, mypubkey, otherpubkey, seq, uuid). The following messages are encrypted with an inband transfered nextciphertext.
To not getting out of sync this protocol has to strictly syncronized to every opened session. The REQ will be encoded with the received ciphertext from 2. The RES will be encoded with the responded ciphertext.
The Flow of Messages is
```
	req:PUSH(data) -> res:ACK
	req:PUSH(data) -> res:PUSH -> req:ACK -> res:ACK|PUSH
```
