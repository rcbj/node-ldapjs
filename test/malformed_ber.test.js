'use strict'

// Malformed requests that used to send the server into a loop it never left.
//
// The @ldapjs packages (packages/ in this fork) read a SEQUENCE OF with
// `while (ber.offset < end)`, where `end` comes from a length the client
// sent, and a BerReader read that cannot be satisfied answers null WITHOUT
// moving the offset. One PDU whose inner length runs past the end of the
// message therefore made the loop read the same bytes for ever, and since
// the parser runs on the event loop the whole process stopped answering
// every connection, not just the one that sent it. The DN parser had the
// same shape: after a hex-string value (`cn=#4142`) it waited for a
// separator and never advanced past anything else, so a bind name of
// `cn=#4142 ,o=x` hung it too.
//
// Each case is sent on its own connection. The connection must be closed
// (or, for a DN, answered), and a simple bind on a fresh connection must
// still be answered afterwards. The decoders are also run directly under a
// vm timeout, so a regression fails here instead of hanging the runner.

const net = require('net')
const vm = require('vm')
const tap = require('tap')
const { BerReader } = require('@ldapjs/asn1')
const { DN } = require('@ldapjs/dn')
const messages = require('@ldapjs/messages')
const ldap = require('../lib')
const { Parser } = require('../lib/messages')

// A TLV with the shortest definite length.
function tlv (tag, ...parts) {
  const body = Buffer.concat(parts)
  let len
  if (body.length < 0x80) {
    len = Buffer.from([body.length])
  } else if (body.length < 0x100) {
    len = Buffer.from([0x81, body.length])
  } else {
    len = Buffer.from([0x82, body.length >> 8, body.length & 0xff])
  }
  return Buffer.concat([Buffer.from([tag]), len, body])
}
const raw = (hex) => Buffer.from(hex.replace(/\s+/g, ''), 'hex')
const str = (tag, s) => tlv(tag, Buffer.from(s, 'utf8'))
const int = (n) => tlv(0x02, Buffer.from([n]))
const message = (id, op, ...rest) => tlv(0x30, int(id), op, ...rest)

const BASE = 'dc=example,dc=com'
// SearchRequest fields up to the filter: base, scope, deref, size, time,
// typesOnly.
const searchHead = Buffer.concat([str(0x04, BASE), raw('0a0102 0a0100'),
  int(0), int(0), raw('010100')])
const search = (filter, attributes) =>
  tlv(0x63, searchHead, filter, attributes || tlv(0x30))

// The four PDUs the Rust port (iya-sts #444, sts-ldap) found, as its corpus
// has them, then one per other loop of the same shape.
const CASES = [
  {
    name: 'bind name with a hex value then a space (the DN parser)',
    pdu: raw('30290201086024020103041b636e3d2334313432202c64633d6578616d70' +
      '6c652c64633d636f6d80027077'),
    answered: true
  },
  {
    name: 'search whose control list runs past its sequence',
    pdu: raw('302f02011e6327041164633d6578616d706c652c64633d636f6d0a01020a' +
      '01000201000201000101008701783000a00330')
  },
  {
    name: 'search with a substring initial longer than the filter',
    pdu: raw('303502011e6330041164633d6578616d706c652c64633d636f6d0a01020a' +
      '0100020100020100010100a40a0402636e30048021616c3000')
  },
  {
    name: 'search with an extensible match value longer than the filter',
    pdu: raw('304302011e633e041164633d6578616d706c652c64633d636f6d0a01020a' +
      '0100020100020100010100a9188108322e352e31332e358202636e838441' +
      '6c6963658401ff3000')
  },
  {
    name: 'bind name with a hex value then a stray character',
    pdu: message(9, tlv(0x60, int(3), str(0x04, 'cn=#4142 x,' + BASE),
      str(0x80, 'pw'))),
    answered: true
  },
  {
    name: 'search with an attribute selector longer than the list',
    pdu: message(10, search(str(0x87, 'cn'), raw('3002 0405')))
  },
  {
    name: 'add with an attribute value longer than its set',
    pdu: message(11, tlv(0x68, str(0x04, 'cn=a,' + BASE),
      tlv(0x30, tlv(0x30, str(0x04, 'cn'), raw('3103 0405 61')))))
  },
  {
    name: 'modify with a change value longer than its set',
    pdu: message(12, tlv(0x66, str(0x04, 'cn=a,' + BASE),
      tlv(0x30, tlv(0x30, raw('0a0100'),
        tlv(0x30, str(0x04, 'cn'), raw('3103 0405 61'))))))
  },
  {
    name: 'search result reference with a URI longer than the message',
    pdu: message(13, raw('7303 0405 61'))
  },
  {
    name: 'search result entry with a value longer than its set',
    pdu: message(14, tlv(0x64, str(0x04, 'cn=a,' + BASE),
      tlv(0x30, tlv(0x30, str(0x04, 'cn'), raw('3103 0405 61')))))
  },
  {
    name: 'SASL bind whose control list runs past its sequence',
    pdu: message(15, tlv(0x60, int(3), str(0x04, ''),
      tlv(0xa3, str(0x04, 'EXTERNAL'))), raw('a003 30')),
    sasl: true
  }
]

function simpleBind (id) {
  return message(id, tlv(0x60, int(3), str(0x04, 'cn=x,' + BASE),
    str(0x80, 'pw')))
}

function readResultCode (buffer) {
  const ber = new BerReader(buffer)
  ber.readSequence()
  ber.readInt()
  ber.readSequence()
  return ber.readEnumeration()
}

// Writes one PDU on a fresh connection and calls back with the first result
// code, or `closed` when the server closed the connection instead.
function exchange (server, pdu, callback) {
  const socket = net.connect(server.port, '127.0.0.1')
  let data = Buffer.alloc(0)
  let done = false
  const timer = setTimeout(function () { finish({ timeout: true }) }, 3000)
  function finish (answer) {
    if (done) { return }
    done = true
    clearTimeout(timer)
    socket.destroy()
    callback(answer)
  }
  socket.on('data', function (chunk) {
    data = Buffer.concat([data, chunk])
    try {
      finish({ resultCode: readResultCode(data) })
    } catch (e) {
      // Not all of it yet.
    }
  })
  socket.on('close', function () { finish({ closed: true }) })
  socket.on('error', function () { finish({ closed: true }) })
  socket.write(pdu)
}

function listening (callback) {
  const server = ldap.createServer({ saslMechanisms: ['EXTERNAL'] })
  server.on('error', function () {
    // A parser error is reported here as well; the connection is what the
    // tests look at.
  })
  const answer = function (req, res, next) {
    res.end()
    return next()
  }
  server.bind('', answer)
  server.search('', answer)
  server.add('', answer)
  server.modify('', answer)
  server.listen(0, '127.0.0.1', function () { callback(server) })
}

tap.test('every malformed PDU ends its connection, and the server still ' +
  'answers', function (t) {
  listening(function (server) {
    let i = 0
    const next = function () {
      if (i === CASES.length) {
        server.close(() => t.end())
        return
      }
      const one = CASES[i++]
      exchange(server, one.pdu, function (got) {
        t.notOk(got.timeout, one.name + ': the server did not hang')
        if (one.answered) {
          t.ok(got.resultCode !== undefined || got.closed,
            one.name + ': answered or closed')
        } else {
          t.ok(got.closed, one.name + ': the connection was closed')
        }
        exchange(server, simpleBind(2), function (after) {
          t.equal(after.resultCode, 0,
            one.name + ': a simple bind afterwards is answered')
          next()
        })
      })
    }
    next()
  })
})

tap.test('a bind name with a hex value', function (t) {
  listening(function (server) {
    const bind = (name) => message(3, tlv(0x60, int(3), str(0x04, name),
      str(0x80, 'pw')))
    exchange(server, bind('cn=#4142 ,' + BASE), function (got) {
      t.equal(got.resultCode, 0, 'a space before the comma is accepted')
      exchange(server, bind('cn=#4142 x,' + BASE), function (got) {
        t.equal(got.resultCode, 34,
          'anything else after the value is invalidDNSyntax')
        server.close(() => t.end())
      })
    })
  })
})

// The parser and the DN parser run under a watchdog: a loop that comes back
// fails here rather than hanging the test.
function underWatchdog (fn) {
  return vm.runInNewContext('fn()', { fn }, { timeout: 2000 })
}

tap.test('the parser reports each malformed PDU as an error', function (t) {
  for (const one of CASES) {
    if (one.answered) { continue }
    const parser = new Parser({ decodeSaslBinds: one.sasl === true })
    const seen = []
    parser.on('message', function (m) { seen.push('message ' + m.type) })
    parser.on('error', function (e) { seen.push('error ' + e.message) })
    try {
      underWatchdog(function () { parser.write(one.pdu) })
    } catch (e) {
      seen.push('threw ' + (e.code || e.message))
    }
    t.equal(seen.length, 1, one.name + ': one outcome ' + seen.join('; '))
    t.match(seen[0], /^error /, one.name + ': an error')
  }
  t.end()
})

tap.test('the DN parser advances past what follows a hex value', function (t) {
  const parse = function (s) {
    return underWatchdog(function () {
      try {
        return DN.fromString(s).toString()
      } catch (e) {
        return 'throws'
      }
    })
  }
  t.equal(parse('cn=#4142 ,o=x'), 'cn=#4142,o=x')
  t.equal(parse('cn=#4142  '), 'cn=#4142')
  t.equal(parse('cn=#4142 +sn=y,o=x'), 'cn=#4142+sn=y,o=x')
  t.equal(parse('cn=#4142 x,o=x'), 'throws')
  t.equal(parse('cn=#4142;o=x'), 'cn=#4142,o=x')
  t.end()
})

tap.test('a well-formed request still decodes', function (t) {
  const pdu = message(4, search(str(0x87, 'cn'),
    tlv(0x30, str(0x04, 'cn'), str(0x04, 'mail'))),
  tlv(0xa0, tlv(0x30, str(0x04, '1.2.840.113556.1.4.319'),
    raw('0101ff'), str(0x04, ''))))
  const m = messages.LdapMessage.parse(new BerReader(pdu))
  t.equal(m.type, 'SearchRequest')
  t.same(m.attributes, ['cn', 'mail'])
  t.equal(m.controls.length, 1)
  t.end()
})
