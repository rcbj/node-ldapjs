'use strict'

// SASL binds (RFC 4511 section 4.2): the `saslMechanisms` and
// `bindDnFromHandler` server options. ldapjs's own client sends only simple
// binds, so the SASL bind request is written here by hand and its
// BindResponse read back the same way.

const net = require('net')
const tap = require('tap')
const { BerReader, BerWriter } = require('@ldapjs/asn1')
const ldap = require('../lib')

function saslBind (messageId, name, mechanism, credentials) {
  const ber = new BerWriter()
  ber.startSequence()
  ber.writeInt(messageId)
  ber.startSequence(0x60)
  ber.writeInt(3)
  ber.writeString(name)
  ber.startSequence(0xa3)
  ber.writeString(mechanism)
  if (credentials !== undefined) {
    ber.writeBuffer(Buffer.from(credentials), 0x04)
  }
  ber.endSequence()
  ber.endSequence()
  ber.endSequence()
  return ber.buffer
}

function readBindResponse (buffer) {
  const ber = new BerReader(buffer)
  ber.readSequence()
  const messageId = ber.readInt()
  ber.readSequence(0x61)
  const resultCode = ber.readEnumeration()
  const matchedDN = ber.readString()
  const diagnosticMessage = ber.readString()
  return { messageId, resultCode, matchedDN, diagnosticMessage }
}

// Sends one request on a fresh connection and answers the first response, or
// `{ closed: true }` when the server closed the connection instead.
function exchange (server, request, callback) {
  const socket = net.connect(server.port, '127.0.0.1')
  let data = Buffer.alloc(0)
  let done = false
  function finish (answer) {
    if (done) { return }
    done = true
    socket.destroy()
    callback(answer)
  }
  socket.on('data', function (chunk) {
    data = Buffer.concat([data, chunk])
    try {
      finish(readBindResponse(data))
    } catch (e) {
      // Not all of it yet.
    }
  })
  socket.on('close', function () { finish({ closed: true }) })
  socket.on('error', function () { finish({ closed: true }) })
  socket.write(request)
}

function listening (options, handler, callback) {
  const server = ldap.createServer(options)
  server.bind('', handler)
  server.listen(0, '127.0.0.1', function () { callback(server) })
}

tap.test('by default a SASL bind cannot be decoded and the connection closes',
  function (t) {
    let called = false
    listening({}, function (req, res, next) {
      called = true
      res.end()
      return next()
    }, function (server) {
      let parserError = null
      server.on('error', function (err) { parserError = err })
      t.equal(server._saslMechanisms, null, 'no mechanisms by default')
      exchange(server, saslBind(1, '', 'EXTERNAL'), function (answer) {
        t.equal(answer.closed, true, 'the connection was closed')
        t.match(String(parserError), /0xa3 not supported/,
          'after @ldapjs/messages refused the sasl choice')
        t.equal(called, false, 'and no bind handler saw it')
        server.close(() => t.end())
      })
    })
  })

tap.test('saslMechanisms routes a SASL bind with an empty name to its handler',
  function (t) {
    const seen = []
    listening({ saslMechanisms: ['EXTERNAL'] }, function (req, res, next) {
      seen.push({
        dn: req.dn.toString(),
        authentication: req.authentication,
        mechanism: req.mechanism,
        credentials: req.saslCredentials
      })
      res.end()
      return next()
    }, function (server) {
      t.same(server._saslMechanisms, ['EXTERNAL'], 'the server took it')
      exchange(server, saslBind(1, '', 'EXTERNAL'), function (first) {
        t.equal(first.resultCode, 0, 'answered by the handler with success')
        t.equal(first.messageId, 1, 'for that message')
        exchange(server, saslBind(2, '', 'EXTERNAL', 'dn:cn=a,dc=test'),
          function (second) {
            t.equal(second.resultCode, 0, 'with credentials too')
            t.equal(seen.length, 2, 'the handler saw both, although the ' +
              'empty name and empty password are an anonymous bind\'s')
            t.equal(seen[0].dn, '', 'the name as sent')
            t.equal(seen[0].authentication, 'sasl', 'the choice')
            t.equal(seen[0].mechanism, 'EXTERNAL', 'the mechanism')
            t.equal(seen[0].credentials, null, 'no credentials were sent')
            t.ok(Buffer.isBuffer(seen[1].credentials), 'credentials as bytes')
            t.equal(String(seen[1].credentials), 'dn:cn=a,dc=test',
              'as they were sent')
            server.close(() => t.end())
          })
      })
    })
  })

tap.test('a mechanism not in saslMechanisms is answered 7 by the server',
  function (t) {
    let called = false
    let emitted = null
    listening({ saslMechanisms: ['EXTERNAL'], encodeErrorMessage: true },
      function (req, res, next) {
        called = true
        res.end()
        return next()
      }, function (server) {
        server.on('saslMechanismNotSupported', function (req) {
          emitted = req.mechanism
        })
        exchange(server, saslBind(1, '', 'PLAIN', '\u0000a\u0000b'),
          function (answer) {
            t.equal(answer.resultCode, 7, 'authMethodNotSupported')
            t.match(answer.diagnosticMessage, /PLAIN/, 'naming it')
            t.equal(called, false, 'the handler never saw it')
            t.equal(emitted, 'PLAIN', 'and the server said so')
            server.close(() => t.end())
          })
      })
  })

tap.test('a simple bind is unchanged with saslMechanisms', function (t) {
  listening({ saslMechanisms: ['EXTERNAL'] }, function (req, res, next) {
    t.equal(req.authentication, undefined, 'not a SASL bind')
    res.end()
    return next()
  }, function (server) {
    const client = ldap.createClient({ url: server.url })
    client.bind('cn=someone', 'secret', function (err) {
      t.error(err, 'the simple bind succeeds')
      client.unbind()
      server.close(() => t.end())
    })
  })
})

tap.test('bindDnFromHandler binds the connection as the DN the handler names',
  function (t) {
    let connection = null
    listening({ saslMechanisms: ['EXTERNAL'], bindDnFromHandler: true },
      function (req, res, next) {
        connection = req.connection
        res.bindDN = 'cn=alice,dc=test'
        res.end()
        return next()
      }, function (server) {
        t.equal(server._bindDnFromHandler, true, 'the server took it')
        exchange(server, saslBind(1, '', 'EXTERNAL'), function (answer) {
          t.equal(answer.resultCode, 0, 'the bind succeeded')
          t.equal(connection.ldap.bindDN.toString(), 'cn=alice,dc=test',
            'as the DN the handler named')
          server.close(() => t.end())
        })
      })
  })

tap.test('without bindDnFromHandler the request\'s name is bound',
  function (t) {
    let connection = null
    listening({ saslMechanisms: ['EXTERNAL'] }, function (req, res, next) {
      connection = req.connection
      res.bindDN = 'cn=alice,dc=test'
      res.end()
      return next()
    }, function (server) {
      t.equal(server._bindDnFromHandler, false, 'off by default')
      exchange(server, saslBind(1, 'cn=bob,dc=test', 'EXTERNAL'),
        function (answer) {
          t.equal(answer.resultCode, 0, 'the bind succeeded')
          t.equal(connection.ldap.bindDN.toString(), 'cn=bob,dc=test',
            'as the request\'s name, whatever the handler set')
          server.close(() => t.end())
        })
    })
  })

tap.test('a refused bind leaves the connection as it was', function (t) {
  let connection = null
  listening({ saslMechanisms: ['EXTERNAL'], bindDnFromHandler: true },
    function (req, res, next) {
      connection = req.connection
      res.bindDN = 'cn=alice,dc=test'
      return next(new ldap.InvalidCredentialsError('no'))
    }, function (server) {
      exchange(server, saslBind(1, '', 'EXTERNAL'), function (answer) {
        t.equal(answer.resultCode, 49, 'refused')
        t.equal(connection.ldap.bindDN.toString(), 'cn=anonymous',
          'and the connection is not bound as the named DN')
        server.close(() => t.end())
      })
    })
})

tap.test('the options are checked', function (t) {
  t.throws(function () {
    ldap.createServer({ saslMechanisms: 'EXTERNAL' })
  }, TypeError, 'saslMechanisms must be an array')
  t.throws(function () {
    ldap.createServer({ saslMechanisms: [''] })
  }, TypeError, 'of non-empty names')
  t.throws(function () {
    ldap.createServer({ bindDnFromHandler: 'yes' })
  }, TypeError, 'bindDnFromHandler must be a boolean')
  t.end()
})
