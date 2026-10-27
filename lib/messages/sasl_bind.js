'use strict'

// A bind request whose authentication choice is `sasl` (RFC 4511 section
// 4.2):
//
//   BindRequest ::= [APPLICATION 0] SEQUENCE {
//     version         INTEGER (1 .. 127),
//     name            LDAPDN,
//     authentication  AuthenticationChoice }
//   AuthenticationChoice ::= CHOICE {
//     simple  [0] OCTET STRING,
//     sasl    [3] SaslCredentials,
//     ... }
//   SaslCredentials ::= SEQUENCE {
//     mechanism    LDAPString,
//     credentials  OCTET STRING OPTIONAL }
//
// `@ldapjs/messages`' BindRequest decodes only the simple choice and throws
// on any other, which the parser reports as an error with no message, and the
// server then destroys the connection. A server created with
// `saslMechanisms` decodes the sasl choice here instead, before the message
// reaches `@ldapjs/messages`, and hands its handlers a BindRequest that also
// carries the mechanism and the credentials.

const { getControl } = require('@ldapjs/controls')
const messages = require('@ldapjs/messages')
const Protocol = require('@ldapjs/protocol')

const BindRequest = messages.BindRequest

// The context-specific, constructed tag of the sasl choice ([3]).
const SASL_CHOICE = 0xa3
const OCTET_STRING = 0x04

/**
 * A bind request with the sasl authentication choice. Everything a
 * BindRequest has, plus the mechanism and the credentials; `credentials`
 * (the simple choice's password) is empty.
 */
class SaslBindRequest extends BindRequest {
  #mechanism = ''
  #saslCredentials = null

  constructor (options = {}) {
    super(Object.assign({}, options, {
      authentication: BindRequest.SASL_BIND,
      credentials: ''
    }))
    this.#mechanism = String(options.mechanism || '')
    this.#saslCredentials = Buffer.isBuffer(options.saslCredentials)
      ? options.saslCredentials
      : null
  }

  /**
   * Always `sasl`.
   *
   * @type {string}
   */
  get authentication () {
    return BindRequest.SASL_BIND
  }

  /**
   * The SASL mechanism the client named, as it sent it.
   *
   * @type {string}
   */
  get mechanism () {
    return this.#mechanism
  }

  /**
   * The SASL credentials, or null when the client sent none (they are
   * OPTIONAL in SaslCredentials).
   *
   * @type {Buffer | null}
   */
  get saslCredentials () {
    return this.#saslCredentials
  }

  _pojo (obj = {}) {
    super._pojo(obj)
    obj.mechanism = this.#mechanism
    obj.saslCredentials = this.#saslCredentials
      ? this.#saslCredentials.toString('base64')
      : null
    return obj
  }
}

/**
 * Decodes a whole LDAPMessage when it is a bind request with the sasl
 * choice, and answers null for every other message, which the caller then
 * hands to `@ldapjs/messages` as before. The reader is not advanced.
 *
 * @param {import('@ldapjs/asn1').BerReader} ber the LDAPMessage, positioned
 * at its SEQUENCE tag
 * @returns {SaslBindRequest | null}
 * @throws when the message is a sasl bind and is malformed
 */
function parseSaslBind (ber) {
  const start = ber.offset
  try {
    ber.readSequence()
    const messageId = ber.readInt()
    if (ber.peek() !== Protocol.operations.LDAP_REQ_BIND) {
      return null
    }
    ber.readSequence(Protocol.operations.LDAP_REQ_BIND)
    const version = ber.readInt()
    const name = ber.readString()
    if (ber.peek() !== SASL_CHOICE) {
      return null
    }
    ber.readSequence(SASL_CHOICE)
    const end = ber.offset + ber.length
    const mechanism = ber.readString(OCTET_STRING)
    if (typeof mechanism !== 'string') {
      throw Error('malformed SaslCredentials: no mechanism')
    }
    let saslCredentials = null
    if (ber.offset < end) {
      saslCredentials = ber.readString(OCTET_STRING, true)
      if (!Buffer.isBuffer(saslCredentials)) {
        throw Error('malformed SaslCredentials: unreadable credentials')
      }
    }
    const message = new SaslBindRequest({
      messageId,
      version,
      name,
      mechanism,
      saslCredentials
    })
    if (ber.remain > 0 && ber.peek() === 0xa0) {
      ber.readSequence()
      const controlsEnd = ber.offset + ber.length
      while (ber.offset < controlsEnd) {
        const control = getControl(ber)
        if (control) {
          message.addControl(control)
        }
      }
    }
    return message
  } finally {
    ber.setOffset(start)
  }
}

module.exports = {
  SASL_CHOICE,
  SaslBindRequest,
  parseSaslBind
}
