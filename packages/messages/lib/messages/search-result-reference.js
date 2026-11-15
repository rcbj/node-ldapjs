'use strict'

const LdapMessage = require('../ldap-message')
const { operations } = require('@ldapjs/protocol')

/**
 * Implements the search result reference response message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.5.2.
 */
class SearchResultReference extends LdapMessage {
  #uri

  /**
   * @typedef {LdapMessageOptions} SearchResultReferenceOptions
   * @property {string[]} [uri=[]] The set of reference URIs the message is
   * providing.
   * @property {string[]} [uris] An alias for uri.
   */

  /**
   * @param {SearchResultReferenceOptions} options
   */
  constructor (options = {}) {
    options.protocolOp = operations.LDAP_RES_SEARCH_REF
    super(options)

    this.uri = (options.uri || options.uris) ?? []
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'SearchResultReference'
  }

  /**
   * The list of reference URIs associated with the message.
   *
   * @returns {string[]}
   */
  get uri () {
    return this.#uri.slice(0)
  }

  /**
   * Define the list of reference URIs associated with the message.
   *
   * @param {string[]} value
   *
   * @throws When the value is not an array or contains a non-string element.
   */
  set uri (value) {
    if (
      Array.isArray(value) === false ||
      value.some(v => typeof v !== 'string')
    ) {
      throw Error('uri must be an array of strings')
    }
    this.#uri = value.slice(0)
  }

  /**
   * Alias of {@link uri}.
   *
   * @returns {string[]}
   */
  get uris () {
    return this.uri
  }

  /**
   * Alias of {@link uri} setter.
   *
   * @param {string[]} value
   */
  set uris (value) {
    this.uri = value
  }

  /**
   * Internal use only.
   *
   * @param {import('@ldapjs/asn1').BerWriter} ber
   *
   * @returns {import('@ldapjs/asn1').BerWriter}
   */
  _toBer (ber) {
    ber.startSequence(operations.LDAP_RES_SEARCH_REF)

    for (const uri of this.#uri) {
      ber.writeString(uri)
    }

    ber.endSequence()
    return ber
  }

  /**
   * Internal use only.
   *
   * @param {object}
   *
   * @returns {object}
   */
  _pojo (obj = {}) {
    obj.uri = []
    for (const uri of this.#uri) {
      obj.uri.push(uri)
    }
    return obj
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   *
   * @returns {object}
   */
  static parseToPojo (ber) {
    const protocolOp = ber.readSequence()
    if (protocolOp !== operations.LDAP_RES_SEARCH_REF) {
      const op = protocolOp.toString(16).padStart(2, '0')
      throw Error(`found wrong protocol operation: 0x${op}`)
    }

    const uri = []

    const endOfMessagePos = ber.offset + ber.length
    while (ber.offset < endOfMessagePos) {
      const before = ber.offset
      const u = ber.readString()
      // iya-sts: a read that answers null leaves the offset where it was,
      // and a length that runs past the buffer kept this loop going for
      // ever on the same bytes, which hung the whole process. An
      // iteration that does not advance is malformed BER.
      if (ber.offset <= before) {
        throw Error('malformed reference URI at offset ' + before)
      }
      uri.push(u)
    }

    return { protocolOp, uri }
  }
}

module.exports = SearchResultReference
