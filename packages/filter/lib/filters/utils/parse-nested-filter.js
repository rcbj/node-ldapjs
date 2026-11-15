'use strict'

const { search } = require('@ldapjs/protocol')
const { BerReader } = require('@ldapjs/asn1')

module.exports = function parseNestedFilter ({ startTag, buffer, constructor }) {
  // We need to import all of the filter objects within the function
  // because this function is meant to be used within each of the objects's
  // `parse` methods. If we import outside of this function, we will get
  // circular import errors.
  const FILTERS = {
    [search.FILTER_AND]: require('../and'),
    [search.FILTER_APPROX]: require('../approximate'),
    [search.FILTER_EQUALITY]: require('../equality'),
    [search.FILTER_EXT]: require('../extensible'),
    [search.FILTER_GE]: require('../greater-than-equals'),
    [search.FILTER_LE]: require('../less-than-equals'),
    [search.FILTER_NOT]: require('../not'),
    [search.FILTER_OR]: require('../or'),
    [search.FILTER_PRESENT]: require('../presence'),
    [search.FILTER_SUBSTRINGS]: require('../substring')
  }

  const reader = new BerReader(buffer)

  const seq = reader.readSequence()
  if (seq !== startTag) {
    const expected = '0x' + startTag.toString(16).padStart(2, '0')
    const found = '0x' + seq.toString(16).padStart(2, '0')
    throw Error(`expected filter tag ${expected}, got ${found}`)
  }

  const filters = []
  const currentFilterLength = reader.length
  while (reader.offset < currentFilterLength) {
    const before = reader.offset
    const tag = reader.peek()
    const tagBuffer = reader.readRawBuffer(tag)
    // iya-sts: a read that answers null leaves the offset where it was,
    // and a length that runs past the buffer kept this loop going for
    // ever on the same bytes, which hung the whole process. An
    // iteration that does not advance is malformed BER.
    if (tagBuffer === null || reader.offset <= before) {
      throw Error('malformed filter at offset ' + before)
    }
    const filter = FILTERS[tag].parse(tagBuffer)
    filters.push(filter)
  }

  if (constructor === FILTERS[search.FILTER_NOT]) {
    return new constructor({ filter: filters[0] })
  }

  return new constructor({ filters })
}
