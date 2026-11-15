# The @ldapjs packages this fork carries

`attribute`, `controls`, `dn`, `filter` and `messages` are the @ldapjs
packages ldapjs 3.0.7 decodes requests with, brought into this fork so that
a fix to them is a commit here like any other change to the library. The
upstream packages are decommissioned (npm marks every version deprecated,
and their repositories are archived), so there is nothing to send a fix to
and no release that will carry one.

Each directory is the published tarball of the version ldapjs 3.0.7
resolved to, unchanged except for:

- `package.json`: `devDependencies`, `scripts` and `pre-commit` removed.
  This fork installs them as `file:` dependencies, and npm installs a local
  dependency's devDependencies (each package's tap 16, eslint and
  `@fastify/pre-commit`, which writes a git hook into whatever repository it
  finds above it). Their own tests run under this fork's tap instead
  (`tap.include` in `../package.json`).
- the fixes below, each marked `iya-sts:` in a comment where it is made.

The version numbers are left as published, so every dependent's range (and
`@ldapjs/change`'s exact `"1.0.0"` on `attribute`) is satisfied by these
copies rather than by a second copy from the registry. A project that
installs this fork as a `file:` dependency should also depend on these five
directories itself (`"@ldapjs/dn": "file:<fork>/packages/dn"`, and so on), so
that npm puts them at its own top level where every other @ldapjs package
resolves them; iya-sts does.

`controls` still depends on `@ldapjs/asn1` 1.x, which npm installs in
`packages/controls/node_modules`. Its parsers use that version's API, so the
nested copy must ship with the rest.

## The fixes

**No loop over BER reads the same bytes twice (2026-11-14).** Every
`SEQUENCE OF` was read with `while (ber.offset < end)`, `end` taken from a
length the peer sent, and a BerReader read that cannot be satisfied answers
null without moving the offset. One PDU with an inner length running past
its message therefore looped for ever, and since the parser runs on the
event loop the process stopped answering every connection. Each loop now
throws when an iteration did not advance, which the server reports as a
parser error and answers by closing the connection:

- `messages/lib/parse-to-message.js` (the message's controls)
- `messages/lib/messages/search-request.js` (the attribute selection)
- `messages/lib/messages/add-request.js` (the attribute list)
- `messages/lib/messages/modify-request.js` (the changes)
- `messages/lib/messages/search-result-entry.js` (the attribute list)
- `messages/lib/messages/search-result-reference.js` (the URIs)
- `messages/lib/ldap-result.js` (the referrals)
- `attribute/index.js` (an attribute's value set)
- `filter/lib/ber-parsing/index.js` (an and/or filter's clauses)
- `filter/lib/filters/utils/parse-nested-filter.js` (the same, by tag)
- `filter/lib/filters/substring.js` (initial, any, final)
- `filter/lib/filters/extensible.js` (rule, type, value, dnAttributes)

`../lib/messages/sasl_bind.js`, this fork's own SASL decoder, had the same
loop over the bind's controls and has the same guard.

**A DN parse advances past a space after a hex-string value (2026-11-14).**
`dn/lib/utils/parse-string/index.js` waited for a separator after each
attribute value and never moved past any other character. A hex-string value
(`cn=#4142`) ends at a space, so `cn=#4142 ,o=x` hung the process. Spaces
before a separator are now skipped, as they already were after a string
value, and any other character is an error (the server answers
invalidDNSyntax).

`../test/malformed_ber.test.js` sends each case to a server and checks that
it still answers afterwards.
