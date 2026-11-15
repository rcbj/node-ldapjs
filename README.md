# RCBJ Notes
This is a clone of the original node-ldapjs project. We use this in our [IYA-STS](https://github.com/rcbj/iya-sts)
and [Identity Protocol Debugger](https://github.com/rcbj/id-proto-debugger) projects.

If there is interest in using this code base beyond those projects, we'll publish
this node project and consider supporting it. However, in the meantime, the only changes
being made to this project are what's needed for our use.

The @ldapjs packages ldapjs decodes requests with (`attribute`, `controls`,
`dn`, `filter`, `messages`) are carried in `packages/`, with the fixes
this project needed; `packages/README.md` says what changed.
