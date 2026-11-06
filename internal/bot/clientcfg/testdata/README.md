# Fixtures for the client config generators

## `inbounds.json`

The live deployment's `inbounds` and `endpoints`, with every credential
replaced. Real shapes, because the fields a generator reads are exactly the
ones that differ between protocols — `short_id` is a list here and a string
there, `host` likewise, mieru states its transport as `portBindings` — and
inventing them would test the invention.

Produced by one privileged read of the server's config, passed through a
redactor, and reviewed by eye before committing. Replaced:

| field | with |
|---|---|
| `private_key` (Reality, WireGuard) | a freshly generated, valid x25519 key |
| `header_protection_key` | a freshly generated 32-byte key |
| `short_id` | `0123456789abcdef` |
| `password`, `secret`, `psk`, `userkey`, `uuid`, `pre_shared_key` | `redacted-<field>` |
| `users[]` | two synthetic users, `user1` and `user2` |
| `peers[]` | emptied |

The Reality and header-protection keys are real keys rather than placeholders
on purpose: public-key derivation has to be exercised for real, and a
placeholder would make that test assert nothing. They were generated for this
file and are used nowhere.

Checked after generating: no string of 16 characters or more appears in both
this file and the server's config except field names and public hostnames.
Worth repeating if the redactor is ever changed — the two leaks found the
first time round were `header_protection_key` and `short_id`, neither of
which was in the original list.

## `python-links.json`

What `bot.py`'s `build_link` produces for every inbound in `inbounds.json`,
given the user `user1`. The oracle for `TestLinksMatchThePythonBot`, which
requires byte equality: a user who re-imports must get the string they already
had, and a reordered query or a differently escaped space is a different
string even when it describes the same server.

**No longer regenerable, deliberately.** `bot.py` was deleted on 2026-11-03
with the bot it was, and the script that produced this file went with it. That
makes the oracle immutable, which is a stronger check than it was: a failing
comparison can no longer be answered by refreshing the file, only by arguing
that the generator was meant to change.

Only regenerate after deciding a generator change was intended. The point of
the file is to notice changes that were not.

## `python-nodes.json`

What `bot.py` produces for the same fixture, for two generators at once:

- `nodes` — `_sb_outbound` per inbound, keyed by tag. `null` where the type has
  no bundle node of its own (mtproto, shadowsocks, shadowtls and masque-wg all
  arrive by another route).
- `configs` — `build_json_config` for each tag in `JSON_TAGS`.

The oracle for `TestBundleNodesMatchThePythonBot` and
`TestJSONConfigsMatchThePythonBot`, which compare **structures**, not bytes.
Byte equality would be false precision here: the structural hash the refresh
loop stores is computed with sorted keys, so key order cannot affect it, and
the two languages render spacing differently for no semantic reason. What has
to match is content — a missing field is a node that will not decode, and an
extra one is a config the client rejects outright.

Frozen for the same reason as above. The generating script is gone.

`build_json_config` reached for the ShadowTLS backend over the core's API and
the script served it from the fixture instead of standing up a stub, which is
why the Go side takes the backend as an argument rather than fetching it.

## `live-node-shapes.json`

The key sets of the nodes the running deployment actually serves, taken from a
real subscription. **Names only, no values** — the point is that a Go node
carries the same fields, and an extra or missing one is exactly what makes a
client reject the configuration.

Captured from a `/sub` response by keeping `sorted(node.keys())` per node type
and, for chain nodes, per leg. Regenerate by fetching a subscription and
reducing it the same way; it carries no credentials, so it is safe to commit.

It is the only check in this package that compares against production rather
than against the Python, which makes it the one that would notice the two
drifting apart.

## What the contract test adds on top of these

`contract_test.go` takes the same fixture and hands every generated artefact to
the core that will actually read it — the client core for everything a user
receives, the server core for the WARP registration config alone. That split is
the whole point: on 2026-11-01 a client-facing MASQUE config was moved to the
server's schema, passed a check against the server core, and left six users
without the WARP path for two days.

Two substitutions happen there rather than in this file, both because the core
decodes credentials instead of merely carrying them:

- the shadowsocks password, which the core reads as a key of the method's exact
  length and which `redacted-password` fails at byte 8;
- the MASQUE account, whose field set has to be `option.MASQUEAccount`'s
  exactly, since an unknown field is rejected outright.

Keeping them out of the fixture avoids regenerating the Python oracles that
quote it. If a future change puts real credentials in here instead, re-run the
leak check described above first.

Set `CONTRACT_REQUIRED=1` to turn the test's skips into failures. The client
core lives outside this repository, so without that flag its absence is a skip
— and a gate that reports success for checks which never ran is worse than a
red one.
