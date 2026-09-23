# Evidence review and embedded inventory

Automatic detection is an observation, not proof of a vulnerability. The default
Vulnerabilities view now contains only items explicitly marked **Confirmed** by
the operator. **Needs review** holds scanner and AI observations separately.
Confidence refers to the observed pattern, not proof of security impact.

The server applies this rule to every source: runtime alerts, rule scans, AI, PE,
pipe permissions, DCOM, TLS, privilege checks and secret scanners. Incoming
`validation_status: confirmed` or `ui_review_status: Confirmed` cannot bypass it.
Existing review decisions survive rescans only for the same source and unchanged
evidence. Dismissed items remain available in the review queue with their status.
Confirmed means operator-reviewed; it is not a claim of mathematical certainty.

In the detail pane, review the evidence and the affected security boundary before
changing Review status. Missing evidence belongs in **In review**. Changes sync
to the server and persist in session archives. Legacy archives without an explicit
confirmation return to review rather than silently entering the confirmed list.

## Precision changes

- Plaintext at a TLS or crypto hook is expected; it does not establish unencrypted transport.
- A failed DLL lookup does not establish a loaded DLL or a writable search path.
- File/registry names, API calls and algorithm names do not establish unsafe usage.
- SQL-like text, database errors, serialization magic bytes and JWT syntax do not prove server-side acceptance or exploitability.
- A random hex/base64 string or high entropy alone is not sufficient secret evidence.
- Runtime credentials are not labelled hardcoded solely because they appear in memory.
- Repeated memory fingerprints do not prove that logout cleanup is defective.
- Cookie flags are parsed as attributes of complete HTTP response headers, not substrings in values or body text.

The rule scan reads the retained server capture, avoiding the old browser's
50-packet/200-string input slices. Its remaining credential, cookie and DPAPI
observations still require review. Raw capture remains available for inspection.

## Embedded inventory

The on-disk scan never executes the selected file. It extracts labelled literals
from ASCII/UTF-8 and UTF-16 LE/BE runs, including Turkish field names such as
`kullanıcı_adı`, `şifre` and `parola`. JSON-style assignments, XML elements/settings,
connection-string assignments and URL userinfo are supported. Complete JWT-shaped
and PEM-delimited values are candidates, not authenticated or parsed key claims.

Validated IPv4/IPv6 addresses and URLs are informational inventory. Version-like
addresses with explicit version/build labels are ignored. Credentials are masked
by default with length, SHA-256 and byte offsets retained. URLs hide userinfo,
query values and fragments; paths may still contain application-specific data.
**Reveal values** is an explicit local option. No credential is tested and no
discovered endpoint is contacted.

Multiple values per string are retained. Deduplication uses category plus full-value
hash, preserving occurrence counts and up to 20 recorded offsets. Nearby username
and password strings are not automatically paired as a valid account. Known dummy
values, environment references, empty values and placeholders are suppressed.

The optional managed helper reports whether a value is a metadata literal, a
runtime static value, or only a member name. Unavailable values remain inventory;
entropy-only guesses are suppressed. The default reflection-only mode does not
execute static constructors. Deep mode remains an explicit existing opt-in.

Limits: first 64 MiB of the selected file, up to 1,000 inventory items, and 4,096
characters per labelled literal. File/result limits are reported explicitly;
credential candidates take precedence over endpoint inventory at the item limit.
Encrypted, packed, dynamically constructed, obfuscated or unlabelled values may
be missed. Synthetic regression tests establish these behaviors, not a measured
false-positive rate on real applications.

The latest inventory and both review/confirmed lists are preserved by Save/Load.
MCP can read the inventory through `get_session_records` with collection
`artifact_inventory`, and read candidates via `get_review_queue` or the saved
`observations` collection.
