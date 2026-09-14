"""What a restore has to tell the operator, beyond that it worked.

Two facts an archive can carry are useless in a log and necessary in the
answer: a record whose stored private key is not its certificate's, which the
export records deliberately rather than refusing to be taken, and sections the
archive holds that this version does not apply.

Written once because there are two ways to ask for a restore, and each time
the two drifted apart it was the operator who lost: the same archive, restored
from one page or the other, said different things about itself.
"""
from typing import Any, Dict


def with_restore_warnings(message: str, results: Dict[str, Any]) -> str:
    """`message`, followed by what the archive had to warn about.

    The joining is here rather than at each caller because the two messages
    are punctuated differently: one ends with a full stop and the other does
    not, so appending a clause that begins with one produced `again.. 1
    record(s)…` on one side and read correctly on the other.
    """
    message = message.rstrip().rstrip('.')

    not_restored = (results or {}).get('sections_not_restored') or []
    if not_restored:
        # The archive carries more than this version applies; saying so is
        # the difference between a restore and a restore that looked fine.
        message += ('. The archive also holds sections this version does not '
                    'restore: ' + ', '.join(not_restored))

    mismatches = (results or {}).get('key_mismatches') or []
    if mismatches:
        # Recorded when the archive was written. An authority whose key is
        # not its certificate's signs certificates nobody can verify, and the
        # operator has to hear it now rather than from the first client that
        # refuses the chain.
        message += (f'. {len(mismatches)} record(s) carry a private key that '
                    "is not their certificate's and cannot sign: "
                    + ', '.join(mismatches[:5]))

    return message + '.' if not message.endswith('.') else message
