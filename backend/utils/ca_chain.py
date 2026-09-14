"""One bounded walk of the CA hierarchy, for every place that builds a chain.

Nothing in the schema forbids a loop: ``CA.caref`` holds the parent's
``refid`` as a plain string, with no foreign key, so a repaired or imported
hierarchy can point a CA at itself or at one of its own descendants. Every
consumer used to inline its own ``while ca:`` walk, and they did not agree on
what to do about it — some raised, some stopped, and several had no guard at
all and span forever on the same rows.

This module holds the walk once. Callers keep their own output format and
their own contract for a chain that cannot be completed:

- ``on_cycle='stop'`` / ``on_missing='stop'`` end the walk (the chain comes
  back short, which is what the export paths have always done);
- ``on_cycle='raise'`` / ``on_missing='raise'`` raise ``ValueError`` with the
  caller's own message, which is what the SCEP chain does.

The depth ceiling is the one ``CA.revoked_in_chain`` already enforces: a
hierarchy deeper than that is refused at issuance, so no chain this walk can
legitimately meet is longer.
"""

MAX_CHAIN_DEPTH = 64


def walk_ca_chain(start, *, include_start=True, max_depth=MAX_CHAIN_DEPTH,
                  on_cycle='stop', on_missing='stop',
                  cycle_message='CA chain loops on itself',
                  missing_message='CA chain is incomplete'):
    """Yield *start* and then each parent resolved through ``caref``.

    Parameters
    ----------
    start:
        The CA to walk up from. ``None`` yields nothing (or raises, when
        ``on_missing='raise'``).
    include_start:
        ``False`` walks the ancestors only. *start* is still marked visited,
        so a parent pointing back at it counts as a loop.
    max_depth:
        Ceiling on the number of CAs visited, *start* included.
    on_cycle, on_missing:
        ``'stop'`` (default) or ``'raise'``.

    Yields
    ------
    CA
        Each CA of the chain, nearest first, at most once.
    """
    from models import CA

    if start is None:
        if on_missing == 'raise':
            raise ValueError(missing_message)
        return

    seen = set()
    ca = start
    depth = 0

    while ca is not None:
        refid = getattr(ca, 'refid', None)
        if refid is not None:
            if refid in seen:
                if on_cycle == 'raise':
                    raise ValueError(cycle_message)
                return
            seen.add(refid)

        depth += 1
        if depth > max_depth:
            if on_cycle == 'raise':
                raise ValueError(cycle_message)
            return

        if include_start or ca is not start:
            yield ca

        caref = getattr(ca, 'caref', None)
        if not caref:
            return

        parent = CA.query.filter_by(refid=caref).first()
        if parent is None:
            if on_missing == 'raise':
                raise ValueError(missing_message)
            return
        ca = parent


__all__ = ['MAX_CHAIN_DEPTH', 'walk_ca_chain']
