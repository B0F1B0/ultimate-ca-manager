"""
Pagination Helper
Simple pagination for SQLAlchemy queries
"""

import math
from datetime import datetime
from flask import request


def paginate(query, page=1, per_page=20):
    """
    Paginate SQLAlchemy query
    
    Args:
        query: SQLAlchemy query object
        page: Page number (1-indexed)
        per_page: Items per page
    
    Returns:
        dict: {items, meta}
    """
    if page < 1:
        page = 1
    if per_page < 1:
        per_page = 20
    if per_page > 100:
        per_page = 100
    
    total = query.count()
    total_pages = math.ceil(total / per_page) if total > 0 else 0
    
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    
    return {
        'items': items,
        'meta': {
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': total_pages,
            'has_next': page < total_pages,
            'has_prev': page > 1
        }
    }


def parse_request_pagination(default_per_page=25, max_per_page=100):
    """
    Parse pagination parameters from Flask request args.

    Uses the Flask request context directly (no parameter needed).

    Returns:
        tuple: (page, per_page) with defaults and bounds applied
    """
    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(max(1, request.args.get('per_page', default_per_page, type=int)), max_per_page)
    return page, per_page


def parse_request_limit(default_limit, max_limit, arg='limit'):
    """Row count asked for by the client, floored at 1 and capped at *max_limit*.

    The listings that page use ``per_page`` and go through
    :func:`parse_request_pagination`. A second family of routes hands the
    client's number straight to ``.limit()`` instead, and those had the
    unbounded-page-size bug the listings were fixed for, one layer down:

    * with no ceiling, ``?limit=1000000`` loads and serialises the whole
      table -- the dashboard widgets did this from an ordinary account;
    * with no floor, ``?limit=-1`` reaches the query as ``LIMIT -1``, which
      SQLite reads as *no limit* and PostgreSQL refuses outright, so the same
      request returned the whole table on one backend and a 500 on the other.

    A value that is not a number is not a refusal either: it falls back to
    *default_limit*, which is what ``type=int`` already did for the page size.
    """
    raw = request.args.get(arg, default_limit)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default_limit
    return min(max(1, value), max_limit)


def parse_date_filter(from_arg='date_from', to_arg='date_to'):
    """
    Parse ISO 8601 date range parameters from Flask request args.

    Args:
        from_arg: Query param name for the start date (default: 'date_from')
        to_arg: Query param name for the end date (default: 'date_to')

    Returns:
        tuple: (date_from, date_to) as datetime objects or None if not provided/invalid
    """
    date_from = None
    date_to = None
    if request.args.get(from_arg):
        try:
            date_from = datetime.fromisoformat(request.args.get(from_arg).replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            pass
    if request.args.get(to_arg):
        try:
            date_to = datetime.fromisoformat(request.args.get(to_arg).replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            pass
    return date_from, date_to
