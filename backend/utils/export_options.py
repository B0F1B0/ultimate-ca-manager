"""Strict parsers for boolean certificate-export options."""


def json_boolean(data, name, default=False):
    """Return a JSON boolean without treating non-empty strings as true."""
    if name not in data:
        return default
    value = data[name]
    if not isinstance(value, bool):
        raise ValueError(f'{name} must be a boolean')
    return value


def query_boolean(args, name, default=False):
    """Parse an HTTP query boolean and reject ambiguous values."""
    value = args.get(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized == 'true':
        return True
    if normalized == 'false':
        return False
    raise ValueError(f'{name} must be true or false')
