import re
from typing import Iterator, Union, TextIO, Optional, List, Set

from irrd.conf import PASSWORD_HASH_DUMMY_VALUE
from irrd.rpsl.passwords import PASSWORD_HASHERS_ALL

re_remove_passwords = re.compile(r'(%s)[^\n]+' % '|'.join(PASSWORD_HASHERS_ALL.keys()), flags=re.IGNORECASE)
re_remove_last_modified = re.compile(r'^last-modified: [^\n]+\n', flags=re.MULTILINE)


def remove_auth_hashes(input: Optional[str]):
    if not input:
        return input
    if not isinstance(input, str):
        raise ValueError('Auth hash removal only supported for strings')
    # If there are no hashes, skip the RE for performance.
    input_lower = input.lower()
    if not any([pw_hash.lower() in input_lower for pw_hash in PASSWORD_HASHERS_ALL.keys()]):
        return input
    return re_remove_passwords.sub(r'\1 %s  # Filtered for security' % PASSWORD_HASH_DUMMY_VALUE, input)


def remove_last_modified(rpsl_text: str):
    """
    Remove all last-modified attributes from an RPSL text with less overhead
    than using the full RPSL parser.
    Assumes the last-modified value is single line. This is a safe assumption
    when the input is guaranteed to have been generated by IRRd.
    """
    return re_remove_last_modified.sub('', rpsl_text)


def splitline_unicodesafe(input: str) -> Iterator[str]:
    """
    Split an input string by newlines, and return an iterator of the lines.

    This is a replacement for Python's built-in splitlines, which also splits
    on characters such as unicode line separator (U+2028). In RPSL, that should
    not be considered a line separator.
    """
    if not input:
        return
    for line in input.strip('\n').split('\n'):
        yield line.strip('\r')


def split_paragraphs_rpsl(input: Union[str, TextIO], strip_comments=True) -> Iterator[str]:
    """
    Split an input into paragraphs, and return an iterator of the paragraphs.

    A paragraph is a block of text, separated by at least one empty line.
    Note that a line with other whitespace, e.g. a space, is not considered
    empty.

    If strip_comments=True, any line starting with % or # is entirely ignored,
    both within a paragraph and between paragraphs.
    """
    current_paragraph = ''
    if isinstance(input, str):
        generator = splitline_unicodesafe(input)
    else:
        generator = input

    for line in generator:
        line = line.strip('\r\n')
        if strip_comments and line.startswith('%') or line.startswith('#'):
            continue
        if line:
            current_paragraph += line + '\n'
        if not line:
            if current_paragraph:
                yield current_paragraph
            current_paragraph = ''

    if current_paragraph.strip():
        yield current_paragraph


def snake_to_camel_case(snake: Union[Set[str], List[str], str]):
    """
    Convert a snake case string to camel case, with lowercase first
    letter. Can also accept a list or set of strings.
    """
    def _str_to_camel_case(snake_str: str):
        components = snake_str.replace('_', '-').split('-')
        return components[0] + ''.join(x.title() for x in components[1:])

    if isinstance(snake, (set, list)):
        return [_str_to_camel_case(s) for s in snake]
    return _str_to_camel_case(snake)


# Turn "IP('193.0.1.1/21') has invalid prefix length (21)" into "invalid prefix length (21)"
re_clean_ip_error = re.compile(r"IP\('[A-F0-9:./]+'\) has ", re.IGNORECASE)


def clean_ip_value_error(value_error):
    return re.sub(re_clean_ip_error, '', str(value_error))
