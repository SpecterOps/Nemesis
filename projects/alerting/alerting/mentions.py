"""Stop collected data (file names, project names, finding text) from pinging people in chat alerts.

Alert text carries strings taken from collected files. In Slack, `<!channel>`, `<!here>`, `<@U123>` and
`<!subteam^ID>` notify people; in Discord, `@everyone`, `@here`, `<@123>` and `<@&role>` do. A zero-width
space after the `<` or `@` leaves the text readable but no longer a mention. Our own message links
(`<https://...|View Finding>`) never start with `!`, `@` or `#`, so they keep working.
"""

import re

_ZWSP = "\u200b"  # zero-width space
# Slack/Discord bracket mentions: <!channel>, <!here>, <!subteam^ID>, <@U123>, <@&role>, <#C123>
_BRACKET_MENTION = re.compile(r"<(?=[!@#])")
# Plain-text group mentions that some services (Discord, Mattermost, Slack with link_names) expand
_PLAIN_MENTION = re.compile(r"@(?=(?:everyone|here|channel|all)\b)", re.IGNORECASE)


def neutralize_mentions(text: str | None) -> str | None:
    """Return text with chat mentions defused; None stays None."""
    if not text:
        return text
    text = _BRACKET_MENTION.sub("<" + _ZWSP, text)
    return _PLAIN_MENTION.sub("@" + _ZWSP, text)
