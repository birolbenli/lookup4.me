"""English-first i18n via Flask-Babel (gettext)."""

from __future__ import annotations

from flask import request
from flask_babel import Babel, get_locale, gettext

from js_messages import JS_MESSAGES

SUPPORTED = ("en", "tr")
DEFAULT = "en"
COOKIE = "lang"

babel = Babel()


def select_locale() -> str:
    explicit = (request.args.get("lang") or "").lower()
    if explicit in SUPPORTED:
        return explicit
    cookie = (request.cookies.get(COOKIE) or "").lower()
    if cookie in SUPPORTED:
        return cookie
    best = request.accept_languages.best_match(SUPPORTED)
    return best or DEFAULT


def init_babel(app) -> Babel:
    app.config.setdefault("BABEL_DEFAULT_LOCALE", DEFAULT)
    app.config.setdefault("BABEL_TRANSLATION_DIRECTORIES", "translations")
    babel.init_app(app, locale_selector=select_locale)
    return babel


def get_lang() -> str:
    try:
        loc = get_locale()
        if loc is None:
            return DEFAULT
        return str(loc)
    except RuntimeError:
        return DEFAULT


def _(text: str, **kwargs) -> str:
    """Translate English msgid; optional str.format kwargs ({name})."""
    out = gettext(text)
    if kwargs:
        try:
            out = out.format(**kwargs)
        except (KeyError, ValueError):
            pass
    return out


def localize_tools(tools: list[dict]) -> list[dict]:
    localized = []
    for tool in tools:
        item = dict(tool)
        if item.get("name"):
            item["name"] = gettext(item["name"])
        if item.get("desc"):
            item["desc"] = gettext(item["desc"])
        if item.get("placeholder"):
            item["placeholder"] = gettext(item["placeholder"])
        localized.append(item)
    return localized


def js_bundle() -> dict[str, str]:
    """English msgid → current-locale string for window.__I18N__."""
    return {msg: gettext(msg) for msg in JS_MESSAGES}
