import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.jsonfix import loads_object

GOOD = {"findings": {"hypotheses": [{"actor": "attacker", "note": "uses \"quotes\""}],
                     "evidence": [{"snippet": "a = 1\nb = 2"}], "coverage": []}}


def test_valid_json_passes_through():
    assert loads_object(json.dumps(GOOD)) == GOOD
    assert loads_object("[1, 2]") is None
    assert loads_object("") is None


def test_missing_or_extra_closing_brackets_at_the_end():
    text = json.dumps(GOOD)
    assert loads_object(text[:-1]) == GOOD
    assert loads_object(text[:-2]) == GOOD
    assert loads_object(text + "}") == GOOD
    assert loads_object(text + "\n```") == GOOD


def test_bad_escapes_inner_quotes_and_raw_newlines():
    text = '{"a": "it\\\'s here", "b": "say "hi" now", "c": "line one\nline two", "d": "C:\\path"}'
    assert loads_object(text) == {"a": "it's here", "b": 'say "hi" now',
                                  "c": "line one\nline two", "d": "C:\\path"}


def test_a_payload_it_cannot_trust_is_refused():
    text = json.dumps(GOOD)
    assert loads_object(text[: len(text) // 2]) is None
    assert loads_object('{"a": 1}} , "b": "a long tail that would be thrown away silently"}') is None
    assert loads_object('{"coverage":: ') is None
    assert loads_object('{"a": "x" "b" "c" "d" "e" "f" "g" "h" "i" "j" "k" "l" "m" "n"}') is None
