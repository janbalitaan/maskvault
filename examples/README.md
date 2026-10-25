# Examples

Runnable files, in the order worth reading them. Each one is self-contained
and prints what it did.

```bash
python examples/01_round_trip.py
```

| | |
| --- | --- |
| [`01_round_trip.py`](01_round_trip.py) | The whole library: anonymize, send, restore. |
| [`02_check_a_reply.py`](02_check_a_reply.py) | Why `leaked()` is not optional — five ways a model breaks a token. |
| [`03_what_would_be_replaced.py`](03_what_would_be_replaced.py) | Building a whitelist from real text rather than guesses. |
| [`04_structured_data.py`](04_structured_data.py) | A request body rather than a sentence. |
| [`05_a_multi_turn_chat.py`](05_a_multi_turn_chat.py) | One vault across turns, so one person keeps one token. |
| [`06_a_store.py`](06_a_store.py) | Restoring on a different node, with encryption. |
| [`07_extending.py`](07_extending.py) | Replacing a pattern, bound or word list without waiting for a release. |

Only the last one needs anything installed:

```bash
pip install 'maskvault[encryption]'
```

Every file is run by the test suite, so an example that stops working fails
CI rather than sitting here misleading someone.

For the reasoning behind any of it, see [`../docs/`](../docs/README.md).
