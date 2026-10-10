import re
import time
import traceback
from contextlib import contextmanager


def log_line(message):
    return ' '.join(re.sub(r'[^a-z0-9\s]', ' ', str(message).lower()).split())


@contextmanager
def watch_run(directory):
    started = time.monotonic()
    with (directory / "progress.log").open("w", encoding="utf-8") as log:
        def stage(message):
            line = f"{int(time.monotonic() - started)}s {log_line(message)}"
            print(line, file=log, flush=True)

        try:
            yield stage
        except BaseException:
            stage(traceback.format_exc().splitlines()[-1])
            raise
