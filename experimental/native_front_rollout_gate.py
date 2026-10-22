"""New native deployments are frozen until admission control is implemented.

This does not pause, stop or inspect any already committed service. A future
implementation must replace this gate using an actual held/pending/overlap
fixture, not a configuration flag or a fabricated receipt.
"""


def require_rollout_admission():
    raise RuntimeError('ROLLOUT_FROZEN_NATIVE_CONNECTION_ADMISSION_NOT_IMPLEMENTED')
