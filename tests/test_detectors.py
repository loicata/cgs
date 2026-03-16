def test_base_detector_circuit_breaker():
    from analyzers.base import BaseDetector, Signal

    class CrashDetector(BaseDetector):
        name = "test_crash"
        def __init__(self):
            super().__init__(type('C', (), {'get': lambda s,k,d=None: d})())
        def _analyze(self, evt):
            raise ValueError("intentional crash")

    d = CrashDetector()
    # Should not raise
    result = d.on_event({"type": "tcp"})
    assert result == []
    assert len(d._crashes) == 1
    # 3 crashes should open circuit
    d.on_event({"type": "tcp"})
    d.on_event({"type": "tcp"})
    assert d._open == True
    assert d.status == "circuit_open"

def test_base_detector_observation_mode():
    from analyzers.base import BaseDetector, Signal

    class TestDetector(BaseDetector):
        name = "test_obs"
        def __init__(self):
            super().__init__(type('C', (), {'get': lambda s,k,d=None: d})())
            self.observe = True
        def _analyze(self, evt):
            return [Signal("test", "test_cat", "Test", "detail", 2, 0.8)]

    d = TestDetector()
    signals = d.on_event({"type": "tcp"})
    assert len(signals) == 1
    assert signals[0].severity == 5  # capped to INFO
    assert signals[0].observed == True

def test_scoring():
    from analyzers.scoring import Scorer
    from analyzers.base import Signal
    cfg = type('C', (), {'get': lambda s,k,d=None: d})()
    scorer = Scorer(cfg)
    sig = Signal("test", "test", "Title", "detail", 2, 0.9, src_ip="1.2.3.4")
    sev, score, should = scorer.score(sig, 2)
    assert isinstance(should, bool)
    assert 0 <= score <= 1
