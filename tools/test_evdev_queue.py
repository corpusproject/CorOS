#!/usr/bin/env python3
"""
Stress test and invariant verification for EvdevClientQueue
"""
import collections
import random
import sys

class InputEvent:
    def __init__(self, time_sec, time_usec, event_type, code, value):
        self.time_sec = time_sec
        self.time_usec = time_usec
        self.event_type = event_type
        self.code = code
        self.value = value

    @staticmethod
    def syn_dropped(sec, usec):
        return InputEvent(sec, usec, 0, 3, 1)

    def __repr__(self):
        return f"Event(type={self.event_type}, code={self.code}, val={self.value})"

class EvdevClientQueue:
    def __init__(self, max_capacity: int):
        self.ring = collections.deque(maxlen=None)
        self.max_capacity = max_capacity
        self.dropped_overflow = False

    def push_event(self, event: InputEvent):
        if self.max_capacity == 0:
            return

        if self.dropped_overflow:
            if self.max_capacity >= 2:
                while len(self.ring) + 2 > self.max_capacity and len(self.ring) > 0:
                    self.ring.popleft()
                self.ring.append(InputEvent.syn_dropped(event.time_sec, event.time_usec))
                self.ring.append(event)
                self.dropped_overflow = False
            else:
                self.ring.clear()
                self.ring.append(event)
                self.dropped_overflow = False
            return

        if len(self.ring) >= self.max_capacity:
            self.dropped_overflow = True
            return

        self.ring.append(event)

    def pop_event(self):
        if self.ring:
            return self.ring.popleft()
        return None

    def len(self):
        return len(self.ring)

    def is_empty(self):
        return len(self.ring) == 0

    def clear(self):
        self.ring.clear()
        self.dropped_overflow = False

    def check_invariants(self, step_name=""):
        assert len(self.ring) <= self.max_capacity, (
            f"INVARIANT VIOLATION at {step_name}: len={len(self.ring)} > max_capacity={self.max_capacity}"
        )

def run_deterministic_tests():
    print("[-] Running deterministic edge case tests...")
    
    # Test 1: Capacity 0
    q0 = EvdevClientQueue(0)
    for i in range(10):
        q0.push_event(InputEvent(0, 0, 1, i, 1))
        q0.check_invariants("cap 0 push")
    assert q0.len() == 0
    assert q0.pop_event() is None

    # Test 2: Capacity 1
    q1 = EvdevClientQueue(1)
    q1.push_event(InputEvent(0, 0, 1, 10, 1))
    q1.check_invariants("cap 1 fill")
    assert q1.len() == 1
    assert not q1.dropped_overflow

    # Overflow cap 1
    q1.push_event(InputEvent(0, 0, 1, 11, 1))
    q1.check_invariants("cap 1 overflow")
    assert q1.len() == 1
    assert q1.dropped_overflow

    # Push again while dropped_overflow is true
    q1.push_event(InputEvent(0, 0, 1, 12, 1))
    q1.check_invariants("cap 1 recovery")
    assert q1.len() == 1
    assert not q1.dropped_overflow
    ev = q1.pop_event()
    assert ev.code == 12, f"Expected 12, got {ev.code}"

    # Test 3: Capacity 2
    q2 = EvdevClientQueue(2)
    q2.push_event(InputEvent(0, 0, 1, 20, 1))
    q2.push_event(InputEvent(0, 0, 1, 21, 1))
    q2.check_invariants("cap 2 fill")
    assert q2.len() == 2

    # Overflow cap 2
    q2.push_event(InputEvent(0, 0, 1, 22, 1))
    q2.check_invariants("cap 2 overflow")
    assert q2.len() == 2
    assert q2.dropped_overflow

    # Push recovery with cap 2: both old events must be dropped to make room for SYN_DROPPED + event
    q2.push_event(InputEvent(0, 0, 1, 23, 1))
    q2.check_invariants("cap 2 recovery")
    assert q2.len() == 2
    assert not q2.dropped_overflow
    syn = q2.pop_event()
    assert syn.event_type == 0 and syn.code == 3
    ev23 = q2.pop_event()
    assert ev23.code == 23

    # Test 4: Capacity 3 (Worker & Challenger scenario)
    q3 = EvdevClientQueue(3)
    q3.push_event(InputEvent(1, 0, 1, 1, 1))
    q3.push_event(InputEvent(1, 1, 1, 2, 1))
    q3.push_event(InputEvent(1, 2, 1, 3, 1))
    q3.check_invariants("cap 3 fill")
    assert q3.len() == 3

    # Overflow
    q3.push_event(InputEvent(1, 3, 1, 4, 1))
    q3.check_invariants("cap 3 overflow")
    assert q3.len() == 3
    assert q3.dropped_overflow

    # Pop 1 -> len 2
    p1 = q3.pop_event()
    q3.check_invariants("cap 3 pop 1")
    assert p1.code == 1
    assert q3.len() == 2
    assert q3.dropped_overflow

    # Push recovery event 5 -> must drop event 2, keep event 3, append SYN_DROPPED + event 5 -> len 3!
    q3.push_event(InputEvent(2, 0, 1, 5, 1))
    q3.check_invariants("cap 3 recovery")
    assert q3.len() == 3
    assert not q3.dropped_overflow
    assert q3.pop_event().code == 3
    syn = q3.pop_event()
    assert syn.event_type == 0 and syn.code == 3
    assert q3.pop_event().code == 5
    assert q3.is_empty()

    # Test 5: Capacity 4 (Challenger 2 exact test)
    q4 = EvdevClientQueue(4)
    for i in range(1, 5):
        q4.push_event(InputEvent(100, i, 2, 0, i))
        q4.check_invariants("cap 4 fill")
    assert q4.len() == 4

    # 5th event -> overflow
    q4.push_event(InputEvent(100, 5, 2, 0, 5))
    q4.check_invariants("cap 4 overflow")
    assert q4.len() == 4
    assert q4.dropped_overflow

    # Pop 1 -> len 3
    q4.pop_event()
    q4.check_invariants("cap 4 pop")
    assert q4.len() == 3

    # Push recovery -> Previously this produced len 5 (violating capacity 4)
    q4.push_event(InputEvent(100, 6, 2, 0, 6))
    q4.check_invariants("cap 4 recovery push")
    assert q4.len() == 4, f"Expected len 4, got {q4.len()}"
    assert not q4.dropped_overflow
    print("[PASS] All deterministic edge case tests passed.")

def run_fuzz_stress_tests(num_iterations=200000):
    print(f"[-] Running {num_iterations} randomized stress operations...")
    random.seed(42)
    capacities = [0, 1, 2, 3, 4, 5, 8, 16, 64]
    
    for cap in capacities:
        q = EvdevClientQueue(cap)
        for i in range(num_iterations // len(capacities)):
            op = random.random()
            if op < 0.65:
                # Push
                sec = random.randint(0, 1000)
                usec = random.randint(0, 1000000)
                typ = random.randint(0, 5)
                code = random.randint(0, 255)
                val = random.randint(-100, 100)
                q.push_event(InputEvent(sec, usec, typ, code, val))
            elif op < 0.95:
                # Pop
                q.pop_event()
            else:
                # Clear
                q.clear()
            
            q.check_invariants(f"cap {cap} iter {i}")

    print(f"[PASS] {num_iterations} stress operations completed without a single invariant violation!")

if __name__ == "__main__":
    run_deterministic_tests()
    run_fuzz_stress_tests()
    print("\nALL EVDEV QUEUE VERIFICATION TESTS PASSED (100% EMPIRICAL CONFIRMATION).")
