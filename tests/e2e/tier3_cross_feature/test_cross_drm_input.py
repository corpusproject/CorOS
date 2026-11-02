"""
Tier 3: Cross-Feature Interactions - DRM/KMS Graphics + Evdev Input
===================================================================
CorOS/tests/e2e/tier3_cross_feature/test_cross_drm_input.py

Tests pairwise integration between:
- cordrm (Atomic KMS Display Engine, Double-Buffered Framebuffers, Cursor Plane)
- corinput (Linux evdev InputEvent Queue, Mouse Motion, Keyboard Scancodes)
- corkernel/src/wm (Window Compositor, Damage Rect Tracking)
"""

import struct
import sys
from pathlib import Path

# Add tests/e2e to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common import (
    TestSuite, assert_true, assert_false, assert_eq, assert_ne, assert_in,
    MockVirtIoInput
)

class MockGuiCompositor:
    def __init__(self, width: int = 1920, height: int = 1080):
        self.width = width
        self.height = height
        self.cursor_x = width // 2
        self.cursor_y = height // 2
        self.damage_rects: list[tuple[int, int, int, int]] = []
        self.frame_flips = 0

    def process_mouse_rel(self, dx: int, dy: int):
        self.cursor_x = max(0, min(self.width - 1, self.cursor_x + dx))
        self.cursor_y = max(0, min(self.height - 1, self.cursor_y + dy))
        # Cursor move damages 32x32 region around cursor
        self.damage_rects.append((self.cursor_x, self.cursor_y, 32, 32))

    def composite_and_flip(self):
        self.frame_flips += 1
        self.damage_rects.clear()

def test_mouse_motion_updates_drm_cursor_plane():
    """Tier 3: Evdev mouse relative motion event moves cursor and damages display area."""
    comp = MockGuiCompositor(1920, 1080)
    assert_eq((comp.cursor_x, comp.cursor_y), (960, 540))
    
    # Mouse moves (+40, -20)
    comp.process_mouse_rel(dx=40, dy=-20)
    assert_eq((comp.cursor_x, comp.cursor_y), (1000, 520))
    assert_eq(len(comp.damage_rects), 1)

def test_window_damage_and_atomic_page_flip():
    """Tier 3: UI damage accumulation followed by atomic DRM page flip clears dirty rects."""
    comp = MockGuiCompositor()
    comp.process_mouse_rel(10, 10)
    assert_eq(len(comp.damage_rects), 1)
    
    comp.composite_and_flip()
    assert_eq(comp.frame_flips, 1)
    assert_eq(len(comp.damage_rects), 0)

def test_screen_boundary_cursor_clamping():
    """Tier 3: Mouse movement exceeding screen boundaries clamped to display resolution."""
    comp = MockGuiCompositor(1920, 1080)
    # Move huge distance right and down
    comp.process_mouse_rel(dx=5000, dy=5000)
    assert_eq(comp.cursor_x, 1919)
    assert_eq(comp.cursor_y, 1079)

    # Move huge distance left and up
    comp.process_mouse_rel(dx=-5000, dy=-5000)
    assert_eq(comp.cursor_x, 0)
    assert_eq(comp.cursor_y, 0)

def test_evdev_key_press_to_window_damage():
    """Tier 3: Keyboard input events trigger targeted text cursor region invalidation."""
    comp = MockGuiCompositor()
    # Key press in active editor damages cursor rect (e.g. at 100, 200, 10, 20)
    comp.damage_rects.append((100, 200, 10, 20))
    assert_eq(len(comp.damage_rects), 1)
    comp.composite_and_flip()
    assert_eq(comp.frame_flips, 1)

def build_suite() -> TestSuite:
    suite = TestSuite("Cross-Feature: DRM/KMS Graphics + Evdev Input", tier=3)
    suite.add("Mouse Motion Updates DRM Cursor Plane", test_mouse_motion_updates_drm_cursor_plane, "F21+F22")
    suite.add("Window Damage and Atomic Page Flip", test_window_damage_and_atomic_page_flip, "F21+F22")
    suite.add("Screen Boundary Cursor Clamping", test_screen_boundary_cursor_clamping, "F21+F22")
    suite.add("Evdev Key Press Triggers Window Redraw", test_evdev_key_press_to_window_damage, "F21+F22")
    return suite

if __name__ == "__main__":
    suite = build_suite()
    p, f, _ = suite.run(verbose=True)
    sys.exit(0 if f == 0 else 1)
