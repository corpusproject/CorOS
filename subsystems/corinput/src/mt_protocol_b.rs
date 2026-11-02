//! Linux Multi-Touch Protocol Type B stateful slot tracker & contact lifecycle manager.

use alloc::vec::Vec;

/// Individual Multi-Touch contact slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct MtSlot {
    pub tracking_id: i32, // -1 if inactive
    pub x: i32,
    pub y: i32,
    pub pressure: i32,
    pub touch_major: i32,
}

impl MtSlot {
    #[inline]
    pub fn is_active(&self) -> bool {
        self.tracking_id >= 0
    }
}

/// Linux MT Protocol Type B slot table.
pub struct MtSlotTable {
    pub slots: Vec<MtSlot>,
    pub current_slot: usize,
    pub next_tracking_id: i32,
}

impl MtSlotTable {
    pub fn new(num_slots: usize) -> Self {
        Self {
            slots: alloc::vec![MtSlot { tracking_id: -1, ..Default::default() }; num_slots],
            current_slot: 0,
            next_tracking_id: 1,
        }
    }

    pub fn select_slot(&mut self, slot_idx: usize) {
        if slot_idx < self.slots.len() {
            self.current_slot = slot_idx;
        }
    }

    pub fn set_contact_down(&mut self, x: i32, y: i32, pressure: i32) {
        let tid = self.next_tracking_id;
        self.next_tracking_id += 1;
        let slot = &mut self.slots[self.current_slot];
        slot.tracking_id = tid;
        slot.x = x;
        slot.y = y;
        slot.pressure = pressure;
    }

    pub fn set_contact_move(&mut self, x: i32, y: i32, pressure: i32) {
        let slot = &mut self.slots[self.current_slot];
        if slot.is_active() {
            slot.x = x;
            slot.y = y;
            slot.pressure = pressure;
        }
    }

    pub fn set_contact_up(&mut self) {
        let slot = &mut self.slots[self.current_slot];
        slot.tracking_id = -1;
    }

    pub fn count_active_contacts(&self) -> usize {
        self.slots.iter().filter(|s| s.is_active()).count()
    }

    pub fn get_slot(&self, slot_idx: usize) -> Option<&MtSlot> {
        self.slots.get(slot_idx)
    }

    pub fn current_slot_info(&self) -> Option<&MtSlot> {
        self.slots.get(self.current_slot)
    }

    pub fn active_tracking_ids(&self) -> Vec<i32> {
        self.slots
            .iter()
            .filter(|s| s.is_active())
            .map(|s| s.tracking_id)
            .collect()
    }

    pub fn find_free_slot(&self) -> Option<usize> {
        self.slots.iter().position(|s| !s.is_active())
    }
}
