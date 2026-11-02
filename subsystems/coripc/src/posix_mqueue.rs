//! Priority-ordered POSIX message queue (`MqAttr`, `PosixMessageQueue`, `mq_send`
//! inserting in descending priority `0..32768` with FIFO tie-breaking, `mq_receive`,
//! and asynchronous notification registration `mq_notify`).

use alloc::vec::Vec;

/// Upper bound (exclusive) for POSIX message priority (`MQ_PRIO_MAX = 32768`).
pub const MQ_PRIO_MAX: u32 = 32768;

/// Errors returned by POSIX message queue operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MqError {
    /// Priority exceeds `MQ_PRIO_MAX - 1` (`EINVAL`).
    InvalidPriority,
    /// Message payload exceeds `mq_msgsize` (`EMSGSIZE`).
    MessageTooLarge,
    /// Receive buffer smaller than `mq_msgsize` (`EMSGSIZE`).
    BufferTooSmall,
    /// Queue has reached `mq_maxmsg` (`EAGAIN`).
    QueueFull,
    /// Queue is empty (`EAGAIN`).
    QueueEmpty,
    /// Another process is already registered for `mq_notify` (`EBUSY`).
    NotifyBusy,
}

/// POSIX message queue attributes (`struct mq_attr`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MqAttr {
    /// Flags (`0` or `O_NONBLOCK`).
    pub mq_flags: u32,
    /// Maximum number of messages allowed on the queue.
    pub mq_maxmsg: usize,
    /// Maximum byte size of a single message.
    pub mq_msgsize: usize,
    /// Number of messages currently queued.
    pub mq_curmsgs: usize,
}

/// Asynchronous notification registration (`struct sigevent` equivalent for `mq_notify`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MqNotificationReg {
    pub subscriber_pid: u32,
    pub signo: u32,
    pub sigval_u64: u64,
}

/// Delivered notification event when an empty queue transitions to non-empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveredMqNotification {
    pub target_pid: u32,
    pub signo: u32,
    pub sigval_u64: u64,
}

/// Single queued message inside `PosixMessageQueue`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedMqMessage {
    pub priority: u32,
    pub seq_order: u64,
    pub payload: Vec<u8>,
}

/// Priority-ordered POSIX Message Queue (`mqueue` filesystem inode state).
pub struct PosixMessageQueue {
    attr: MqAttr,
    /// Sorted in descending priority order; equal priorities are ordered in ascending `seq_order` (FIFO).
    messages: Vec<QueuedMqMessage>,
    next_seq: u64,
    notify_reg: Option<MqNotificationReg>,
    last_fired_notification: Option<DeliveredMqNotification>,
}

impl PosixMessageQueue {
    pub fn new(maxmsg: usize, msgsize: usize, flags: u32) -> Self {
        Self {
            attr: MqAttr {
                mq_flags: flags,
                mq_maxmsg: maxmsg.max(1),
                mq_msgsize: msgsize.max(1),
                mq_curmsgs: 0,
            },
            messages: Vec::with_capacity(maxmsg.min(64)),
            next_seq: 1,
            notify_reg: None,
            last_fired_notification: None,
        }
    }

    #[inline]
    pub fn getattr(&self) -> MqAttr {
        self.attr
    }

    #[inline]
    pub fn take_last_notification(&mut self) -> Option<DeliveredMqNotification> {
        self.last_fired_notification.take()
    }

    /// Register or unregister (`reg == None`) single-shot `mq_notify` notification.
    pub fn mq_notify(&mut self, reg: Option<MqNotificationReg>) -> Result<(), MqError> {
        match reg {
            Some(new_reg) => {
                if self.notify_reg.is_some() {
                    return Err(MqError::NotifyBusy);
                }
                self.notify_reg = Some(new_reg);
                Ok(())
            }
            None => {
                self.notify_reg = None;
                Ok(())
            }
        }
    }

    /// Enqueue a message with `priority` in `0..MQ_PRIO_MAX`.
    /// Maintains descending priority order with strict FIFO ordering among equal priorities.
    /// If the queue transitions from empty to non-empty and an `mq_notify` registration is active,
    /// fires the one-shot notification and clears the registration per POSIX semantics.
    pub fn mq_send(&mut self, payload: &[u8], priority: u32) -> Result<(), MqError> {
        if priority >= MQ_PRIO_MAX {
            return Err(MqError::InvalidPriority);
        }
        if payload.len() > self.attr.mq_msgsize {
            return Err(MqError::MessageTooLarge);
        }
        if self.messages.len() >= self.attr.mq_maxmsg {
            return Err(MqError::QueueFull);
        }

        let was_empty = self.messages.is_empty();
        let seq = self.next_seq;
        self.next_seq += 1;

        // Find insertion index: first element with strictly smaller priority (`msg.priority < priority`).
        // Because existing messages with `msg.priority == priority` precede this position,
        // equal-priority messages are naturally kept in FIFO order.
        let insert_idx = self
            .messages
            .iter()
            .position(|m| m.priority < priority)
            .unwrap_or(self.messages.len());

        self.messages.insert(
            insert_idx,
            QueuedMqMessage {
                priority,
                seq_order: seq,
                payload: Vec::from(payload),
            },
        );
        self.attr.mq_curmsgs = self.messages.len();

        if was_empty {
            if let Some(reg) = self.notify_reg.take() {
                self.last_fired_notification = Some(DeliveredMqNotification {
                    target_pid: reg.subscriber_pid,
                    signo: reg.signo,
                    sigval_u64: reg.sigval_u64,
                });
            }
        }
        Ok(())
    }

    /// Remove and return the oldest message of the highest priority `(payload, priority)`.
    pub fn mq_receive(&mut self, recv_buf_cap: usize) -> Result<(Vec<u8>, u32), MqError> {
        if recv_buf_cap < self.attr.mq_msgsize {
            return Err(MqError::BufferTooSmall);
        }
        if self.messages.is_empty() {
            return Err(MqError::QueueEmpty);
        }
        let msg = self.messages.remove(0);
        self.attr.mq_curmsgs = self.messages.len();
        Ok((msg.payload, msg.priority))
    }
}

/// Self-test verifying priority ordering (`0..32768`), FIFO tie-breaking for equal priorities,
/// and one-shot `mq_notify` firing on empty-to-non-empty transition.
pub fn self_test() -> bool {
    let mut mq = PosixMessageQueue::new(8, 64, 0);

    if mq
        .mq_notify(Some(MqNotificationReg {
            subscriber_pid: 777,
            signo: 10, // SIGUSR1
            sigval_u64: 0xDEAD_BEEF,
        }))
        .is_err()
    {
        return false;
    }

    // Second concurrent notify registration must fail with NotifyBusy.
    if mq.mq_notify(Some(MqNotificationReg {
        subscriber_pid: 888,
        signo: 12,
        sigval_u64: 1,
    })) != Err(MqError::NotifyBusy)
    {
        return false;
    }

    // Send 4 messages with priorities: 10 ("low"), 50 ("high-first"), 32767 ("urgent"), 50 ("high-second").
    if mq.mq_send(b"low", 10).is_err()
        || mq.mq_send(b"high-first", 50).is_err()
        || mq.mq_send(b"urgent", 32767).is_err()
        || mq.mq_send(b"high-second", 50).is_err()
    {
        return false;
    }

    // Verify one-shot notification fired on the first message (empty -> non-empty) and cleared registration.
    let fired = match mq.take_last_notification() {
        Some(n) => n,
        None => return false,
    };
    if fired.target_pid != 777 || fired.sigval_u64 != 0xDEAD_BEEF {
        return false;
    }

    // Priority 32768 must be rejected.
    if mq.mq_send(b"bad", MQ_PRIO_MAX) != Err(MqError::InvalidPriority) {
        return false;
    }

    // Receive order must be: ("urgent", 32767), ("high-first", 50), ("high-second", 50), ("low", 10).
    let r1 = mq.mq_receive(64);
    let r2 = mq.mq_receive(64);
    let r3 = mq.mq_receive(64);
    let r4 = mq.mq_receive(64);

    r1 == Ok((Vec::from(&b"urgent"[..]), 32767))
        && r2 == Ok((Vec::from(&b"high-first"[..]), 50))
        && r3 == Ok((Vec::from(&b"high-second"[..]), 50))
        && r4 == Ok((Vec::from(&b"low"[..]), 10))
        && mq.getattr().mq_curmsgs == 0
}
