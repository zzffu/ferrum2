use std::cell::RefCell;
use std::rc::Rc;

use super::*;
use crate::CreateError;
use crate::windows::core::managed::{
    CleanupOperations, cleanup_transaction, finish_setup_transaction,
};

#[derive(Clone, Debug, Eq, PartialEq)]
enum Event {
    Subscribe(usize),
    Snapshot,
    Commit,
    Cancel(usize),
    ContextDropped,
    EndSession,
    CloseAdapter,
}

type Events = Rc<RefCell<Vec<Event>>>;

struct Context(Events);

impl Drop for Context {
    fn drop(&mut self) {
        self.0.borrow_mut().push(Event::ContextDropped);
    }
}

struct Notifications {
    handles: Vec<usize>,
    context: Option<Context>,
    failed_handle: Option<usize>,
    events: Events,
}

impl Notifications {
    fn subscribe(events: &Events, failed_handle: Option<usize>) -> Result<Self, Error> {
        let (handles, context) = subscribe_notification_sequence(
            Context(Rc::clone(events)),
            |ordinal| {
                events.borrow_mut().push(Event::Subscribe(ordinal));
                Ok(ordinal)
            },
            |_| panic!("successful subscriptions must remain owned"),
        )?;
        Ok(Self {
            handles,
            context: Some(context),
            failed_handle,
            events: Rc::clone(events),
        })
    }

    fn cancel_all(&mut self) -> bool {
        cancel_notification_handles(&mut self.handles, &mut self.context, |handle| {
            self.events.borrow_mut().push(Event::Cancel(*handle));
            self.failed_handle != Some(*handle)
        })
    }
}

impl Drop for Notifications {
    fn drop(&mut self) {
        let _ = close_notification_handles(&mut self.handles, &mut self.context, |handle| {
            self.events.borrow_mut().push(Event::Cancel(*handle));
            self.failed_handle != Some(*handle)
        });
    }
}

/// Injects only platform operations; production staging, cancellation and the
/// complete setup/cleanup transaction functions remain under test.
struct Operations {
    pending: Option<Notifications>,
    committed: Option<Notifications>,
    close_failed: bool,
    events: Events,
}

impl CleanupOperations for Operations {
    fn session_is_idle(&mut self) -> bool {
        true
    }

    fn cancel_notifications(&mut self) -> Option<bool> {
        match cancel_notification_stages(
            NotificationStages {
                pending: self.pending.as_mut(),
                committed: self.committed.as_mut(),
            },
            Notifications::cancel_all,
        ) {
            NotificationCleanup::Absent => None,
            NotificationCleanup::Cleaned => Some(false),
            NotificationCleanup::Failed => Some(true),
        }
    }

    fn end_session(&mut self) -> Option<bool> {
        self.events.borrow_mut().push(Event::EndSession);
        Some(false)
    }
    fn delete_last_address(&mut self) -> Option<bool> {
        None
    }
    fn restore_ipv6_mtu(&mut self) -> Option<bool> {
        None
    }
    fn restore_ipv4_mtu(&mut self) -> Option<bool> {
        None
    }
    fn restore_ipv4_link_local(&mut self) -> Option<bool> {
        None
    }
    fn close_adapter(&mut self) -> Option<bool> {
        self.events.borrow_mut().push(Event::CloseAdapter);
        Some(self.close_failed)
    }
}

#[derive(Clone, Copy)]
enum FailureStage {
    Snapshot,
    AfterCommit,
}

#[test]
fn staged_notifications_are_rollback_owned_before_snapshot_and_after_commit() {
    for stage in [FailureStage::Snapshot, FailureStage::AfterCommit] {
        for setup_error in [Error, Error::cleanup()] {
            for failed_handle in [None, Some(1)] {
                for close_failed in [false, true] {
                    for strict_route_failed in [false, true] {
                        let events = Events::default();
                        let mut operations = Operations {
                            pending: None,
                            committed: None,
                            close_failed,
                            events: Rc::clone(&events),
                        };
                        let prepared = prepare_notification_owner(
                            &mut operations.pending,
                            || Notifications::subscribe(&events, failed_handle),
                            |notifications| {
                                assert_eq!(notifications.handles, [0, 1, 2]);
                                assert!(notifications.context.is_some());
                                events.borrow_mut().push(Event::Snapshot);
                                match stage {
                                    FailureStage::Snapshot => Err(setup_error),
                                    FailureStage::AfterCommit => Ok(7_u64),
                                }
                            },
                        );
                        let setup = match prepared {
                            Ok((notifications, generation)) => {
                                assert_eq!(generation, 7);
                                assert!(operations.pending.is_none());
                                operations.committed = Some(notifications);
                                events.borrow_mut().push(Event::Commit);
                                Err(setup_error)
                            }
                            Err(error) => {
                                assert!(operations.pending.is_some());
                                assert!(operations.committed.is_none());
                                Err(error)
                            }
                        };
                        let result = finish_setup_transaction(setup, strict_route_failed, || {
                            cleanup_transaction(&mut operations)
                        });
                        let cleanup_failed = setup_error.kind() == crate::ErrorKind::Cleanup
                            || failed_handle.is_some()
                            || close_failed;
                        let expected = if strict_route_failed {
                            CreateError::strict_route_install(cleanup_failed)
                        } else if cleanup_failed {
                            CreateError::cleanup()
                        } else {
                            CreateError::operation()
                        };
                        assert_eq!(result, Err(expected));
                        let mut expected_events = vec![
                            Event::Subscribe(0),
                            Event::Subscribe(1),
                            Event::Subscribe(2),
                            Event::Snapshot,
                        ];
                        if matches!(stage, FailureStage::AfterCommit) {
                            expected_events.push(Event::Commit);
                        }
                        expected_events.extend([
                            Event::Cancel(2),
                            Event::Cancel(1),
                            Event::Cancel(0),
                        ]);
                        if failed_handle.is_none() {
                            expected_events.push(Event::ContextDropped);
                        }
                        expected_events.extend([Event::EndSession, Event::CloseAdapter]);
                        assert_eq!(*events.borrow(), expected_events);
                        drop(operations);
                        if failed_handle.is_some() {
                            expected_events.push(Event::Cancel(1));
                        }
                        assert_eq!(*events.borrow(), expected_events);
                    }
                }
            }
        }
    }
}

#[test]
fn pending_cancellation_failure_does_not_skip_committed_notifications() {
    let events = Events::default();
    let mut pending = Notifications::subscribe(&events, Some(1)).unwrap();
    let mut committed = Notifications::subscribe(&events, None).unwrap();
    events.borrow_mut().clear();
    assert_eq!(
        cancel_notification_stages(
            NotificationStages {
                pending: Some(&mut pending),
                committed: Some(&mut committed)
            },
            Notifications::cancel_all,
        ),
        NotificationCleanup::Failed,
    );
    assert_eq!(
        *events.borrow(),
        [
            Event::Cancel(2),
            Event::Cancel(1),
            Event::Cancel(0),
            Event::Cancel(2),
            Event::Cancel(1),
            Event::Cancel(0),
            Event::ContextDropped,
        ]
    );
}

#[test]
fn occupied_pending_slot_is_not_replaced_or_resubscribed() {
    let events = Events::default();
    let mut pending = Some(Notifications::subscribe(&events, None).unwrap());
    assert_eq!(
        prepare_notification_owner(
            &mut pending,
            || panic!("retained notifications must not be replaced"),
            |_| Ok(())
        )
        .err(),
        Some(Error),
    );
    assert_eq!(pending.as_ref().unwrap().handles, [0, 1, 2]);
    drop(pending);
    assert_eq!(
        *events.borrow(),
        [
            Event::Subscribe(0),
            Event::Subscribe(1),
            Event::Subscribe(2),
            Event::Cancel(2),
            Event::Cancel(1),
            Event::Cancel(0),
            Event::ContextDropped,
        ]
    );
}
