use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use ferrum2_runtime::OwnerSnapshot;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;
use crate::run::test_support::*;

mod lifecycle;
mod readiness;
mod root_routing;
mod udp_composition;
