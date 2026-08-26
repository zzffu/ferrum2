use super::*;

#[test]
fn tun_udp_authorizes_only_successful_send_or_dns_answer_and_adf_ignores_port() {
    let first: SocketAddr = "192.0.2.8:53".parse().unwrap();
    let second_port: SocketAddr = "192.0.2.8:5353".parse().unwrap();
    let authorized = std::cell::RefCell::new(Vec::new());
    assert!(!commit_peer_after_success(Err::<usize, ()>(()), 4, || {
        authorized.borrow_mut().push(first.ip());
        true
    },));
    assert!(!commit_peer_after_success(Ok::<usize, ()>(3), 4, || {
        authorized.borrow_mut().push(first.ip());
        true
    },));
    assert!(
        authorized.borrow().is_empty(),
        "failed sends authorize nobody"
    );

    assert!(commit_peer_after_success(Ok::<usize, ()>(4), 4, || {
        authorized.borrow_mut().push(first.ip());
        true
    },));
    assert!(commit_peer_after_success(Ok::<usize, ()>(4), 4, || {
        authorized.borrow_mut().push(second_port.ip());
        true
    },));
    assert_eq!(
        *authorized.borrow(),
        [first.ip(), first.ip()],
        "ADF authorization is keyed by IP rather than UDP port"
    );

    let ordinary_dns: SocketAddr = "198.51.100.53:53".parse().unwrap();
    let missing = authorize_dns_peer_after_answer(None::<Vec<u8>>, ordinary_dns, |peer| {
        authorized.borrow_mut().push(peer);
        true
    });
    assert!(missing.is_none());
    assert_eq!(
        authorized.borrow().len(),
        2,
        "missing DNS answers authorize nobody"
    );

    let answer = authorize_dns_peer_after_answer(Some(vec![1, 2, 3]), ordinary_dns, |peer| {
        authorized.borrow_mut().push(peer);
        true
    });
    assert_eq!(answer.as_deref(), Some([1, 2, 3].as_slice()));
    assert_eq!(authorized.borrow().last(), Some(&ordinary_dns.ip()));
    assert!(
        authorize_dns_peer_after_answer(Some(()), ordinary_dns, |_| false).is_none(),
        "DNS response survived a rejected ADF reservation"
    );

    let synthetic_dns: SocketAddr = "198.18.0.1:53".parse().unwrap();
    assert!(
        authorize_dns_peer_after_answer(Some(()), synthetic_dns, |peer| {
            authorized.borrow_mut().push(peer);
            true
        })
        .is_some()
    );
    assert_eq!(authorized.borrow().last(), Some(&synthetic_dns.ip()));
}
