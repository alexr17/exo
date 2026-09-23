use super::*;

#[test]
fn shared_network_policy_works_without_firecracker() -> Result<()> {
    for (networking, permitted) in [
        (SandboxNetworkPolicy::Unrestricted, true),
        (
            SandboxNetworkPolicy::Limited {
                allowed_hosts: vec!["api.test".into()],
            },
            true,
        ),
        (
            SandboxNetworkPolicy::Limited {
                allowed_hosts: vec![],
            },
            false,
        ),
        (SandboxNetworkPolicy::Disabled, false),
    ] {
        let state = EgressEngine::new(
            EgressIdentity {
                sandbox_id: "request-test".into(),
                scope: None,
            },
            networking.into(),
            None,
        );
        let request = Request::builder()
            .uri("/a/../v1?query=1")
            .header(HOST, "api.test")
            .body(())?;
        let destination = state.and_then(|state| state.destination(&request, Some("api.test")));
        assert_eq!(destination.is_ok(), permitted);
        if let Ok((destination, _)) = destination {
            assert_eq!(destination.path, "/v1?query=1");
        }
    }
    Ok(())
}
