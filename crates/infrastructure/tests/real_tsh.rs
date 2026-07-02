//! Live smoke tests against the real `tsh` on this machine. Ignored by default
//! (require a logged-in session + network). Run with:
//!   cargo test -p infrastructure -- --ignored
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::indexing_slicing
)]

use domain::port::{ClusterRepository, NodeRepository};
use infrastructure::platform::locate_tsh;
use infrastructure::process::SystemCommandRunner;
use infrastructure::tsh::{TshClusterRepository, TshNodeRepository};

#[test]
#[ignore = "hits the live Teleport cluster"]
fn lists_real_clusters_and_nodes() {
    let tsh = locate_tsh(None).expect("tsh must be installed");

    let clusters = TshClusterRepository::new(SystemCommandRunner, tsh.clone());
    let topo = clusters.list_clusters().expect("list clusters");
    println!(
        "root={} leaves={} selected={}",
        topo.root().name,
        topo.leaves().count(),
        topo.selected().name
    );
    assert!(!topo.all().is_empty());

    let nodes = TshNodeRepository::new(SystemCommandRunner, tsh);
    let list = nodes
        .list_nodes(topo.selected())
        .expect("list nodes on selected cluster");
    println!("nodes on {} = {}", topo.selected().name, list.len());
    if let Some(n) = list.first() {
        println!("first node: {} [{}]", n.hostname, n.id);
    }
}
