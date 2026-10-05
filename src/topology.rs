//! Cytoscape.js output: `elements` can be passed straight to `cy.add()`.

use crate::model::Inventory;
use serde_json::{Value, json};

pub fn build(inv: &Inventory, cidr: &str, scan: Value) -> Value {
    let subnet_id = format!("net:{cidr}");
    let mut nodes = vec![json!({ "data": { "id": subnet_id, "label": cidr, "type": "subnet" } })];
    let mut edges = Vec::new();

    for host in inv.0.values() {
        let id = format!("host:{}", host.ip);
        let mut data = serde_json::to_value(host).expect("host serializes");
        let obj = data.as_object_mut().unwrap();
        let label = host.hostnames.iter().next().cloned().unwrap_or_else(|| host.ip.to_string());
        let kind = if host.is_gateway {
            "gateway"
        } else if host.is_self {
            "self"
        } else {
            "host"
        };
        obj.insert("id".into(), json!(id));
        obj.insert("label".into(), json!(label));
        obj.insert("type".into(), json!(kind));
        obj.insert("status".into(), json!(if host.online { "online" } else { "offline" }));
        obj.insert("open_ports".into(), json!(host.ports.len()));
        nodes.push(json!({ "data": data }));
        edges.push(json!({ "data": { "id": format!("edge:{}", host.ip), "source": id, "target": subnet_id } }));
    }

    json!({ "scan": scan, "elements": { "nodes": nodes, "edges": edges } })
}
