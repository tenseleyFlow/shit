// SPDX-License-Identifier: AGPL-3.0-or-later

//! `tracing_subscriber::Layer` that pushes each event as a JSON line
//! into a [`shit_proto::crash::TracingRing`] (DR-68).
//!
//! Plumbing: every `tracing::*!` call passes through every registered
//! layer. This one formats the event into one JSON line — matching
//! the daemon-log JSON shape closely enough that a reader can grep
//! the crash file's tail the same way they grep the daemon's
//! structured log — and pushes the line. The ring is bounded
//! (`TracingRing` enforces capacity); push at the cap drops the
//! oldest.
//!
//! ## Format
//!
//! ```jsonl
//! {"ts":1700000000,"level":"INFO","target":"shitd::server","message":"hook frame decoded","fields":{"component":"daemon","subsystem":"ipc",...}}
//! ```
//!
//! `ts` is unix-seconds (no fractional). The daemon's JSON-file
//! layer renders RFC3339 — we use seconds in the ring because the
//! crash-log writer prints this verbatim and human readers prefer
//! the compact form.
//!
//! ## Why not delegate to tracing-subscriber's JSON formatter
//!
//! `tracing_subscriber::fmt::layer().json()` writes to a
//! `MakeWriter`, not to a borrowable target. Wiring a writer that
//! captures into the ring would require shadowing the writer trait
//! plus interior mutability. The custom Visit impl below is ~60
//! lines and avoids that indirection.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};
use shit_proto::crash::TracingRing;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

/// Layer that serialises every event into a single JSON line and
/// calls [`TracingRing::push`].
pub struct RingLayer {
    ring: Arc<TracingRing>,
}

impl RingLayer {
    pub fn new(ring: Arc<TracingRing>) -> Self {
        Self { ring }
    }
}

impl<S> Layer<S> for RingLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut fields = JsonFieldVisitor::default();
        event.record(&mut fields);
        let message = fields.message.take().unwrap_or_default();

        // Flatten the parent-span's recorded fields into the
        // event's `fields` so `component=daemon` and friends carry
        // through. The JSON-file layer does the same via
        // `with_current_span(true)`.
        if let Some(span) = ctx.event_span(event) {
            let mut cursor = Some(span);
            while let Some(s) = cursor {
                if let Some(ext) = s.extensions().get::<SpanFields>() {
                    for (k, v) in &ext.0 {
                        fields.fields.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }
                cursor = s.parent();
            }
        }

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let record = serde_json::json!({
            "ts": ts,
            "level": meta.level().as_str(),
            "target": meta.target(),
            "message": message,
            "fields": Value::Object(fields.fields),
        });
        self.ring.push(record.to_string());
    }

    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::Id,
        ctx: Context<'_, S>,
    ) {
        // Capture the span's recorded fields once at creation. This
        // lets on_event flatten them without a per-event re-walk.
        let mut visitor = JsonFieldVisitor::default();
        attrs.record(&mut visitor);
        let mut pairs = Vec::with_capacity(visitor.fields.len());
        for (k, v) in visitor.fields {
            pairs.push((k, v));
        }
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(SpanFields(pairs));
        }
    }
}

/// Field bundle stashed per-span via `extensions_mut`.
struct SpanFields(Vec<(String, Value)>);

/// Visitor that builds a JSON object from a `tracing` event's fields.
#[derive(Default)]
struct JsonFieldVisitor {
    fields: Map<String, Value>,
    /// `message` is special — every `tracing::info!("...")` form
    /// records it as a field named "message"; we lift it to a
    /// top-level JSON key.
    message: Option<String>,
}

impl Visit for JsonFieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields
                .insert(field.name().to_string(), Value::String(value.to_string()));
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), Value::Bool(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .insert(field.name().to_string(), Value::Number(value.into()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .insert(field.name().to_string(), Value::Number(value.into()));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        if let Some(n) = serde_json::Number::from_f64(value) {
            self.fields.insert(field.name().to_string(), Value::Number(n));
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let rendered = format!("{value:?}");
        if field.name() == "message" {
            self.message = Some(rendered);
        } else {
            self.fields
                .insert(field.name().to_string(), Value::String(rendered));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::Level;
    use tracing_subscriber::layer::SubscriberExt;

    /// Build a one-shot subscriber that pushes events into the ring.
    /// Returns a guard that — when dropped — drops the default
    /// subscriber. The ring is the inspection point.
    fn with_ring<F: FnOnce()>(ring: Arc<TracingRing>, f: F) {
        let layer = RingLayer::new(ring);
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        f();
    }

    #[test]
    fn event_lands_in_ring_as_json() {
        let ring = Arc::new(TracingRing::new(8));
        with_ring(Arc::clone(&ring), || {
            tracing::info!(component = "test", "hello world");
        });
        let snap = ring.snapshot();
        assert_eq!(snap.len(), 1);
        let v: Value = serde_json::from_str(&snap[0]).expect("ring line is JSON");
        assert_eq!(v["level"], "INFO");
        assert_eq!(v["message"], "hello world");
        assert_eq!(v["fields"]["component"], "test");
    }

    #[test]
    fn span_fields_propagate_to_child_events() {
        let ring = Arc::new(TracingRing::new(8));
        with_ring(Arc::clone(&ring), || {
            let span = tracing::info_span!("root", component = "daemon");
            let _g = span.enter();
            tracing::info!(seq = 42u64, "inside span");
        });
        let snap = ring.snapshot();
        // Find the actual event (the span itself may also generate
        // a creation entry depending on the subscriber config).
        let event_line = snap
            .iter()
            .find(|l| l.contains("inside span"))
            .expect("event line in ring");
        let v: Value = serde_json::from_str(event_line).unwrap();
        // The component field from the parent span MUST flatten in.
        assert_eq!(v["fields"]["component"], "daemon");
        assert_eq!(v["fields"]["seq"], 42);
    }

    #[test]
    fn level_serialises_correctly_for_all_levels() {
        let ring = Arc::new(TracingRing::new(8));
        with_ring(Arc::clone(&ring), || {
            tracing::error!("e");
            tracing::warn!("w");
            tracing::info!("i");
            tracing::debug!("d");
            tracing::trace!("t");
        });
        let snap = ring.snapshot();
        // Default registry forwards every level since we didn't
        // attach an EnvFilter — debug/trace fall through.
        let levels: Vec<String> = snap
            .iter()
            .map(|l| {
                let v: Value = serde_json::from_str(l).unwrap();
                v["level"].as_str().unwrap().to_string()
            })
            .collect();
        assert!(levels.contains(&"ERROR".to_string()));
        assert!(levels.contains(&"WARN".to_string()));
        assert!(levels.contains(&"INFO".to_string()));
    }

    #[test]
    fn ring_overflow_drops_oldest() {
        let ring = Arc::new(TracingRing::new(3));
        with_ring(Arc::clone(&ring), || {
            for i in 0..10 {
                tracing::info!(seq = i, "n");
            }
        });
        let snap = ring.snapshot();
        assert_eq!(snap.len(), 3);
        // The last three are seqs 7, 8, 9.
        for (idx, line) in snap.iter().enumerate() {
            let expected = (7 + idx) as u64;
            let v: Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["fields"]["seq"], expected);
        }
    }

    #[test]
    fn debug_formatted_field_is_stringified() {
        let ring = Arc::new(TracingRing::new(8));
        with_ring(Arc::clone(&ring), || {
            #[derive(Debug)]
            #[allow(dead_code)]
            struct Thing {
                x: u8,
            }
            let t = Thing { x: 7 };
            tracing::info!(thing = ?t, "dbg");
        });
        let snap = ring.snapshot();
        let v: Value = serde_json::from_str(&snap[0]).unwrap();
        // record_debug renders via the Debug impl as a string.
        assert!(
            v["fields"]["thing"]
                .as_str()
                .unwrap()
                .contains("x: 7")
        );
    }

    #[test]
    fn level_filter_unset_records_at_all_levels() {
        // Sanity: without an EnvFilter the layer logs everything;
        // production attaches a filter (via SubscriberExt::with(filter))
        // upstream of this layer.
        let ring = Arc::new(TracingRing::new(8));
        with_ring(Arc::clone(&ring), || {
            tracing::event!(Level::TRACE, "trace event");
        });
        assert!(!ring.snapshot().is_empty());
    }
}
