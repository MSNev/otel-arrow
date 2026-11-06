// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use enrichment::{BoundSource, invalid_config};
use otel_arrow_dfe_engine::pdata_context::NodeBindings;

/// One action with an optional telemetry-signal filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopedAction {
    /// The attribute operation.
    #[serde(flatten)]
    pub action: Action,
    /// Selected signals; omission selects all signals.
    #[serde(
        default,
        deserialize_with = "enrichment::non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub signals: Option<Vec<ActionSignal>>,
}

/// A telemetry signal, independent of the selected attribute domains.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionSignal {
    /// Log records.
    Logs,
    /// Metric data.
    Metrics,
    /// Spans.
    Traces,
}

impl ScopedAction {
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        if self.signals.as_ref().is_some_and(Vec::is_empty) {
            return Err(invalid_config("signals cannot be empty"));
        }
        Ok(())
    }

    fn applies(&self, signal: SignalType) -> bool {
        self.signals.as_ref().is_none_or(|signals| {
            signals.iter().any(|selected| {
                matches!(
                    (selected, signal),
                    (ActionSignal::Logs, SignalType::Logs)
                        | (ActionSignal::Metrics, SignalType::Metrics)
                        | (ActionSignal::Traces, SignalType::Traces)
                )
            })
        })
    }
}

pub(super) fn signal_index(signal: SignalType) -> usize {
    match signal {
        SignalType::Logs => 0,
        SignalType::Metrics => 1,
        SignalType::Traces => 2,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Operation {
    Insert,
    Upsert,
    Update,
}

pub(super) fn effective_value_actions(
    actions: &[ScopedAction],
    signal: SignalType,
) -> impl Iterator<Item = (Operation, &str, &ConfiguredValue)> {
    let mut seen = BTreeSet::new();
    actions
        .iter()
        .rev()
        .filter(move |action| action.applies(signal))
        .filter_map(move |scoped| {
            let (operation, key, value) = match &scoped.action {
                Action::Insert { key, value } => (Operation::Insert, key, value),
                Action::Upsert { key, value } => (Operation::Upsert, key, value),
                Action::Update { key, value } => (Operation::Update, key, value),
                _ => return None,
            };
            seen.insert((operation, key.as_str()))
                .then_some((operation, key.as_str(), value))
        })
}

struct DynamicAction {
    operation: Operation,
    key: String,
    source: BoundSource,
}

/// How dynamic sources are treated while compiling actions.
#[derive(Clone, Copy)]
pub(super) enum SourceBindings<'a> {
    /// Factory validation without a pipeline; dynamic sources are not retained.
    ValidateOnly,
    /// Construction or reconfiguration; dynamic sources bind to compiled node reads.
    Node(&'a NodeBindings),
}

pub(super) struct CompiledTransform {
    pub(super) transform: AttributesTransform,
    dynamic: Vec<DynamicAction>,
}

pub(super) fn is_noop(transform: &AttributesTransform) -> bool {
    transform.rename.is_none()
        && transform.delete.is_none()
        && transform.insert.is_none()
        && transform.upsert.is_none()
        && transform.update.is_none()
        && transform.hash.is_none()
}

fn values_transform(
    inserts: BTreeMap<String, LiteralValue>,
    upserts: BTreeMap<String, LiteralValue>,
    updates: BTreeMap<String, LiteralValue>,
) -> AttributesTransform {
    AttributesTransform {
        insert: (!inserts.is_empty()).then(|| InsertTransform::new(inserts)),
        upsert: (!upserts.is_empty()).then(|| UpsertTransform::new(upserts)),
        update: (!updates.is_empty()).then(|| UpdateTransform::new(updates)),
        ..Default::default()
    }
}

impl CompiledTransform {
    pub(super) fn is_noop(&self) -> bool {
        is_noop(&self.transform) && self.dynamic.is_empty()
    }

    pub(super) fn new(
        actions: &[ScopedAction],
        signal: SignalType,
        bindings: SourceBindings<'_>,
    ) -> Result<Self, ConfigError> {
        let mut renames = BTreeMap::new();
        let mut deletes = BTreeSet::new();
        let mut inserts = BTreeMap::new();
        let mut upserts = BTreeMap::new();
        let mut updates = BTreeMap::new();
        let mut hashes = BTreeMap::new();
        for (operation, key, value) in effective_value_actions(actions, signal) {
            let destination = match operation {
                Operation::Insert => &mut inserts,
                Operation::Upsert => &mut upserts,
                Operation::Update => &mut updates,
            };
            _ = destination.insert(key.to_string(), value.clone());
        }
        for scoped in actions.iter().filter(|action| action.applies(signal)) {
            match &scoped.action {
                Action::Rename {
                    source_key,
                    destination_key,
                } => {
                    _ = renames.insert(source_key.clone(), destination_key.clone());
                }
                Action::Delete { key } => {
                    _ = deletes.insert(key.clone());
                }
                Action::Insert { .. } | Action::Upsert { .. } | Action::Update { .. } => {}
                Action::Hash {
                    key,
                    algorithm: HashAlgorithm::Sha256,
                    salt,
                } => {
                    _ = hashes.insert(key.clone(), HashSpec::sha256(salt.clone().into_inner()));
                }
                Action::Unsupported => {}
            }
        }
        // Validate all configured destinations even when their sources are unavailable.
        let placeholder = |sources: &BTreeMap<String, ConfiguredValue>| {
            sources
                .keys()
                .map(|key| (key.clone(), LiteralValue::Int(0)))
                .collect()
        };
        let mut transform = values_transform(
            placeholder(&inserts),
            placeholder(&upserts),
            placeholder(&updates),
        );
        transform.rename = (!renames.is_empty()).then(|| RenameTransform::new(renames));
        transform.delete = (!deletes.is_empty()).then(|| DeleteTransform::new(deletes));
        transform.hash = (!hashes.is_empty()).then(|| HashTransform::new(hashes));
        transform.validate().map_err(|error| {
            invalid_config(format!(
                "Invalid attribute transform configuration: {error}"
            ))
        })?;

        let mut dynamic = Vec::new();
        let mut split = |sources: BTreeMap<String, ConfiguredValue>,
                         operation|
         -> Result<BTreeMap<String, LiteralValue>, ConfigError> {
            let mut literals = BTreeMap::new();
            for (key, value) in sources {
                match value {
                    ConfiguredValue::Literal(value) | ConfiguredValue::Typed(value) => {
                        _ = literals.insert(key, value);
                    }
                    ConfiguredValue::Dynamic { source } => {
                        if let SourceBindings::Node(bindings) = bindings {
                            dynamic.push(DynamicAction {
                                operation,
                                key,
                                source: BoundSource::bind(&source, bindings)?,
                            });
                        }
                    }
                }
            }
            Ok(literals)
        };
        let values = values_transform(
            split(inserts, Operation::Insert)?,
            split(upserts, Operation::Upsert)?,
            split(updates, Operation::Update)?,
        );
        transform.insert = values.insert;
        transform.upsert = values.upsert;
        transform.update = values.update;
        Ok(Self { transform, dynamic })
    }

    pub(super) fn resolve(
        &self,
        metadata: &otel_arrow_dfe_engine::pdata_context::Metadata,
    ) -> Result<AttributesTransform, EngineError> {
        let mut inserts = BTreeMap::new();
        let mut upserts = BTreeMap::new();
        let mut updates = BTreeMap::new();
        for action in &self.dynamic {
            if let Some(value) = action.source.resolve(metadata)? {
                let destination = match action.operation {
                    Operation::Insert => &mut inserts,
                    Operation::Upsert => &mut upserts,
                    Operation::Update => &mut updates,
                };
                _ = destination.insert(action.key.clone(), value);
            }
        }
        Ok(values_transform(inserts, upserts, updates))
    }
}
