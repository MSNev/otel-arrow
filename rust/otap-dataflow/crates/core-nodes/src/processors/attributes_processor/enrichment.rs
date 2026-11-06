// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

use otel_arrow_dfe_config::ContextSelector;
use otel_arrow_dfe_engine::pdata_context::{
    ContextDomain, ContextEntrySelector, ContextEntrySelectorForm, ContextEntryTake,
    ContextValueCardinality, ContextValueKind, Metadata, NodeBindings, Read, ReadMember, ValueRead,
};

use super::*;

/// An insert, upsert, or update value: either the existing literal or a nested source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum ConfiguredValue {
    /// Existing typed literal, with unchanged configuration syntax.
    Literal(LiteralValue),
    /// Explicit typed literal, as documented in existing configuration examples.
    Typed(#[serde(with = "TypedLiteralSerde")] LiteralValue),
    /// Dynamic request metadata source, configured under the `value` key.
    Dynamic {
        /// Ordered fallback primitives in one domain, or composite references.
        source: ContextSelector,
    },
}

// Adapt the documented tagged syntax without introducing a second value representation.
#[derive(Serialize, Deserialize)]
#[serde(remote = "LiteralValue", rename_all = "lowercase", deny_unknown_fields)]
enum TypedLiteralSerde {
    Bool(bool),
    Int(i64),
    Double(f64),
    #[serde(rename = "string")]
    Str(String),
}

pub(super) fn non_null<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

pub(super) fn invalid_config(error: impl Into<String>) -> ConfigError {
    ConfigError::InvalidUserConfig {
        error: error.into(),
    }
}

pub(super) fn invalid_data(error: impl Into<String>) -> EngineError {
    EngineError::PdataConversionError {
        error: error.into(),
    }
}

/// Declares one value read per candidate, in fallback order.
pub(super) fn context_entries(
    source: &ContextSelector,
) -> impl Iterator<Item = ContextEntrySelector> + '_ {
    ContextEntrySelector::from_config(
        source,
        ContextEntrySelectorForm::Value,
        ContextEntryTake::All,
    )
}

/// A dynamic source bound to the node's compiled reads at construction.
#[derive(Debug, Clone)]
pub(super) struct BoundSource {
    domain: Option<ContextDomain>,
    reads: Box<[ValueRead]>,
}

impl BoundSource {
    /// Looks up the compiled read for every declared candidate.
    pub(super) fn bind(
        source: &ContextSelector,
        bindings: &NodeBindings,
    ) -> Result<Self, ConfigError> {
        Ok(Self {
            domain: source.domain(),
            reads: context_entries(source)
                .map(|selector| bindings.value(&selector).cloned())
                .collect::<Result<_, _>>()?,
        })
    }

    /// Returns the first usable candidate as text.
    ///
    /// Transport headers skip binary, invalid UTF-8, and blank values and fall
    /// through to later candidates. Identity claims and composite members must
    /// be scalar text; other shapes are errors.
    pub(super) fn resolve(&self, metadata: &Metadata) -> Result<Option<LiteralValue>, EngineError> {
        for read in &self.reads {
            let Some(selected) = read
                .read(metadata)
                .map_err(|error| invalid_data(error.to_string()))?
            else {
                continue;
            };
            let text = match self.domain {
                Some(ContextDomain::TransportHeader) => first_usable_header(selected),
                Some(ContextDomain::AuthorizedIdentity) => Some(scalar_text(selected, false)?),
                None => Some(scalar_text(selected, true)?),
            };
            if let Some(text) = text {
                return Ok(Some(LiteralValue::Str(text)));
            }
        }
        Ok(None)
    }
}

/// Selects the first non-blank text value among one header's captured values.
fn first_usable_header(selected: Read<'_>) -> Option<String> {
    let mut found = None;
    selected.visit_members(|member| {
        if found.is_some() {
            return;
        }
        found = member.values().find_map(|value| {
            if value.kind != ContextValueKind::Text {
                return None;
            }
            let text = std::str::from_utf8(value.bytes).ok()?;
            (!text.trim().is_empty()).then(|| text.to_owned())
        });
    });
    found
}

/// Requires one scalar text member; composites must select exactly one member.
fn scalar_text(selected: Read<'_>, composite: bool) -> Result<String, EngineError> {
    let mut first: Option<ReadMember<'_>> = None;
    let mut members = 0usize;
    selected.visit_members(|member| {
        members += 1;
        if first.is_none() {
            first = Some(member);
        }
    });
    if composite && members > 1 {
        return Err(invalid_data(
            "context source requires entry:member for multi-member entries",
        ));
    }
    let Some(member) = first else {
        return Err(invalid_data("context source selected no members"));
    };
    if member.cardinality != ContextValueCardinality::One {
        return Err(invalid_data("context source requires a scalar value"));
    }
    let Some(value) = member.values().next() else {
        return Err(invalid_data("context source requires a scalar value"));
    };
    if value.kind != ContextValueKind::Text {
        return Err(invalid_data(
            "context source requires text for scalar attributes",
        ));
    }
    std::str::from_utf8(value.bytes)
        .map(str::to_owned)
        .map_err(|_| invalid_data("context source contains invalid UTF-8"))
}
