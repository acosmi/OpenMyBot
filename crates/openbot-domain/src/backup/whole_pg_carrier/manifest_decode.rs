//! Bounded decode of an authenticated first-frame manifest plaintext.
//!
//! A `DeserializeSeed` drives `serde_json::Deserializer::from_slice`; every
//! decoded string and sequence element is charged against the checked
//! metadata bound before serde allocates it, so an oversized manifest stops
//! with `CapacityExceeded` instead of being decoded first and measured later.
use std::cell::Cell;
use std::marker::PhantomData;

use serde::de::{self, DeserializeSeed, Deserializer, EnumAccess, MapAccess, SeqAccess, Visitor};

use super::{Result, WholePgCarrierBounds, WholePgCarrierFault, WholePgManifestClaim};

struct Budget {
    left: Cell<u64>,
    exceeded: Cell<bool>,
}

impl Budget {
    fn charge<E: de::Error>(&self, bytes: usize) -> std::result::Result<(), E> {
        match self.left.get().checked_sub(bytes as u64) {
            Some(left) => {
                self.left.set(left);
                Ok(())
            }
            None => {
                self.exceeded.set(true);
                Err(E::custom("manifest metadata bound exceeded"))
            }
        }
    }
}

/// Decode `plain` as the closed manifest claim within `bounds.max_metadata_bytes`.
pub(super) fn decode(plain: &[u8], bounds: &WholePgCarrierBounds) -> Result<WholePgManifestClaim> {
    let budget = Budget {
        left: Cell::new(bounds.max_metadata_bytes),
        exceeded: Cell::new(false),
    };
    // serde_json unescapes an escaped string into its own scratch buffer, which
    // never exceeds the input length. Canonical manifests carry hex digests,
    // UUIDs, IDs and paths, so secret digest text never passes through it.
    if plain.contains(&b'\\') {
        budget
            .charge::<serde_json::Error>(plain.len())
            .map_err(|_| WholePgCarrierFault::CapacityExceeded)?;
    }
    let fault = |budget: &Budget| {
        if budget.exceeded.get() {
            WholePgCarrierFault::CapacityExceeded
        } else {
            WholePgCarrierFault::ManifestInvalid
        }
    };
    let mut json = serde_json::Deserializer::from_slice(plain);
    let claim = Charged {
        budget: &budget,
        seed: PhantomData::<WholePgManifestClaim>,
    }
    .deserialize(&mut json)
    .map_err(|_| fault(&budget))?;
    json.end()
        .map_err(|_| WholePgCarrierFault::ManifestInvalid)?;
    Ok(claim)
}

/// Seed that runs the wrapped seed against a charging deserializer.
struct Charged<'b, S> {
    budget: &'b Budget,
    seed: S,
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for Charged<'_, S> {
    type Value = S::Value;
    fn deserialize<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<S::Value, D::Error> {
        self.seed.deserialize(ChargedDeserializer {
            budget: self.budget,
            inner: deserializer,
        })
    }
}

struct ChargedDeserializer<'b, D> {
    budget: &'b Budget,
    inner: D,
}

struct ChargedVisitor<'b, V> {
    budget: &'b Budget,
    inner: V,
}

macro_rules! forward {
    ($($method:ident($($arg:ident: $ty:ty),*)),* $(,)?) => {$(
        fn $method<V: Visitor<'de>>(self, $($arg: $ty,)* visitor: V) -> std::result::Result<V::Value, D::Error> {
            self.inner.$method($($arg,)* ChargedVisitor { budget: self.budget, inner: visitor })
        }
    )*};
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for ChargedDeserializer<'_, D> {
    type Error = D::Error;
    forward!(
        deserialize_any(), deserialize_bool(), deserialize_i8(), deserialize_i16(), deserialize_i32(),
        deserialize_i64(), deserialize_i128(), deserialize_u8(), deserialize_u16(), deserialize_u32(),
        deserialize_u64(), deserialize_u128(), deserialize_f32(), deserialize_f64(), deserialize_char(),
        deserialize_str(), deserialize_string(), deserialize_bytes(), deserialize_byte_buf(),
        deserialize_option(), deserialize_unit(), deserialize_unit_struct(name: &'static str),
        deserialize_newtype_struct(name: &'static str), deserialize_seq(), deserialize_tuple(len: usize),
        deserialize_tuple_struct(name: &'static str, len: usize), deserialize_map(),
        deserialize_struct(name: &'static str, fields: &'static [&'static str]),
        deserialize_enum(name: &'static str, variants: &'static [&'static str]),
        deserialize_identifier(), deserialize_ignored_any(),
    );
    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
}

macro_rules! pass {
    ($($method:ident($ty:ty)),* $(,)?) => {$(
        fn $method<E: de::Error>(self, value: $ty) -> std::result::Result<V::Value, E> { self.inner.$method(value) }
    )*};
}

impl<'de, V: Visitor<'de>> Visitor<'de> for ChargedVisitor<'_, V> {
    type Value = V::Value;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.expecting(formatter)
    }
    pass!(
        visit_bool(bool),
        visit_i64(i64),
        visit_i128(i128),
        visit_u64(u64),
        visit_u128(u128),
        visit_f64(f64),
        visit_char(char)
    );
    fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<V::Value, E> {
        self.budget.charge(value.len())?;
        self.inner.visit_str(value)
    }
    fn visit_borrowed_str<E: de::Error>(self, value: &'de str) -> std::result::Result<V::Value, E> {
        self.budget.charge(value.len())?;
        self.inner.visit_borrowed_str(value)
    }
    fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<V::Value, E> {
        self.budget.charge(value.len())?;
        self.inner.visit_string(value)
    }
    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> std::result::Result<V::Value, E> {
        self.budget.charge(value.len())?;
        self.inner.visit_bytes(value)
    }
    fn visit_borrowed_bytes<E: de::Error>(
        self,
        value: &'de [u8],
    ) -> std::result::Result<V::Value, E> {
        self.budget.charge(value.len())?;
        self.inner.visit_borrowed_bytes(value)
    }
    fn visit_none<E: de::Error>(self) -> std::result::Result<V::Value, E> {
        self.inner.visit_none()
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<V::Value, E> {
        self.inner.visit_unit()
    }
    fn visit_some<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<V::Value, D::Error> {
        self.inner.visit_some(ChargedDeserializer {
            budget: self.budget,
            inner: deserializer,
        })
    }
    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<V::Value, D::Error> {
        self.inner.visit_newtype_struct(ChargedDeserializer {
            budget: self.budget,
            inner: deserializer,
        })
    }
    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> std::result::Result<V::Value, A::Error> {
        self.inner.visit_seq(ChargedSeq {
            budget: self.budget,
            inner: seq,
        })
    }
    fn visit_map<A: MapAccess<'de>>(self, map: A) -> std::result::Result<V::Value, A::Error> {
        self.inner.visit_map(ChargedMap {
            budget: self.budget,
            inner: map,
        })
    }
    fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> std::result::Result<V::Value, A::Error> {
        // The claim's enums are unit variants named by borrowed input text.
        self.inner.visit_enum(data)
    }
}

struct ChargedSeq<'b, A> {
    budget: &'b Budget,
    inner: A,
}

impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for ChargedSeq<'_, A> {
    type Error = A::Error;
    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> std::result::Result<Option<T::Value>, A::Error> {
        // Vec growth may double its capacity, so each element prepays two slots.
        self.budget.charge(2 * std::mem::size_of::<T::Value>())?;
        self.inner.next_element_seed(Charged {
            budget: self.budget,
            seed,
        })
    }
}

struct ChargedMap<'b, A> {
    budget: &'b Budget,
    inner: A,
}

impl<'de, A: MapAccess<'de>> MapAccess<'de> for ChargedMap<'_, A> {
    type Error = A::Error;
    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> std::result::Result<Option<K::Value>, A::Error> {
        self.inner.next_key_seed(Charged {
            budget: self.budget,
            seed,
        })
    }
    fn next_value_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> std::result::Result<T::Value, A::Error> {
        self.inner.next_value_seed(Charged {
            budget: self.budget,
            seed,
        })
    }
}
