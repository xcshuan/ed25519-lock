// Generated by Molecule 0.7.0

#![allow(unused_imports)]
#![allow(dead_code)]

use super::ckb_types::{packed::*, prelude::*};
use super::molecule::{self, prelude::*};
use super::vec;
use super::ToOwned;
// these lines above are manually added
// replace "::molecule" to "molecule" in below code
#[derive(Clone)]
pub struct Signature(molecule::bytes::Bytes);
impl ::core::fmt::LowerHex for Signature {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        use molecule::hex_string;
        if f.alternate() {
            write!(f, "0x")?;
        }
        write!(f, "{}", hex_string(self.as_slice()))
    }
}
impl ::core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "{}({:#x})", Self::NAME, self)
    }
}
impl ::core::fmt::Display for Signature {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "{} {{ ", Self::NAME)?;
        write!(f, "{}: {}", "mes", self.mes())?;
        write!(f, ", {}: {}", "sig", self.sig())?;
        write!(f, ", {}: {}", "pubkey", self.pubkey())?;
        let extra_count = self.count_extra_fields();
        if extra_count != 0 {
            write!(f, ", .. ({} fields)", extra_count)?;
        }
        write!(f, " }}")
    }
}
impl ::core::default::Default for Signature {
    fn default() -> Self {
        let v: Vec<u8> = vec![
            28, 0, 0, 0, 16, 0, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        Signature::new_unchecked(v.into())
    }
}
impl Signature {
    pub const FIELD_COUNT: usize = 3;
    pub fn total_size(&self) -> usize {
        molecule::unpack_number(self.as_slice()) as usize
    }
    pub fn field_count(&self) -> usize {
        if self.total_size() == molecule::NUMBER_SIZE {
            0
        } else {
            (molecule::unpack_number(&self.as_slice()[molecule::NUMBER_SIZE..]) as usize / 4) - 1
        }
    }
    pub fn count_extra_fields(&self) -> usize {
        self.field_count() - Self::FIELD_COUNT
    }
    pub fn has_extra_fields(&self) -> bool {
        Self::FIELD_COUNT != self.field_count()
    }
    pub fn mes(&self) -> Bytes {
        let slice = self.as_slice();
        let start = molecule::unpack_number(&slice[4..]) as usize;
        let end = molecule::unpack_number(&slice[8..]) as usize;
        Bytes::new_unchecked(self.0.slice(start..end))
    }
    pub fn sig(&self) -> Bytes {
        let slice = self.as_slice();
        let start = molecule::unpack_number(&slice[8..]) as usize;
        let end = molecule::unpack_number(&slice[12..]) as usize;
        Bytes::new_unchecked(self.0.slice(start..end))
    }
    pub fn pubkey(&self) -> Bytes {
        let slice = self.as_slice();
        let start = molecule::unpack_number(&slice[12..]) as usize;
        if self.has_extra_fields() {
            let end = molecule::unpack_number(&slice[16..]) as usize;
            Bytes::new_unchecked(self.0.slice(start..end))
        } else {
            Bytes::new_unchecked(self.0.slice(start..))
        }
    }
    pub fn as_reader<'r>(&'r self) -> SignatureReader<'r> {
        SignatureReader::new_unchecked(self.as_slice())
    }
}
impl molecule::prelude::Entity for Signature {
    type Builder = SignatureBuilder;
    const NAME: &'static str = "Signature";
    fn new_unchecked(data: molecule::bytes::Bytes) -> Self {
        Signature(data)
    }
    fn as_bytes(&self) -> molecule::bytes::Bytes {
        self.0.clone()
    }
    fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }
    fn from_slice(slice: &[u8]) -> molecule::error::VerificationResult<Self> {
        SignatureReader::from_slice(slice).map(|reader| reader.to_entity())
    }
    fn from_compatible_slice(slice: &[u8]) -> molecule::error::VerificationResult<Self> {
        SignatureReader::from_compatible_slice(slice).map(|reader| reader.to_entity())
    }
    fn new_builder() -> Self::Builder {
        ::core::default::Default::default()
    }
    fn as_builder(self) -> Self::Builder {
        Self::new_builder()
            .mes(self.mes())
            .sig(self.sig())
            .pubkey(self.pubkey())
    }
}
#[derive(Clone, Copy)]
pub struct SignatureReader<'r>(&'r [u8]);
impl<'r> ::core::fmt::LowerHex for SignatureReader<'r> {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        use molecule::hex_string;
        if f.alternate() {
            write!(f, "0x")?;
        }
        write!(f, "{}", hex_string(self.as_slice()))
    }
}
impl<'r> ::core::fmt::Debug for SignatureReader<'r> {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "{}({:#x})", Self::NAME, self)
    }
}
impl<'r> ::core::fmt::Display for SignatureReader<'r> {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "{} {{ ", Self::NAME)?;
        write!(f, "{}: {}", "mes", self.mes())?;
        write!(f, ", {}: {}", "sig", self.sig())?;
        write!(f, ", {}: {}", "pubkey", self.pubkey())?;
        let extra_count = self.count_extra_fields();
        if extra_count != 0 {
            write!(f, ", .. ({} fields)", extra_count)?;
        }
        write!(f, " }}")
    }
}
impl<'r> SignatureReader<'r> {
    pub const FIELD_COUNT: usize = 3;
    pub fn total_size(&self) -> usize {
        molecule::unpack_number(self.as_slice()) as usize
    }
    pub fn field_count(&self) -> usize {
        if self.total_size() == molecule::NUMBER_SIZE {
            0
        } else {
            (molecule::unpack_number(&self.as_slice()[molecule::NUMBER_SIZE..]) as usize / 4) - 1
        }
    }
    pub fn count_extra_fields(&self) -> usize {
        self.field_count() - Self::FIELD_COUNT
    }
    pub fn has_extra_fields(&self) -> bool {
        Self::FIELD_COUNT != self.field_count()
    }
    pub fn mes(&self) -> BytesReader<'r> {
        let slice = self.as_slice();
        let start = molecule::unpack_number(&slice[4..]) as usize;
        let end = molecule::unpack_number(&slice[8..]) as usize;
        BytesReader::new_unchecked(&self.as_slice()[start..end])
    }
    pub fn sig(&self) -> BytesReader<'r> {
        let slice = self.as_slice();
        let start = molecule::unpack_number(&slice[8..]) as usize;
        let end = molecule::unpack_number(&slice[12..]) as usize;
        BytesReader::new_unchecked(&self.as_slice()[start..end])
    }
    pub fn pubkey(&self) -> BytesReader<'r> {
        let slice = self.as_slice();
        let start = molecule::unpack_number(&slice[12..]) as usize;
        if self.has_extra_fields() {
            let end = molecule::unpack_number(&slice[16..]) as usize;
            BytesReader::new_unchecked(&self.as_slice()[start..end])
        } else {
            BytesReader::new_unchecked(&self.as_slice()[start..])
        }
    }
}
impl<'r> molecule::prelude::Reader<'r> for SignatureReader<'r> {
    type Entity = Signature;
    const NAME: &'static str = "SignatureReader";
    fn to_entity(&self) -> Self::Entity {
        Self::Entity::new_unchecked(self.as_slice().to_owned().into())
    }
    fn new_unchecked(slice: &'r [u8]) -> Self {
        SignatureReader(slice)
    }
    fn as_slice(&self) -> &'r [u8] {
        self.0
    }
    fn verify(slice: &[u8], compatible: bool) -> molecule::error::VerificationResult<()> {
        use molecule::verification_error as ve;
        let slice_len = slice.len();
        if slice_len < molecule::NUMBER_SIZE {
            return ve!(Self, HeaderIsBroken, molecule::NUMBER_SIZE, slice_len);
        }
        let total_size = molecule::unpack_number(slice) as usize;
        if slice_len != total_size {
            return ve!(Self, TotalSizeNotMatch, total_size, slice_len);
        }
        if slice_len == molecule::NUMBER_SIZE && Self::FIELD_COUNT == 0 {
            return Ok(());
        }
        if slice_len < molecule::NUMBER_SIZE * 2 {
            return ve!(Self, HeaderIsBroken, molecule::NUMBER_SIZE * 2, slice_len);
        }
        let offset_first = molecule::unpack_number(&slice[molecule::NUMBER_SIZE..]) as usize;
        if offset_first % molecule::NUMBER_SIZE != 0 || offset_first < molecule::NUMBER_SIZE * 2 {
            return ve!(Self, OffsetsNotMatch);
        }
        if slice_len < offset_first {
            return ve!(Self, HeaderIsBroken, offset_first, slice_len);
        }
        let field_count = offset_first / molecule::NUMBER_SIZE - 1;
        if field_count < Self::FIELD_COUNT {
            return ve!(Self, FieldCountNotMatch, Self::FIELD_COUNT, field_count);
        } else if !compatible && field_count > Self::FIELD_COUNT {
            return ve!(Self, FieldCountNotMatch, Self::FIELD_COUNT, field_count);
        };
        let mut offsets: Vec<usize> = slice[molecule::NUMBER_SIZE..offset_first]
            .chunks_exact(molecule::NUMBER_SIZE)
            .map(|x| molecule::unpack_number(x) as usize)
            .collect();
        offsets.push(total_size);
        if offsets.windows(2).any(|i| i[0] > i[1]) {
            return ve!(Self, OffsetsNotMatch);
        }
        BytesReader::verify(&slice[offsets[0]..offsets[1]], compatible)?;
        BytesReader::verify(&slice[offsets[1]..offsets[2]], compatible)?;
        BytesReader::verify(&slice[offsets[2]..offsets[3]], compatible)?;
        Ok(())
    }
}
#[derive(Debug, Default)]
pub struct SignatureBuilder {
    pub(crate) mes: Bytes,
    pub(crate) sig: Bytes,
    pub(crate) pubkey: Bytes,
}
impl SignatureBuilder {
    pub const FIELD_COUNT: usize = 3;
    pub fn mes(mut self, v: Bytes) -> Self {
        self.mes = v;
        self
    }
    pub fn sig(mut self, v: Bytes) -> Self {
        self.sig = v;
        self
    }
    pub fn pubkey(mut self, v: Bytes) -> Self {
        self.pubkey = v;
        self
    }
}
impl molecule::prelude::Builder for SignatureBuilder {
    type Entity = Signature;
    const NAME: &'static str = "SignatureBuilder";
    fn expected_length(&self) -> usize {
        molecule::NUMBER_SIZE * (Self::FIELD_COUNT + 1)
            + self.mes.as_slice().len()
            + self.sig.as_slice().len()
            + self.pubkey.as_slice().len()
    }
    fn write<W: molecule::io::Write>(&self, writer: &mut W) -> molecule::io::Result<()> {
        let mut total_size = molecule::NUMBER_SIZE * (Self::FIELD_COUNT + 1);
        let mut offsets = Vec::with_capacity(Self::FIELD_COUNT);
        offsets.push(total_size);
        total_size += self.mes.as_slice().len();
        offsets.push(total_size);
        total_size += self.sig.as_slice().len();
        offsets.push(total_size);
        total_size += self.pubkey.as_slice().len();
        writer.write_all(&molecule::pack_number(total_size as molecule::Number))?;
        for offset in offsets.into_iter() {
            writer.write_all(&molecule::pack_number(offset as molecule::Number))?;
        }
        writer.write_all(self.mes.as_slice())?;
        writer.write_all(self.sig.as_slice())?;
        writer.write_all(self.pubkey.as_slice())?;
        Ok(())
    }
    fn build(&self) -> Self::Entity {
        let mut inner = Vec::with_capacity(self.expected_length());
        self.write(&mut inner)
            .unwrap_or_else(|_| panic!("{} build should be ok", Self::NAME));
        Signature::new_unchecked(inner.into())
    }
}
#[derive(Clone)]
pub struct SignatureVec(molecule::bytes::Bytes);
impl ::core::fmt::LowerHex for SignatureVec {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        use molecule::hex_string;
        if f.alternate() {
            write!(f, "0x")?;
        }
        write!(f, "{}", hex_string(self.as_slice()))
    }
}
impl ::core::fmt::Debug for SignatureVec {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "{}({:#x})", Self::NAME, self)
    }
}
impl ::core::fmt::Display for SignatureVec {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "{} [", Self::NAME)?;
        for i in 0..self.len() {
            if i == 0 {
                write!(f, "{}", self.get_unchecked(i))?;
            } else {
                write!(f, ", {}", self.get_unchecked(i))?;
            }
        }
        write!(f, "]")
    }
}
impl ::core::default::Default for SignatureVec {
    fn default() -> Self {
        let v: Vec<u8> = vec![4, 0, 0, 0];
        SignatureVec::new_unchecked(v.into())
    }
}
impl SignatureVec {
    pub fn total_size(&self) -> usize {
        molecule::unpack_number(self.as_slice()) as usize
    }
    pub fn item_count(&self) -> usize {
        if self.total_size() == molecule::NUMBER_SIZE {
            0
        } else {
            (molecule::unpack_number(&self.as_slice()[molecule::NUMBER_SIZE..]) as usize / 4) - 1
        }
    }
    pub fn len(&self) -> usize {
        self.item_count()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn get(&self, idx: usize) -> Option<Signature> {
        if idx >= self.len() {
            None
        } else {
            Some(self.get_unchecked(idx))
        }
    }
    pub fn get_unchecked(&self, idx: usize) -> Signature {
        let slice = self.as_slice();
        let start_idx = molecule::NUMBER_SIZE * (1 + idx);
        let start = molecule::unpack_number(&slice[start_idx..]) as usize;
        if idx == self.len() - 1 {
            Signature::new_unchecked(self.0.slice(start..))
        } else {
            let end_idx = start_idx + molecule::NUMBER_SIZE;
            let end = molecule::unpack_number(&slice[end_idx..]) as usize;
            Signature::new_unchecked(self.0.slice(start..end))
        }
    }
    pub fn as_reader<'r>(&'r self) -> SignatureVecReader<'r> {
        SignatureVecReader::new_unchecked(self.as_slice())
    }
}
impl molecule::prelude::Entity for SignatureVec {
    type Builder = SignatureVecBuilder;
    const NAME: &'static str = "SignatureVec";
    fn new_unchecked(data: molecule::bytes::Bytes) -> Self {
        SignatureVec(data)
    }
    fn as_bytes(&self) -> molecule::bytes::Bytes {
        self.0.clone()
    }
    fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }
    fn from_slice(slice: &[u8]) -> molecule::error::VerificationResult<Self> {
        SignatureVecReader::from_slice(slice).map(|reader| reader.to_entity())
    }
    fn from_compatible_slice(slice: &[u8]) -> molecule::error::VerificationResult<Self> {
        SignatureVecReader::from_compatible_slice(slice).map(|reader| reader.to_entity())
    }
    fn new_builder() -> Self::Builder {
        ::core::default::Default::default()
    }
    fn as_builder(self) -> Self::Builder {
        Self::new_builder().extend(self.into_iter())
    }
}
#[derive(Clone, Copy)]
pub struct SignatureVecReader<'r>(&'r [u8]);
impl<'r> ::core::fmt::LowerHex for SignatureVecReader<'r> {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        use molecule::hex_string;
        if f.alternate() {
            write!(f, "0x")?;
        }
        write!(f, "{}", hex_string(self.as_slice()))
    }
}
impl<'r> ::core::fmt::Debug for SignatureVecReader<'r> {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "{}({:#x})", Self::NAME, self)
    }
}
impl<'r> ::core::fmt::Display for SignatureVecReader<'r> {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "{} [", Self::NAME)?;
        for i in 0..self.len() {
            if i == 0 {
                write!(f, "{}", self.get_unchecked(i))?;
            } else {
                write!(f, ", {}", self.get_unchecked(i))?;
            }
        }
        write!(f, "]")
    }
}
impl<'r> SignatureVecReader<'r> {
    pub fn total_size(&self) -> usize {
        molecule::unpack_number(self.as_slice()) as usize
    }
    pub fn item_count(&self) -> usize {
        if self.total_size() == molecule::NUMBER_SIZE {
            0
        } else {
            (molecule::unpack_number(&self.as_slice()[molecule::NUMBER_SIZE..]) as usize / 4) - 1
        }
    }
    pub fn len(&self) -> usize {
        self.item_count()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn get(&self, idx: usize) -> Option<SignatureReader<'r>> {
        if idx >= self.len() {
            None
        } else {
            Some(self.get_unchecked(idx))
        }
    }
    pub fn get_unchecked(&self, idx: usize) -> SignatureReader<'r> {
        let slice = self.as_slice();
        let start_idx = molecule::NUMBER_SIZE * (1 + idx);
        let start = molecule::unpack_number(&slice[start_idx..]) as usize;
        if idx == self.len() - 1 {
            SignatureReader::new_unchecked(&self.as_slice()[start..])
        } else {
            let end_idx = start_idx + molecule::NUMBER_SIZE;
            let end = molecule::unpack_number(&slice[end_idx..]) as usize;
            SignatureReader::new_unchecked(&self.as_slice()[start..end])
        }
    }
}
impl<'r> molecule::prelude::Reader<'r> for SignatureVecReader<'r> {
    type Entity = SignatureVec;
    const NAME: &'static str = "SignatureVecReader";
    fn to_entity(&self) -> Self::Entity {
        Self::Entity::new_unchecked(self.as_slice().to_owned().into())
    }
    fn new_unchecked(slice: &'r [u8]) -> Self {
        SignatureVecReader(slice)
    }
    fn as_slice(&self) -> &'r [u8] {
        self.0
    }
    fn verify(slice: &[u8], compatible: bool) -> molecule::error::VerificationResult<()> {
        use molecule::verification_error as ve;
        let slice_len = slice.len();
        if slice_len < molecule::NUMBER_SIZE {
            return ve!(Self, HeaderIsBroken, molecule::NUMBER_SIZE, slice_len);
        }
        let total_size = molecule::unpack_number(slice) as usize;
        if slice_len != total_size {
            return ve!(Self, TotalSizeNotMatch, total_size, slice_len);
        }
        if slice_len == molecule::NUMBER_SIZE {
            return Ok(());
        }
        if slice_len < molecule::NUMBER_SIZE * 2 {
            return ve!(
                Self,
                TotalSizeNotMatch,
                molecule::NUMBER_SIZE * 2,
                slice_len
            );
        }
        let offset_first = molecule::unpack_number(&slice[molecule::NUMBER_SIZE..]) as usize;
        if offset_first % molecule::NUMBER_SIZE != 0 || offset_first < molecule::NUMBER_SIZE * 2 {
            return ve!(Self, OffsetsNotMatch);
        }
        if slice_len < offset_first {
            return ve!(Self, HeaderIsBroken, offset_first, slice_len);
        }
        let mut offsets: Vec<usize> = slice[molecule::NUMBER_SIZE..offset_first]
            .chunks_exact(molecule::NUMBER_SIZE)
            .map(|x| molecule::unpack_number(x) as usize)
            .collect();
        offsets.push(total_size);
        if offsets.windows(2).any(|i| i[0] > i[1]) {
            return ve!(Self, OffsetsNotMatch);
        }
        for pair in offsets.windows(2) {
            let start = pair[0];
            let end = pair[1];
            SignatureReader::verify(&slice[start..end], compatible)?;
        }
        Ok(())
    }
}
#[derive(Debug, Default)]
pub struct SignatureVecBuilder(pub(crate) Vec<Signature>);
impl SignatureVecBuilder {
    pub fn set(mut self, v: Vec<Signature>) -> Self {
        self.0 = v;
        self
    }
    pub fn push(mut self, v: Signature) -> Self {
        self.0.push(v);
        self
    }
    pub fn extend<T: ::core::iter::IntoIterator<Item = Signature>>(mut self, iter: T) -> Self {
        for elem in iter {
            self.0.push(elem);
        }
        self
    }
}
impl molecule::prelude::Builder for SignatureVecBuilder {
    type Entity = SignatureVec;
    const NAME: &'static str = "SignatureVecBuilder";
    fn expected_length(&self) -> usize {
        molecule::NUMBER_SIZE * (self.0.len() + 1)
            + self
                .0
                .iter()
                .map(|inner| inner.as_slice().len())
                .sum::<usize>()
    }
    fn write<W: molecule::io::Write>(&self, writer: &mut W) -> molecule::io::Result<()> {
        let item_count = self.0.len();
        if item_count == 0 {
            writer.write_all(&molecule::pack_number(
                molecule::NUMBER_SIZE as molecule::Number,
            ))?;
        } else {
            let (total_size, offsets) = self.0.iter().fold(
                (
                    molecule::NUMBER_SIZE * (item_count + 1),
                    Vec::with_capacity(item_count),
                ),
                |(start, mut offsets), inner| {
                    offsets.push(start);
                    (start + inner.as_slice().len(), offsets)
                },
            );
            writer.write_all(&molecule::pack_number(total_size as molecule::Number))?;
            for offset in offsets.into_iter() {
                writer.write_all(&molecule::pack_number(offset as molecule::Number))?;
            }
            for inner in self.0.iter() {
                writer.write_all(inner.as_slice())?;
            }
        }
        Ok(())
    }
    fn build(&self) -> Self::Entity {
        let mut inner = Vec::with_capacity(self.expected_length());
        self.write(&mut inner)
            .unwrap_or_else(|_| panic!("{} build should be ok", Self::NAME));
        SignatureVec::new_unchecked(inner.into())
    }
}
pub struct SignatureVecIterator(SignatureVec, usize, usize);
impl ::core::iter::Iterator for SignatureVecIterator {
    type Item = Signature;
    fn next(&mut self) -> Option<Self::Item> {
        if self.1 >= self.2 {
            None
        } else {
            let ret = self.0.get_unchecked(self.1);
            self.1 += 1;
            Some(ret)
        }
    }
}
impl ::core::iter::ExactSizeIterator for SignatureVecIterator {
    fn len(&self) -> usize {
        self.2 - self.1
    }
}
impl ::core::iter::IntoIterator for SignatureVec {
    type Item = Signature;
    type IntoIter = SignatureVecIterator;
    fn into_iter(self) -> Self::IntoIter {
        let len = self.len();
        SignatureVecIterator(self, 0, len)
    }
}
impl<'r> SignatureVecReader<'r> {
    pub fn iter<'t>(&'t self) -> SignatureVecReaderIterator<'t, 'r> {
        SignatureVecReaderIterator(&self, 0, self.len())
    }
}
pub struct SignatureVecReaderIterator<'t, 'r>(&'t SignatureVecReader<'r>, usize, usize);
impl<'t: 'r, 'r> ::core::iter::Iterator for SignatureVecReaderIterator<'t, 'r> {
    type Item = SignatureReader<'t>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.1 >= self.2 {
            None
        } else {
            let ret = self.0.get_unchecked(self.1);
            self.1 += 1;
            Some(ret)
        }
    }
}
impl<'t: 'r, 'r> ::core::iter::ExactSizeIterator for SignatureVecReaderIterator<'t, 'r> {
    fn len(&self) -> usize {
        self.2 - self.1
    }
}
