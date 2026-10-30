//! Audited against the ISA-L 2.31.0 public EC API and its base/x86 implementations.
//! Tables and sources are read-only during encoding despite the C pointer types.
use crate::{error, Result};
use std::ffi::c_int;

// Conservative common floor for the SSE/AVX/AVX2/AVX512 dispatch families.
pub(crate) const MIN_LENGTH: usize = 64;

#[link(name = "isal")]
extern "C" {
    fn ec_init_tables(k: c_int, rows: c_int, coefficients: *mut u8, tables: *mut u8);
    fn ec_encode_data(
        length: c_int,
        k: c_int,
        rows: c_int,
        tables: *mut u8,
        input: *mut *mut u8,
        output: *mut *mut u8,
    );
}

fn ffi_length(length: usize) -> Result<c_int> {
    if length < MIN_LENGTH {
        return Err(error("ISA-L wrapper requires at least 64 bytes"));
    }
    c_int::try_from(length).map_err(|_| error("ISA-L block length exceeds C int"))
}

/// Expanded coefficients, initialized once and immutable after construction.
/// No unsafe Send/Sync implementation is needed: only ordinary owned data is held.
#[derive(Debug, Clone)]
pub(crate) struct Tables {
    k: c_int,
    rows: c_int,
    // Initialization uses uint64_t stores in both base and GFNI implementations.
    // Vec<u64> guarantees that alignment; allocate the public API's 32*k*rows bytes.
    words: Vec<u64>,
}

impl Tables {
    pub(crate) fn new(coefficients: &[Vec<u8>]) -> Result<Self> {
        let rows = coefficients.len();
        let k = coefficients.first().map_or(0, Vec::len);
        if k == 0
            || rows == 0
            || k.checked_add(rows).is_none_or(|n| n > 256)
            || coefficients.iter().any(|row| row.len() != k)
        {
            return Err(error("invalid ISA-L coefficient dimensions"));
        }
        let count = k
            .checked_mul(rows)
            .ok_or_else(|| error("ISA-L coefficient count overflow"))?;
        let table_words = count
            .checked_mul(4)
            .ok_or_else(|| error("ISA-L table size overflow"))?;
        let k = c_int::try_from(k).map_err(|_| error("ISA-L k exceeds C int"))?;
        let rows = c_int::try_from(rows).map_err(|_| error("ISA-L rows exceeds C int"))?;
        let mut flat: Vec<u8> = coefficients.iter().flatten().copied().collect();
        let mut words = vec![0u64; table_words];
        // SAFETY: dimensions are positive and bounded; flat owns k*rows bytes;
        // words owns 32*k*rows bytes and has uint64_t alignment. Both allocations
        // are distinct, mutable, and live throughout this synchronous call.
        unsafe {
            ec_init_tables(k, rows, flat.as_mut_ptr(), words.as_mut_ptr().cast());
        }
        Ok(Self { k, rows, words })
    }

    pub(crate) fn apply<I: AsRef<[u8]>>(
        &self,
        inputs: &[I],
        length: usize,
    ) -> Result<Vec<Vec<u8>>> {
        let ffi_length = ffi_length(length)?;
        if inputs.len() != self.k as usize {
            return Err(error(
                "ISA-L input count or lengths differ from prepared tables",
            ));
        }
        let mut source_ptrs: Vec<_> = inputs
            .iter()
            .map(|input| {
                // Obtain each borrowed slice once: a generic AsRef may return
                // a different slice on a later call. Validate the actual pointer
                // passed to C rather than relying on repeated AsRef calls.
                let bytes = input.as_ref();
                if bytes.len() != length {
                    return Err(error(
                        "ISA-L input count or lengths differ from prepared tables",
                    ));
                }
                Ok(bytes.as_ptr().cast_mut())
            })
            .collect::<Result<_>>()?;
        let mut outputs = vec![vec![0; length]; self.rows as usize];
        let mut output_ptrs: Vec<_> = outputs.iter_mut().map(Vec::as_mut_ptr).collect();
        // SAFETY: all buffers have exactly length bytes, length>=64 and fits C
        // int. Pointer arrays have k/rows entries; outputs are newly allocated
        // and cannot alias inputs or tables. The public dispatcher accepts
        // unaligned addresses and handles arbitrary tails within each buffer.
        // ISA-L 2.31.0 ec_encode_data_base and the dispatched x86 kernels only
        // read sources and tables; their mutable C types do not imply writes.
        // Keeping words immutable permits shared plans without a per-call copy
        // or lock. Caller buffers stay borrowed and all allocations stay live.
        unsafe {
            ec_encode_data(
                ffi_length,
                self.k,
                self.rows,
                self.words.as_ptr().cast::<u8>().cast_mut(),
                source_ptrs.as_mut_ptr(),
                output_ptrs.as_mut_ptr(),
            );
        }
        Ok(outputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_inputs_are_checked_once_without_copying_or_mutation() {
        struct ChangingView(std::cell::Cell<usize>);

        impl AsRef<[u8]> for ChangingView {
            fn as_ref(&self) -> &[u8] {
                let call = self.0.get();
                self.0.set(call + 1);
                if call == 0 {
                    &[123; 64]
                } else {
                    &[]
                }
            }
        }

        let tables = Tables::new(&[vec![1]]).unwrap();
        let views = [ChangingView(std::cell::Cell::new(0))];
        assert_eq!(tables.apply(&views, 64).unwrap(), vec![vec![123; 64]]);
        assert_eq!(views[0].0.get(), 1);

        let source = [47; 66];
        assert_eq!(
            tables.apply(&[&source[1..]], 65).unwrap(),
            vec![vec![47; 65]]
        );
        assert_eq!(source, [47; 66]);
        assert!(tables.apply(&[&source[..63]], 64).is_err());
    }

    #[test]
    fn rejects_invalid_ffi_dimensions_and_lengths() {
        for coefficients in [
            vec![],
            vec![vec![]],
            vec![vec![1], vec![1, 2]],
            vec![vec![1; 256]],
        ] {
            assert!(Tables::new(&coefficients).is_err());
        }
        let tables = Tables::new(&[vec![1, 2]]).unwrap();
        assert!(tables.apply(&[vec![0; 63], vec![0; 63]], 63).is_err());
        assert!(tables.apply(&[vec![0; 64]], 64).is_err());
        assert!(tables.apply(&[vec![0; 64], vec![0; 65]], 64).is_err());
        assert!(ffi_length(c_int::MAX as usize + 1).is_err());
        assert_eq!(ffi_length(c_int::MAX as usize).unwrap(), c_int::MAX);
        assert_eq!(tables.words.len() * 8, 32 * 2);
    }
}
