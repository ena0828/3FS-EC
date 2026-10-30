use crate::{error, Result};

// Polynomial basis, primitive polynomial x^8+x^4+x^3+x^2+1 (0x11d).
fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut out = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            out ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1d;
        }
        b >>= 1;
    }
    out
}

fn inverse(a: u8) -> Result<u8> {
    if a == 0 {
        return Err(error("zero has no multiplicative inverse"));
    }
    let (mut value, mut base, mut power) = (1, a, 254u16);
    while power != 0 {
        if power & 1 != 0 {
            value = mul(value, base);
        }
        base = mul(base, base);
        power >>= 1;
    }
    Ok(value)
}

fn invert(mut matrix: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
    let n = matrix.len();
    let mut out = vec![vec![0; n]; n];
    for (i, row) in out.iter_mut().enumerate() {
        row[i] = 1;
    }
    for col in 0..n {
        let pivot = (col..n)
            .find(|&row| matrix[row][col] != 0)
            .ok_or_else(|| error("singular decoding matrix"))?;
        matrix.swap(col, pivot);
        out.swap(col, pivot);
        let scale = inverse(matrix[col][col])?;
        for j in 0..n {
            matrix[col][j] = mul(matrix[col][j], scale);
            out[col][j] = mul(out[col][j], scale);
        }
        for row in 0..n {
            if row == col {
                continue;
            }
            let factor = matrix[row][col];
            for j in 0..n {
                matrix[row][j] ^= mul(factor, matrix[col][j]);
                out[row][j] ^= mul(factor, out[col][j]);
            }
        }
    }
    Ok(out)
}

fn equal_lengths<'a>(mut shards: impl Iterator<Item = &'a Vec<u8>>) -> Result<usize> {
    let length = shards.next().ok_or_else(|| error("no shards"))?.len();
    if shards.any(|shard| shard.len() != length) {
        return Err(error("shards must have equal lengths"));
    }
    Ok(length)
}

fn combine<I: AsRef<[u8]>>(coefficients: &[Vec<u8>], inputs: &[I], length: usize) -> Vec<Vec<u8>> {
    coefficients
        .iter()
        .map(|row| {
            let mut output = vec![0; length];
            for (&coefficient, input) in row.iter().zip(inputs) {
                let input = input.as_ref();
                if coefficient == 0 {
                    continue;
                }
                if coefficient == 1 {
                    for (out, &byte) in output.iter_mut().zip(input) {
                        *out ^= byte;
                    }
                } else {
                    for (out, &byte) in output.iter_mut().zip(input) {
                        *out ^= mul(coefficient, byte);
                    }
                }
            }
            output
        })
        .collect()
}

/// Computation selection; every backend uses the same on-disk code format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Backend {
    #[default]
    Scalar,
    /// System ISA-L, with scalar fallback for slices shorter than 64 bytes.
    #[cfg(feature = "isal-backend")]
    Isal,
}

#[derive(Debug, Clone)]
enum Kernel {
    Scalar,
    #[cfg(feature = "isal-backend")]
    Isal(crate::isal::Tables),
}

#[derive(Debug, Clone)]
struct Transform {
    coefficients: Vec<Vec<u8>>,
    kernel: Kernel,
}

impl Transform {
    fn new(coefficients: Vec<Vec<u8>>, backend: Backend) -> Result<Self> {
        let kernel = match backend {
            Backend::Scalar => Kernel::Scalar,
            #[cfg(feature = "isal-backend")]
            Backend::Isal => Kernel::Isal(crate::isal::Tables::new(&coefficients)?),
        };
        Ok(Self {
            coefficients,
            kernel,
        })
    }

    fn backend(&self) -> Backend {
        match self.kernel {
            Kernel::Scalar => Backend::Scalar,
            #[cfg(feature = "isal-backend")]
            Kernel::Isal(_) => Backend::Isal,
        }
    }

    fn apply<I: AsRef<[u8]>>(&self, inputs: &[I], length: usize) -> Result<Vec<Vec<u8>>> {
        #[cfg(feature = "isal-backend")]
        if let Kernel::Isal(tables) = &self.kernel {
            if length >= crate::isal::MIN_LENGTH {
                return tables.apply(inputs, length);
            }
        }
        Ok(combine(&self.coefficients, inputs, length))
    }
}

/// Systematic Cauchy code: parity G[i,j] = inverse(i XOR j).
/// Here i is the global parity row index k..k+m, and j is in 0..k.
/// Callers own object padding and original-length metadata.
#[derive(Debug, Clone)]
pub struct Codec {
    k: usize,
    m: usize,
    matrix: Vec<Vec<u8>>,
    parity: Transform,
}

impl Codec {
    pub fn new(k: usize, m: usize) -> Result<Self> {
        Self::with_backend(k, m, Backend::Scalar)
    }

    /// Selects computation without changing the systematic Cauchy matrix.
    /// ISA-L lookup tables are initialized here and in `repair_plan`, not per slice.
    pub fn with_backend(k: usize, m: usize, backend: Backend) -> Result<Self> {
        if k == 0 || m == 0 || k.checked_add(m).is_none_or(|n| n > 256) {
            return Err(error("require k >= 1, m >= 1 and k + m <= 256"));
        }
        let mut matrix = vec![vec![0; k]; k + m];
        for (i, row) in matrix.iter_mut().enumerate() {
            if i < k {
                row[i] = 1;
            } else {
                for (j, coefficient) in row.iter_mut().enumerate() {
                    *coefficient = inverse((i ^ j) as u8)?;
                }
            }
        }
        let parity = Transform::new(matrix[k..].to_vec(), backend)?;
        Ok(Self {
            k,
            m,
            matrix,
            parity,
        })
    }

    pub fn backend(&self) -> Backend {
        self.parity.backend()
    }

    pub fn data_shards(&self) -> usize {
        self.k
    }

    pub fn parity_shards(&self) -> usize {
        self.m
    }

    /// Returns all k+m shards, starting with the unchanged data shards.
    pub fn encode(&self, data: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
        if data.len() != self.k {
            return Err(error("encode requires exactly k data shards"));
        }
        let length = equal_lengths(data.iter())?;
        let mut encoded = data.to_vec();
        encoded.extend(self.parity.apply(data, length)?);
        Ok(encoded)
    }

    pub fn repair_plan(&self, healthy: &[usize], targets: &[usize]) -> Result<RepairPlan> {
        if healthy.len() != self.k || targets.is_empty() || targets.len() > self.m {
            return Err(error(
                "repair requires exactly k healthy and 1..m target shards",
            ));
        }
        let mut seen = vec![false; self.k + self.m];
        for &index in healthy.iter().chain(targets) {
            if index >= seen.len() || seen[index] {
                return Err(error(
                    "shard indices must be in range, distinct and disjoint",
                ));
            }
            seen[index] = true;
        }
        let decoding = invert(healthy.iter().map(|&i| self.matrix[i].clone()).collect())?;
        let coefficients = targets
            .iter()
            .map(|&target| {
                (0..self.k)
                    .map(|col| {
                        (0..self.k).fold(0, |sum, j| {
                            sum ^ mul(self.matrix[target][j], decoding[j][col])
                        })
                    })
                    .collect()
            })
            .collect();
        Ok(RepairPlan {
            healthy: healthy.to_vec(),
            targets: targets.to_vec(),
            transform: Transform::new(coefficients, self.backend())?,
        })
    }

    /// Reconstructs known erasures. Existing bytes must be validated separately.
    /// On validation failure, the input is unchanged.
    pub fn reconstruct(&self, shards: &mut [Option<Vec<u8>>]) -> Result<()> {
        if shards.len() != self.k + self.m {
            return Err(error("reconstruct requires k+m shard slots"));
        }
        let targets: Vec<_> = shards
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.is_none().then_some(i))
            .collect();
        if targets.len() > self.m {
            return Err(error("too many erasures"));
        }
        equal_lengths(shards.iter().filter_map(Option::as_ref))?;
        if targets.is_empty() {
            return Ok(());
        }
        let healthy: Vec<_> = shards
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.is_some().then_some(i))
            .take(self.k)
            .collect();
        let plan = self.repair_plan(&healthy, &targets)?;
        let inputs: Vec<_> = healthy
            .iter()
            .map(|&i| shards[i].as_ref().unwrap().clone())
            .collect();
        for (index, recovered) in targets.into_iter().zip(plan.recover_slice(&inputs)?) {
            shards[index] = Some(recovered);
        }
        Ok(())
    }
}

/// A validated, immutable plan, reusable for every equally sized slice.
#[derive(Debug, Clone)]
pub struct RepairPlan {
    healthy: Vec<usize>,
    targets: Vec<usize>,
    transform: Transform,
}

impl RepairPlan {
    /// Selected backend; ISA-L plans still use scalar computation below 64 bytes.
    pub fn backend(&self) -> Backend {
        self.transform.backend()
    }

    pub fn healthy(&self) -> &[usize] {
        &self.healthy
    }

    pub fn targets(&self) -> &[usize] {
        &self.targets
    }

    /// Prepares the contribution of one actual shard in this plan's helper set.
    ///
    /// Each returned row contributes to the target at the same position in
    /// `targets()`. XOR exactly one contribution from every `healthy()` shard,
    /// using the same plan, byte offset and length, to obtain the repaired slice.
    /// Helper order does not affect the XOR sum. Plans from different helper
    /// sets must not be mixed: their decoding coefficients generally differ.
    pub fn contribution(&self, helper_shard: usize) -> Result<ContributionPlan> {
        let column = self
            .healthy
            .iter()
            .position(|&shard| shard == helper_shard)
            .ok_or_else(|| error("contribution helper is not in the repair plan"))?;
        let coefficients = self
            .transform
            .coefficients
            .iter()
            .map(|row| vec![row[column]])
            .collect();
        Ok(ContributionPlan {
            helper: helper_shard,
            healthy: self.healthy.clone(),
            targets: self.targets.clone(),
            transform: Transform::new(coefficients, self.backend())?,
        })
    }

    pub fn recover_slice(&self, inputs: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
        if inputs.len() != self.healthy.len() {
            return Err(error("slice input count differs from repair plan"));
        }
        let length = equal_lengths(inputs.iter())?;
        self.transform.apply(inputs, length)
    }
}

/// Immutable coefficients for one helper's part of a fixed repair plan.
///
/// This is an arithmetic primitive, not a transport or duplicate-detection
/// protocol. The caller must validate the source shard's identity, generation,
/// integrity, slice offset and expected length before calling `apply`.
#[derive(Debug, Clone)]
pub struct ContributionPlan {
    helper: usize,
    healthy: Vec<usize>,
    targets: Vec<usize>,
    transform: Transform,
}

impl ContributionPlan {
    /// Actual source shard index, not its position in `healthy()`.
    pub fn helper(&self) -> usize {
        self.helper
    }

    /// Ordered helper set used to derive these coefficients.
    pub fn healthy(&self) -> &[usize] {
        &self.healthy
    }

    /// Output rows use this target order.
    pub fn targets(&self) -> &[usize] {
        &self.targets
    }

    /// Selected backend; lengths below 64 bytes still use scalar computation.
    pub fn backend(&self) -> Backend {
        self.transform.backend()
    }

    /// Computes one weighted output per target without copying the input.
    ///
    /// All outputs have exactly `input.len()` bytes; an empty slice is valid.
    /// The plan has no object length or offset, so it cannot detect an input
    /// truncated by its caller. ISA-L rejects lengths exceeding its C int API.
    /// Tables are prepared once in `RepairPlan::contribution` and reused here.
    pub fn apply(&self, input: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.transform.apply(&[input], input.len())
    }
}
