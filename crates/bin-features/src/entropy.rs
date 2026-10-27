/// Shannon entropy in bits per byte (0.0 ..= 8.0).
pub fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Normalized 256-bin byte histogram (sums to 1.0, or all zeros for empty input).
pub fn byte_histogram(data: &[u8]) -> Vec<f32> {
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len().max(1) as f32;
    counts.iter().map(|&c| c as f32 / total).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_constant_have_zero_entropy() {
        assert_eq!(shannon(&[]), 0.0);
        assert_eq!(shannon(&[7u8; 1024]), 0.0);
    }

    #[test]
    fn uniform_bytes_have_max_entropy() {
        let data: Vec<u8> = (0..=255u8).collect();
        assert!((shannon(&data) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn histogram_is_normalized() {
        let hist = byte_histogram(b"aab");
        assert_eq!(hist.len(), 256);
        assert!((hist.iter().sum::<f32>() - 1.0).abs() < 1e-6);
        assert!((hist[b'a' as usize] - 2.0 / 3.0).abs() < 1e-6);
    }
}
