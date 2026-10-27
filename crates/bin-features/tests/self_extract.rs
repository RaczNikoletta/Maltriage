//! Integration test: on Windows the test executable itself is a valid PE file.
#![cfg(windows)]

use bin_features::{extract, PeFeatures};

#[test]
fn extracts_features_from_own_binary() {
    let exe = std::env::current_exe().expect("current exe");
    let bytes = std::fs::read(exe).expect("read exe");

    let f = extract(&bytes).expect("test binary is a valid PE");

    assert!(f.sections.count > 0);
    assert!(f.imports.count > 0);
    assert!(f.byte_entropy > 0.0);
    assert_eq!(f.flatten().len(), PeFeatures::feature_names().len());
}
