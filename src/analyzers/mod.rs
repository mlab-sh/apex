//! Analyzer trait and registry.

use crate::models::{AppType, Finding};
use std::path::Path;

pub trait Analyzer {
    /// Human-readable analyzer name (mirrors the Python `name` attribute).
    #[allow(dead_code)]
    fn name(&self) -> &'static str;
    /// Finding category slug (mirrors the Python `category` attribute).
    #[allow(dead_code)]
    fn category(&self) -> &'static str;
    fn can_analyze(&self, app_type: AppType) -> bool;
    fn analyze(&self, extracted: &Path, app_type: AppType, original: &Path) -> Vec<Finding>;
}

pub mod api_android;
pub mod binary_advanced;
pub mod binary_android;
pub mod cert_android;
pub mod dataflow;
pub mod firebase_cloud;
pub mod jar_aar;
pub mod manifest_android;
pub mod network_security;
pub mod permissions_android;
pub mod platform_android;
pub mod privacy;
pub mod sast_android;
pub mod secrets;
pub mod supply_chain;

/// Registered analyzers, in the same order as the Python scanner.
pub fn get_analyzers() -> Vec<Box<dyn Analyzer>> {
    vec![
        Box::new(manifest_android::AndroidManifestAnalyzer),
        Box::new(cert_android::AndroidCertAnalyzer),
        Box::new(network_security::NetworkSecurityAnalyzer),
        Box::new(sast_android::AndroidSastAnalyzer),
        Box::new(api_android::AndroidApiAnalyzer),
        Box::new(permissions_android::AndroidPermissionsAnalyzer),
        Box::new(binary_android::AndroidBinaryAnalyzer),
        Box::new(secrets::SecretsAnalyzer),
        Box::new(jar_aar::JarAarAnalyzer),
        Box::new(dataflow::DataFlowAnalyzer),
        Box::new(firebase_cloud::FirebaseCloudAnalyzer),
        Box::new(privacy::PrivacyAnalyzer),
        Box::new(binary_advanced::AdvancedBinaryAnalyzer),
        Box::new(platform_android::AndroidPlatformDeepAnalyzer),
        Box::new(supply_chain::SupplyChainAnalyzer),
    ]
}

