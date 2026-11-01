//! Windside scoring (docs/windside.md section 6): load a model directory
//! and score feature rows from the native LightGBM text model.
//!
//! The text model is trees of `fval <= threshold` splits over positional
//! features (column order is the manifest's `feature_names`); the loader
//! refuses anything else. A row scores only at or above
//! [`TURNS_HELD_FLOOR`]; below it the row is skipped, never defaulted.

use crate::rules::features;
use std::collections::HashMap;
use std::path::Path;

/// Rows below this many held turns are not scored (windside §6: the
/// cold-start floor). Training is unchanged.
pub const TURNS_HELD_FLOOR: f32 = 5.0;

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad manifest: {0}")]
    Manifest(String),
    #[error("bad model: {0}")]
    Model(String),
}

/// The training manifest: versions, column order, per-surface thresholds.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub model_version: String,
    pub features_version: u32,
    pub feature_names: Vec<String>,
    /// Surface name to decision threshold.
    pub thresholds: HashMap<String, f64>,
}

#[derive(serde::Deserialize)]
struct ManifestWire {
    model_version: String,
    features_version: u32,
    feature_names: Vec<String>,
    #[serde(default)]
    thresholds: HashMap<String, ThresholdWire>,
}

#[derive(serde::Deserialize)]
struct ThresholdWire {
    threshold: f64,
}

pub fn load_manifest(dir: &Path) -> Result<Manifest, LoadError> {
    let text = std::fs::read_to_string(dir.join("manifest.json"))?;
    let w: ManifestWire =
        serde_json::from_str(&text).map_err(|e| LoadError::Manifest(e.to_string()))?;
    if w.features_version != features::VERSION {
        return Err(LoadError::Manifest(format!(
            "features_version {} != leesided {}",
            w.features_version,
            features::VERSION
        )));
    }
    if w.feature_names != features::NAMES {
        return Err(LoadError::Manifest(
            "feature_names differ from leesided's: columns would misalign".to_string(),
        ));
    }
    Ok(Manifest {
        model_version: w.model_version,
        features_version: w.features_version,
        feature_names: w.feature_names,
        thresholds: w
            .thresholds
            .into_iter()
            .map(|(k, v)| (k, v.threshold))
            .collect(),
    })
}

/// One tree: parallel arrays over the internal nodes, leaf values below.
/// A negative child `c` names leaf `!c`.
#[derive(Debug, Clone)]
struct Tree {
    split_feature: Vec<usize>,
    threshold: Vec<f64>,
    gain: Vec<f64>,
    left: Vec<i32>,
    right: Vec<i32>,
    leaf: Vec<f64>,
}

/// The parsed text model: binary trees over positional features.
#[derive(Debug, Clone)]
pub struct NativeModel {
    trees: Vec<Tree>,
}

fn words(line: &str) -> Result<Vec<&str>, LoadError> {
    line.split_once('=')
        .map(|(_, v)| v.split_whitespace().collect())
        .ok_or_else(|| LoadError::Model(format!("bad line: {line}")))
}

fn parse_tree(block: &[&str]) -> Result<Tree, LoadError> {
    let get = |key: &str| {
        block
            .iter()
            .find(|l| l.starts_with(key))
            .map(|l| words(l))
            .transpose()
    };
    let num_leaves: usize = get("num_leaves=")?
        .and_then(|v| v.first().copied())
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| LoadError::Model("tree lacks num_leaves".to_string()))?;
    if num_leaves == 0 {
        return Err(LoadError::Model("tree has no leaves".to_string()));
    }
    let num_cat: u32 = get("num_cat=")?
        .and_then(|v| v.first().copied())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if num_cat != 0 {
        return Err(LoadError::Model(
            "categorical splits are not supported".to_string(),
        ));
    }
    let split_feature: Vec<usize> = get("split_feature=")?
        .unwrap_or_default()
        .iter()
        .map(|v| v.parse())
        .collect::<Result<_, _>>()
        .map_err(|_| LoadError::Model("bad split_feature".to_string()))?;
    let threshold: Vec<f64> = get("threshold=")?
        .unwrap_or_default()
        .iter()
        .map(|v| v.parse())
        .collect::<Result<_, _>>()
        .map_err(|_| LoadError::Model("bad threshold".to_string()))?;
    let gain: Vec<f64> = get("split_gain=")?
        .unwrap_or_default()
        .iter()
        .map(|v| v.parse())
        .collect::<Result<_, _>>()
        .map_err(|_| LoadError::Model("bad split_gain".to_string()))?;
    let decision: Vec<i32> = get("decision_type=")?
        .unwrap_or_default()
        .iter()
        .map(|v| v.parse())
        .collect::<Result<_, _>>()
        .map_err(|_| LoadError::Model("bad decision_type".to_string()))?;
    if decision.iter().any(|d| *d != 2) {
        return Err(LoadError::Model(
            "only `<=' splits (decision_type 2) are supported".to_string(),
        ));
    }
    let child = |key: &str| {
        get(key).and_then(|v| {
            v.unwrap_or_default()
                .iter()
                .map(|c| c.parse::<i32>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| LoadError::Model(format!("bad {key}")))
        })
    };
    let left = child("left_child=")?;
    let right = child("right_child=")?;
    let leaf: Vec<f64> = get("leaf_value=")?
        .ok_or_else(|| LoadError::Model("tree lacks leaf_value".to_string()))?
        .iter()
        .map(|v| v.parse())
        .collect::<Result<_, _>>()
        .map_err(|_| LoadError::Model("bad leaf_value".to_string()))?;
    let n = num_leaves - 1;
    if split_feature.len() != n
        || threshold.len() != n
        || left.len() != n
        || right.len() != n
        || leaf.len() != num_leaves
    {
        return Err(LoadError::Model(
            "tree arrays disagree in length".to_string(),
        ));
    }
    Ok(Tree {
        split_feature,
        threshold,
        gain,
        left,
        right,
        leaf,
    })
}

pub fn parse_model(text: &str, n_features: usize) -> Result<NativeModel, LoadError> {
    let mut max_idx: Option<usize> = None;
    let mut binary = false;
    let mut trees = Vec::new();
    let mut block: Vec<&str> = Vec::new();
    let mut in_tree = false;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if line.starts_with("Tree=") {
            if in_tree {
                trees.push(parse_tree(&block)?);
                block.clear();
            }
            in_tree = true;
            continue;
        }
        if in_tree {
            block.push(line);
        } else if let Some(v) = line.strip_prefix("max_feature_idx=") {
            max_idx = Some(
                v.parse()
                    .map_err(|_| LoadError::Model("bad max_feature_idx".to_string()))?,
            );
        } else if line.starts_with("objective=") && line.contains("binary") {
            binary = true;
        }
    }
    if in_tree {
        trees.push(parse_tree(&block)?);
    }
    if !binary {
        return Err(LoadError::Model("not a binary objective".to_string()));
    }
    match max_idx {
        Some(m) if m + 1 == n_features => {}
        _ => {
            return Err(LoadError::Model(format!(
                "max_feature_idx {max_idx:?} != {n_features} columns"
            )));
        }
    }
    if trees.is_empty() {
        return Err(LoadError::Model("no trees".to_string()));
    }
    for t in &trees {
        if t.split_feature.iter().any(|f| *f >= n_features) {
            return Err(LoadError::Model("split_feature out of range".to_string()));
        }
    }
    Ok(NativeModel { trees })
}

fn sigmoid(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}

fn walk(tree: &Tree, x: &[f32], mut gains: Option<&mut [f64]>) -> f64 {
    let mut node = 0usize;
    loop {
        if node >= tree.split_feature.len() {
            // A single-leaf tree has no splits: node 0 is leaf 0.
            return tree.leaf[0];
        }
        let f = tree.split_feature[node];
        // `<=' with the decision on the left. NaN compares false and
        // goes right, as in LightGBM with no missing values in training
        // (features.rs never emits NaN; the dataset carries none).
        let go_left = f < x.len() && (x[f] as f64) <= tree.threshold[node];
        if let Some(g) = gains.as_mut() {
            g[f] += tree.gain[node];
        }
        let child = if go_left {
            tree.left[node]
        } else {
            tree.right[node]
        };
        if child < 0 {
            return tree.leaf[(!child) as usize];
        }
        node = child as usize;
    }
}

/// The malicious probability: sigmoid over the leaf sum.
pub fn predict(model: &NativeModel, x: &[f32]) -> f64 {
    sigmoid(model.trees.iter().map(|t| walk(t, x, None)).sum())
}

/// The three features with the most split gain along this row's taken
/// paths. Path gain, not SHAP: an account of where this row went.
pub fn top3(model: &NativeModel, names: &[String], x: &[f32]) -> Vec<(String, f64)> {
    let mut gains = vec![0.0; names.len().max(x.len())];
    for t in &model.trees {
        walk(t, x, Some(&mut gains));
    }
    let mut order: Vec<usize> = (0..names.len().min(x.len())).collect();
    order.sort_by(|a, b| {
        gains[*b]
            .partial_cmp(&gains[*a])
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    order
        .into_iter()
        .filter(|i| gains[*i] > 0.0)
        .take(3)
        .map(|i| (names[i].clone(), gains[i]))
        .collect()
}

/// A loaded model directory: manifest plus native model.
pub struct Loaded {
    pub manifest: Manifest,
    pub model: NativeModel,
    turns_held_idx: usize,
}

pub fn load(dir: &Path) -> Result<Loaded, LoadError> {
    let manifest = load_manifest(dir)?;
    let text = std::fs::read_to_string(dir.join("model.txt"))?;
    let model = parse_model(&text, manifest.feature_names.len())?;
    let turns_held_idx = features::NAMES
        .iter()
        .position(|n| *n == "turns_held")
        .ok_or_else(|| LoadError::Model("leesided has no turns_held".to_string()))?;
    Ok(Loaded {
        manifest,
        model,
        turns_held_idx,
    })
}

impl Loaded {
    /// Score one feature row, or `None` below the cold-start floor.
    /// Returns the probability and the top-3 path-gain JSON.
    pub fn score_row(&self, values: &[f32]) -> Option<(f64, String)> {
        if values.get(self.turns_held_idx).copied().unwrap_or(0.0) < TURNS_HELD_FLOOR {
            return None;
        }
        let p = predict(&self.model, values);
        let top = top3(&self.model, &self.manifest.feature_names, values)
            .iter()
            .map(|(n, g)| serde_json::json!({"name": n, "path_gain": g}))
            .collect::<Vec<_>>();
        Some((
            p,
            serde_json::to_string(&top).unwrap_or_else(|_| "[]".to_string()),
        ))
    }

    pub fn threshold(&self, surface: Option<&str>) -> Option<f64> {
        surface.and_then(|s| self.manifest.thresholds.get(s).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TINY: &str = "tree
version=v4
num_class=1
num_tree_per_iteration=1
label_index=0
max_feature_idx=1
objective=binary sigmoid:1
feature_names=A B
feature_infos=A B
tree_sizes=100

Tree=0
num_leaves=2
num_cat=0
split_feature=0
split_gain=1.5
threshold=0.5
decision_type=2
left_child=-1
right_child=-2
leaf_value=2.0 -2.0
leaf_weight=1 1
leaf_count=10 10
internal_value=0
internal_weight=2
internal_count=20
is_linear=0
shrinkage=1
";

    #[test]
    fn tiny_model_scores_by_hand() {
        let m = parse_model(TINY, 2).unwrap();
        assert_eq!(m.trees.len(), 1);
        // sigmoid(2) left of the split, sigmoid(-2) right of it.
        assert!((predict(&m, &[0.25, 0.0]) - 0.8807970779778823).abs() < 1e-12);
        assert!((predict(&m, &[0.75, 0.0]) - 0.11920292202211755).abs() < 1e-12);
        // On the threshold goes left (`<='), and NaN goes right.
        assert!((predict(&m, &[0.5, 0.0]) - 0.8807970779778823).abs() < 1e-12);
        assert!((predict(&m, &[f32::NAN, 0.0]) - 0.11920292202211755).abs() < 1e-12);
        let top = top3(&m, &["A".to_string(), "B".to_string()], &[0.25, 0.0]);
        assert_eq!(top, vec![("A".to_string(), 1.5)]);
    }

    #[test]
    fn loader_refuses_what_it_cannot_evaluate() {
        assert!(parse_model(&TINY.replace("decision_type=2", "decision_type=1"), 2).is_err());
        assert!(parse_model(&TINY.replace("num_cat=0", "num_cat=1"), 2).is_err());
        assert!(parse_model(
            &TINY.replace("objective=binary sigmoid:1", "objective=regression"),
            2
        )
        .is_err());
        assert!(parse_model(TINY, 3).is_err());
    }
}
