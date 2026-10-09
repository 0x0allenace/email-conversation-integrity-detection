# ML Model Adapter Design

## 1. Purpose

This document defines the integration requirements for the initial
unsupervised anomaly-detection model adapters used by Email Conversation
Integrity Detection.

The planned models are:

- Isolation Forest
- Local Outlier Factor (LOF)
- One-Class Support Vector Machine (One-Class SVM)
- Gaussian Mixture Model (GMM)

This document extends `docs/ml-model-interface.md` and
`docs/ml-preprocessing.md`. It specifies architecture and integration
requirements; it does not implement or train the models.

The deterministic BEC-007 behavior, evidence, and result contract must
remain unchanged.

## 2. Architecture

The intended processing flow is:

1. Analyze the message using the existing deterministic BEC-007 rule.
2. Extract the established 24 ML features.
3. Validate and preprocess the feature dictionary using the existing
   BEC007Preprocessor.
4. Produce the 30-feature transformed representation: 24 numeric features
   and six missingness indicators.
5. Apply model-specific preprocessing fitted on training data only.
6. Fit the selected anomaly model.
7. Select and retain an explicit decision threshold.
8. Convert native model outputs into the common anomaly-score direction.
9. Use the shared AnomalyModel interface for scoring and prediction.

Model-specific preprocessing must remain separate from shared missing-value
handling. Model adapters must not silently change the shared feature schema.

## 3. Shared adapter contract

Every adapter must implement the abstract operations defined by
`src/ml/model_interface.py`:

- `_fit_model(training_matrix)` fits the underlying model and returns a
  finite decision threshold.
- `_score_model(matrix)` returns one anomaly score per input row.

The inherited public operations provide:

- `fit(training_data)`
- `score_samples(data)`
- `predict(data)`
- `is_fitted`
- `threshold`

The public interface must retain these semantics:

- Each input row contains exactly the established 30 numeric features.
- Feature ordering is deterministic.
- Higher scores mean greater anomalousness.
- A score greater than or equal to the fitted threshold predicts an anomaly.
- `True` means anomaly; `False` means normal.
- Inference must not refit the model or preprocessing.
- Invalid inputs and invalid model outputs must raise explicit errors.

A model adapter must not override the common prediction semantics without
a separately reviewed change to the shared contract.

## 4. Model-specific preprocessing

The six missingness indicators are part of the model input and must not be
discarded implicitly.

Scaling must be treated as a fitted preprocessing operation where required.
Any scaler must be fitted on the training partition only and reused
unchanged for validation, testing, and inference.

The adapter or its dedicated preprocessing component must retain the
feature order and fitted preprocessing state required for inference.

The initial scaling policy is:

- Isolation Forest: begin without mandatory scaling; evaluate whether
  scaling is useful for the selected feature distributions.
- LOF: scale features because distance-based neighborhood calculations
  can be dominated by features with larger numeric ranges.
- One-Class SVM: scale features because its kernel and distance behavior
  are sensitive to feature magnitude.
- GMM: evaluate feature scaling explicitly; use a training-fitted scaler
  for the initial implementation so feature magnitudes do not arbitrarily
  dominate the fitted density model.

Any deviation from these initial choices must be justified and evaluated.
Scaling parameters must never be fitted using validation, test, or inference
data.

## 5. Score direction and threshold policies

Every adapter must convert native outputs to the common convention:
higher scores indicate greater anomalousness.

Threshold calibration must be explicit. The initial policy is to
derive thresholds from training-partition scores, unless a fixed threshold
was configured before model fitting. Validation data may be used for
documented model and hyperparameter selection, but must not be used to
calibrate the threshold under this policy. Test data must never be used
to select or tune the threshold.

A threshold is model-specific. Numeric thresholds must not be compared
directly across algorithms as though they had equivalent meanings.

### 5.1 Isolation Forest

Isolation Forest implementations commonly expose a decision function or
anomaly score with a direction that must be verified for the selected
library.

The adapter must transform the chosen native output so larger values mean
more anomalous behavior.

The implementation must document the selected contamination or threshold
policy. If the threshold is derived from training scores, it must be
calibrated from training observations only.

### 5.2 Local Outlier Factor

LOF must use a supported novelty-detection configuration for scoring
previously unseen observations. Training-set outlier-detection behavior
must not be assumed to provide equivalent inference semantics.

The adapter must verify the selected library's score direction and convert
its native novelty scores so larger values indicate greater anomalousness.

Any threshold derived from training scores must be selected using the
training partition only. The implementation must document how training
scores are obtained and how that choice relates to novelty scoring for
unseen observations.

### 5.3 One-Class SVM

The adapter must verify the selected library's decision-function convention
and transform scores as necessary so larger values indicate greater
anomalousness.

The implementation must document the role of configuration such as `nu`
and distinguish the model's native decision boundary from any additional
threshold calibration.

If a separate threshold is calibrated from scores, calibration must use
training observations only.

### 5.4 Gaussian Mixture Model

A GMM provides a density or log-likelihood measure rather than a native
anomaly decision in the same form as the other models.

The adapter must convert log-likelihood to an anomaly score, for example
by negating the log-likelihood so lower likelihood produces a higher
anomaly score.

The implementation must document its component-count selection policy,
covariance configuration, convergence checks, and threshold policy.

Any model selection or threshold calibration must follow the documented
training and validation protocol. Test data must not be used to select
components or calibrate the threshold.

## 6. Training and evaluation separation

Data must be partitioned before fitting any learned preprocessing,
model parameters, or threshold-calibration parameters.

The training partition may be used to fit:

- Shared imputation parameters.
- Model-specific scaling parameters.
- Model parameters.
- Training-score-based threshold calibration.

Validation data may be used for documented model selection or configuration
decisions, but must not be used to refit the final model or its preprocessing
during evaluation.

Test data is reserved for final evaluation. It must not influence
preprocessing, model fitting, feature selection, or threshold selection.

Synthetic ground-truth labels must be stored separately from model features.
Labels must not enter unsupervised training or inference input.

If a final model is retrained on combined training and validation data,
all learned preprocessing and threshold calibration must be refitted using
that same combined training set, and the untouched test set must remain
isolated.

## 7. Fitting, refitting, and inference

A successful fit must establish a complete and internally consistent state
containing the fitted model, required preprocessing state, configuration,
and threshold.

If fitting fails, the adapter must not report itself as fitted.

Inference must reuse the fitted model and fitted preprocessing state. It
must not learn new imputation values, scaling parameters, model parameters,
or thresholds from incoming observations.

Each adapter must support the common empty-inference behavior established
by the shared interface, returning empty score and prediction lists without
attempting model refitting.

The selected model library's behavior for empty batches must be handled
without violating the public interface.

## 8. Configuration and reproducibility

Each adapter must expose or record the configuration required to reproduce
its fitted behavior, including where applicable:

- Algorithm name and library version.
- Feature schema and ordering.
- Scaling strategy and fitted scaler state.
- Model hyperparameters.
- Random-state configuration when supported.
- Threshold-selection method and fitted threshold.
- Training-data version or identifier.
- Fit status and relevant convergence diagnostics.

GMM implementations must report unsuccessful convergence rather than
silently treating an invalid or incomplete fit as successful.

Random-state settings must be explicit where the selected implementation
supports them. Reproducibility expectations and limitations must be
documented for each model.

## 9. Persistence requirements

Persistence must be implemented separately from the initial adapter
contract.

Before persisted models are used in production inference, the implementation
must define a versioned artifact format that includes the model, required
preprocessing state, threshold, feature schema, and configuration.

Loading an artifact must validate compatibility with the current feature
schema and adapter version.

Persisted artifacts must be treated as trusted executable or serialized
objects only when their origin and integrity are verified. Unsafe or
untrusted serialized model files must not be loaded.

A persistence implementation must include round-trip tests confirming that
scores and predictions remain consistent after save and restore, within
documented numerical tolerances.

## 10. Adapter testing requirements

Each real adapter must have tests for:

- Successful fitting on valid training observations.
- Rejection of empty training data.
- Explicit fitted-state behavior after failed fitting.
- Exact feature schema and deterministic feature ordering.
- Score count matching input observation count.
- Finite score validation and common score direction.
- Threshold behavior below, at, and above the threshold.
- No refitting or state changes during inference.
- Correct reuse of fitted preprocessing parameters.
- Training-only threshold calibration.
- Reproducibility where supported.
- Library-specific inference semantics.
- Relevant invalid configurations and model convergence failures.

Tests must exercise the selected real model library. Mock-only tests are
not sufficient to establish the native score direction or inference behavior.

Synthetic fixtures should include normal-like observations and multiple
types of anomalous behavior. Evaluation labels may be used to assess results,
but must not be supplied as model features.

## 11. Implementation sequence

The adapters should be implemented and reviewed incrementally:

1. Confirm the selected library APIs and dependency policy.
2. Implement Isolation Forest as the initial reference adapter.
3. Test the real model's score direction, threshold behavior, and inference.
4. Implement LOF with explicit novelty-detection semantics.
5. Implement One-Class SVM with fitted scaling.
6. Implement GMM with density-based anomaly scoring and convergence checks.
7. Compare models under the same documented data-splitting and evaluation
   protocol.
8. Add persistence only after fitted-state and inference contracts are stable.

Each adapter must be introduced in a separate, tested change where practical.
No adapter may change deterministic BEC-007 behavior or the shared 30-feature
schema.

## 12. Scope

This document defines the model-adapter integration policy. It does not add
model implementations, install dependencies, fit models, select final
hyperparameters, implement persistence, or establish final empirical
performance claims.

Those activities require separate implementation and evaluation steps.
