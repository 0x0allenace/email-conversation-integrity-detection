# ML Model Adapter Design

## 1. Purpose

This document describes the design and implementation of the
unsupervised anomaly-detection model adapters used by Email Conversation
Integrity Detection.

The implemented models are:

- Isolation Forest
- Local Outlier Factor (LOF)
- One-Class Support Vector Machine (One-Class SVM)
- Gaussian Mixture Model (GMM)

This document extends `docs/ml-model-interface.md` and
`docs/ml-preprocessing.md`. The four adapters, their common interface,
and an experimental evaluation workflow are implemented. Model
persistence and production detection-path integration remain outstanding.
The synthetic benchmark does not establish real-world detection effectiveness.

The deterministic BEC-007 behavior, evidence, and result contract must
remain unchanged.

## 2. Architecture

The experimental ML processing flow is:

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

The implemented scaling policy is:

- Isolation Forest: no scaler is applied by the adapter.
- LOF: `StandardScaler` is used.
- One-Class SVM: `StandardScaler` is used.
- GMM: `StandardScaler` is used.

The adapters retain the fitted scaling state required for inference where
scaling is applied. The calling training workflow must ensure that any
learned preprocessing is fitted using training observations only and then
reused unchanged for validation, test, and inference observations. The
existence of the adapters does not by itself establish that the entire
workflow enforces this separation.

## 5. Score direction and threshold policies

Every adapter must convert native outputs to the common convention:
higher scores indicate greater anomalousness.

Threshold selection is model-specific in the implemented adapters.
Isolation Forest, LOF, and One-Class SVM derive thresholds from their fitted
model offsets, using `math.nextafter` to align threshold comparisons with
the shared `score >= threshold` prediction contract. GMM selects a threshold
from its training anomaly-score quantile using the configured contamination
rate.

The implemented evaluation workflow separates training, validation, and
test partitions, and its tests cover key leakage-prevention requirements.
Test data must remain reserved for final evaluation and must not influence
preprocessing, model fitting, feature selection, or threshold selection.
The synthetic benchmark does not establish real-world detection effectiveness.

A threshold is model-specific. Numeric thresholds must not be compared
directly across algorithms as though they had equivalent meanings.

### 5.1 Isolation Forest

The implemented adapter negates the native `score_samples` output so
larger values indicate greater anomalousness. Its threshold is derived from
the fitted model offset and adjusted using `math.nextafter` to align with
the common prediction comparison. The selected contamination configuration
and threshold behavior should be considered when interpreting results.

### 5.2 Local Outlier Factor

The implemented adapter uses `novelty=True` to score previously unseen
observations and negates the native `score_samples` output so larger values
indicate greater anomalousness. Its threshold is derived from the fitted
model offset and adjusted using `math.nextafter` to align with the common
prediction comparison.

### 5.3 One-Class SVM

The implemented adapter uses `StandardScaler` and negates the native
`score_samples` output so larger values indicate greater anomalousness.
Its threshold is derived from the fitted model offset and adjusted using
`math.nextafter` to align with the common prediction comparison. The `nu`
configuration remains a model parameter and should not be confused with
the shared interface's explicit threshold.

### 5.4 Gaussian Mixture Model

A GMM provides a density or log-likelihood measure rather than a native
anomaly decision in the same form as the other models.

The adapter must convert log-likelihood to an anomaly score, for example
by negating the log-likelihood so lower likelihood produces a higher
anomaly score.

The implemented adapter uses `StandardScaler`, scores observations using
negative log likelihood, and selects its threshold from the training-score
quantile determined by the configured contamination rate. It rejects a
fit when the GMM does not converge and validates the contamination
configuration. Component-count selection and empirical comparison still
belong to the documented evaluation workflow; test data must not be used
for model selection or threshold tuning.

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

A successful fit must establish the fitted state required by the shared
interface. The interface clears its fitted flag and threshold before a fit
attempt and marks the adapter fitted only after fitting and threshold
validation succeed.

If fitting fails, the adapter must not report itself as fitted. This does
not guarantee that every internal model or scaler object is reset; callers
must rely on the public fitted-state checks and must not infer that a
previous model remains ready for inference after a failed refit.

Inference must reuse the fitted model and fitted preprocessing state. It
must not learn new imputation values, scaling parameters, model parameters,
or thresholds from incoming observations.

Each adapter must support the common empty-inference behavior established
by the shared interface, returning empty score and prediction lists without
attempting model refitting.

The selected model library's behavior for empty batches must be handled
without violating the public interface.

## 8. Configuration and reproducibility

Reproducibility requires documenting or recording configuration such as:

- Algorithm name and library version.
- Feature schema and ordering.
- Scaling strategy and fitted scaler state.
- Model hyperparameters.
- Random-state configuration when supported.
- Threshold-selection method and fitted threshold.
- Training-data version or identifier, when the workflow records it.
- Fit status and relevant convergence diagnostics.

The adapter tests cover important configuration, fitting, scoring, and
validation behaviors, but the presence of adapters does not establish that
all experiment metadata is automatically recorded.

GMM rejects unsuccessful convergence rather than silently treating an
invalid or incomplete fit as successful.

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

The existing real-adapter tests cover core fitting, scoring, and validation
behavior. Test coverage should be maintained and expanded for the following
contracts, with gaps distinguished from verified behavior:

- Successful fitting on valid training observations.
- Rejection of empty training data.
- Explicit fitted-state behavior after failed fitting.
- Exact feature schema and deterministic feature ordering.
- Score count matching input observation count.
- Finite score validation and common score direction.
- Threshold behavior below, at, and above the threshold for each adapter;
  this full boundary coverage is not established for every model.
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

The four model adapters are implemented:

1. Isolation Forest uses native score normalization and offset-based
   thresholding.
2. LOF uses novelty detection, `StandardScaler`, and offset-based thresholding.
3. One-Class SVM uses `StandardScaler` and offset-based thresholding.
4. GMM uses `StandardScaler`, negative log-likelihood scoring, a
   training-score quantile threshold, and convergence validation.

Remaining work includes strengthening threshold-boundary test coverage
where needed, improving experiment metadata and reproducibility practices,
and implementing and testing model persistence. Further empirical
evaluation on representative, appropriately labeled email data is needed
before making claims about real-world detection effectiveness.

No adapter may change deterministic BEC-007 behavior or the shared 30-feature
schema.

## 12. Scope

This document defines the model-adapter integration policy. It does not add
model implementations, install dependencies, fit models, select final
hyperparameters, implement persistence, or establish final empirical
performance claims.

Those activities require separate implementation and evaluation steps.
