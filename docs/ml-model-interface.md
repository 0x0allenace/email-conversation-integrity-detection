# ML Model Interface and Contracts

## 1. Purpose

This document defines the shared interface for unsupervised anomaly-detection
models used by the Email Conversation Integrity Detection project.

The project currently implements four model adapters:

- Isolation Forest
- Local Outlier Factor (LOF)
- One-Class Support Vector Machine (One-Class SVM)
- Gaussian Mixture Model (GMM)

The shared interface is implemented in `src/ml/model_interface.py`, and the
adapters are implemented in their corresponding modules under `src/ml/`.
This document describes their common contracts and the implemented behavior.
It does not imply that model persistence, restoration, or production
detection-path integration is complete. The experimental evaluation
workflow is implemented separately.

The deterministic BEC-007 detection behavior and result contract must remain
unchanged.

## 2. Architecture

The experimental ML workflow includes:

1. Extraction of the 24 BEC-007 behavioral features.
2. Feature validation and dataset splitting using the implemented
   utilities; the calling workflow remains responsible for fitting learned
   preprocessing and models on training data only.
3. Shared preprocessing, including median imputation and six missingness
   indicators, producing 30 numeric features.
4. Model-specific preprocessing, including scaling where required.
5. Fitting and scoring through the implemented model adapters.
6. Consistent anomaly scores and Boolean predictions.

The shared preprocessor remains independent of model-specific scaling.
These ML components are separate from the deterministic production detection
path.

## 3. Common model operations

Each model adapter must expose the following operations:

### fit(training_data)

Fits the model using training observations only.

Any learned preprocessing parameters, model parameters, and decision
thresholds must be derived without using validation or test data.

The method must establish a fitted state only after successful completion.
A failed fit must not leave the adapter appearing successfully fitted.

### score_samples(data)

Returns one finite numeric anomaly score for each input observation.

Higher scores must always indicate greater anomalousness, regardless of
the underlying model's native score convention.

Calling this operation before a successful fit must raise a clear error.

Scoring must not refit the model or update learned parameters.

### predict(data)

Returns one Boolean decision per input observation:

- True: anomaly
- False: normal

Predictions must use the adapter's explicit decision threshold or documented
model-specific decision policy.

Calling this operation before a successful fit must raise a clear error.

The number and order of predictions must match the input observations.

## 4. Input contract

Model adapters consume transformed observations produced by
`BEC007Preprocessor`.

The transformed feature schema consists of:

- The 24 features defined by the ML feature extractor.
- Six missingness indicators defined by the ML preprocessing module.

The expected transformed observation therefore contains 30 numeric features.

Adapters must use a stable feature order and must not silently accept missing,
unexpected, non-numeric, Boolean-as-numeric, or non-finite feature values.

Permitted missing source values must already have been imputed by the shared
preprocessor. Adapters must not independently impute raw source features.

The original feature extraction and preprocessing contracts must remain
unchanged unless a separate reviewed change explicitly revises them.

## 5. Score direction and model-specific adapters

The shared contract requires that higher scores mean greater anomalousness.

Each adapter is responsible for converting its algorithm's native output
to this convention.

The implemented adapters follow this convention as follows:

- Isolation Forest negates its native `score_samples` output.
- LOF uses `novelty=True` to score unseen observations and negates its native
  `score_samples` output.
- One-Class SVM uses `StandardScaler` and negates its native `score_samples`
  output.
- GMM uses `StandardScaler` and converts log likelihood into negative
  log-likelihood anomaly scores.

The adapters therefore expose a common score direction while retaining
model-specific scoring behavior.

## 6. Threshold and prediction policy

Each adapter must make its decision threshold or decision policy explicit.

The interface standardizes prediction semantics, not the mathematical method
used to select a threshold. Each adapter must document its threshold or
decision policy and the assumptions behind it.

Thresholds and any learned threshold-calibration parameters must be determined
using training data only. Validation and test observations must not influence
the fitted model or its threshold. Any fixed configuration chosen in advance
must be documented separately from parameters learned from training data.

The implemented adapters use model-specific threshold policies:

- Isolation Forest, LOF, and One-Class SVM derive their decision thresholds
  from the fitted model's offset, using `math.nextafter` to align the
  threshold with the shared `score >= threshold` prediction contract.
- GMM selects its threshold from the configured quantile of training
  anomaly scores, using the configured contamination rate.

A threshold must not be assumed to have the same numeric meaning across
different model types. These threshold policies do not replace the need for
a separately documented and executed empirical evaluation protocol.

Predictions use the common Boolean contract:

- True: anomaly
- False: normal

## 7. Training, inference, and state

A successful fit establishes the adapter's fitted state.

Inference must reuse the fitted model and learned preprocessing parameters.
It must not refit on validation, test, or incoming inference observations.

A failed or incomplete fit must not be reported as successful. The shared
interface clears its fitted flag and threshold before attempting a fit and
marks the adapter fitted only after the fit and threshold validation succeed.
Callers must use the interface's fitted-state checks rather than assume that
a failed refit leaves the previous model ready for inference.

Model configuration and fitted thresholds can be inspected through the
implemented adapter interfaces where exposed. A complete persistence and
restore workflow has not been established by this interface contract and
must be documented and tested before persisted models are used for inference.

## 8. Validation and errors

Adapters must reject:

- Inference before successful fitting.
- Inputs with an incorrect feature schema.
- Missing or unexpected features.
- Non-numeric values, including Booleans used as numbers.
- NaN and positive or negative infinity.
- Invalid threshold or model configuration.

Errors must be explicit and must not silently produce normal predictions
for invalid input.

The interface and adapter tests cover empty inference batches. Continue to
verify this behavior when changing the shared contract or any adapter.

## 9. Reproducibility and testing

Where supported by the selected algorithm, random-state configuration must
be explicit.

Tests must verify:

- The common interface and fitted-state behavior.
- Stable input feature ordering.
- Score direction: higher means more anomalous.
- One score and one prediction per input observation.
- Threshold behavior at and around the decision boundary.
- No refitting during inference.
- Training-only fitting and threshold calibration.
- Invalid-input rejection.
- Reproducibility where the algorithm supports it.

Model-specific tests must also verify the actual selected library's behavior.
Mock-only tests are not sufficient to establish score direction or inference
semantics for a real model adapter.

## 10. Evaluation and label separation

Training must not depend on test labels.

For evaluation, synthetic attack scenarios may carry ground-truth labels in
a separate evaluation dataset or metadata structure. Those labels must not
be included in the model's feature input.

Evaluation metrics and threshold-selection procedures must be documented
separately from the model interface.

## 11. Scope

The shared interface and four model adapters are implemented, including
model-specific scaling where required, score normalization, and threshold
selection. Tests cover important interface and adapter behaviors, but the
existing tests do not establish that every threshold boundary is explicitly
tested for every model.

The experimental evaluation runner and metrics workflow are implemented
separately from the model interface. Model persistence and restoration,
and production detection-path integration, remain outstanding. The
evaluation protocol must be followed to assess empirical performance;
the presence of adapters and unit tests alone does not establish detection
effectiveness. The current synthetic benchmark does not establish
real-world detection effectiveness.

The deterministic BEC-007 detection behavior must remain unchanged.
