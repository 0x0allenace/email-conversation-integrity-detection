# ML Model Interface and Contracts

## 1. Purpose

This document defines the shared interface for unsupervised anomaly-detection
models used by the Email Conversation Integrity Detection project.

The initial model adapters are planned for:

- Isolation Forest
- Local Outlier Factor (LOF)
- One-Class Support Vector Machine (One-Class SVM)
- Gaussian Mixture Model (GMM)

This document defines contracts, not model implementations. Model libraries,
training logic, scoring logic, and inference integration will be introduced
in separate tested changes.

The deterministic BEC-007 detection behavior and result contract must remain
unchanged.

## 2. Architecture

The intended pipeline is:

1. Deterministic BEC-007 behavioral detection.
2. ML-1 feature extraction.
3. ML-2 vector preparation and validation.
4. ML-3 shared preprocessing and missingness indicators.
5. Model-specific preprocessing, including scaling where required.
6. Model training or inference.
7. Consistent anomaly scores and predictions.

The shared preprocessor remains independent of model-specific scaling.

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

Examples of the required interpretation include:

- Isolation Forest: transform native scores as necessary to make larger
  values indicate greater anomalousness.
- LOF: use a supported inference mode for unseen observations and normalize
  the score direction.
- One-Class SVM: transform its decision-function output as necessary.
- GMM: a lower likelihood may be represented by a higher negative
  log-likelihood anomaly score.

These examples define score interpretation, not implementation details.
The selected library's exact API and behavior must be verified when each
adapter is implemented.

## 6. Threshold and prediction policy

Each adapter must make its decision threshold or decision policy explicit.

The interface standardizes prediction semantics, not the mathematical method
used to select a threshold. Each adapter must document its threshold or
decision policy and the assumptions behind it.

Thresholds and any learned threshold-calibration parameters must be determined
using training data only. Validation and test observations must not influence
the fitted model or its threshold. Any fixed configuration chosen in advance
must be documented separately from parameters learned from training data.

The model integration design must document how the threshold is selected,
including relevant configuration such as a contamination rate or training
score quantile where appropriate.

A threshold must not be assumed to have the same numeric meaning across
different model types.

Predictions use the common Boolean contract:

- True: anomaly
- False: normal

## 7. Training, inference, and state

A successful fit establishes the adapter's fitted state.

Inference must reuse the fitted model and learned preprocessing parameters.
It must not refit on validation, test, or incoming inference observations.

A failed or incomplete fit must not be reported as successful.

Model configuration and the fitted threshold must be inspectable or
reproducibly recorded by the eventual model integration layer.

The implementation must document how models are persisted and restored
before persistence is used in production inference.

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

Empty-batch behavior must be consistent across adapters and explicitly
tested when the interface is implemented.

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

This document does not implement model adapters, scaling, model training,
threshold calibration, model persistence, or evaluation.

Those capabilities will be added in separate, tested changes.

The deterministic BEC-007 detection behavior must remain unchanged.
