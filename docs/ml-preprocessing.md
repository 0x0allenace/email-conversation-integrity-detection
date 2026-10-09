# Machine Learning Preprocessing Policy

## 1. Purpose

This document defines the preprocessing policy for machine-learning-based
behavioral anomaly detection in Email Conversation Integrity Detection.

The initial feature representation is produced by the BEC-007 feature
extractor in `src/ml/feature_extractor.py`.

The preprocessing layer must preserve a stable feature schema, handle
legitimately unavailable historical information, reject invalid input, and
prevent information leakage between training and evaluation datasets.

This policy does not change the behavior, evidence, or result contract of
BEC-007.

## 2. Design Principles

The preprocessing pipeline follows these principles:

- Preserve the established feature names and ordering.
- Distinguish unavailable historical information from invalid current-message
  data.
- Never silently replace invalid values with invented observations.
- Record missingness where it may provide useful information about baseline
  availability.
- Learn imputation and scaling parameters from training data only.
- Apply the learned preprocessing parameters unchanged to validation,
  test, and inference data.
- Keep preprocessing deterministic and independently testable.
- Keep model-specific decisions outside the BEC-007 detection rule.

## 3. Feature Categories

### 3.1 Current-message features

The following features describe the analyzed message:

- `recipient_count`
- `cc_count`
- `attachment_present`

These values are expected to be available when the message has been parsed
and the BEC-007 behavioral result has been constructed.

If any of these values is unexpectedly missing, the preprocessing layer
must reject the incomplete input rather than impute it.

The `attachment_present` feature is binary and must contain either `0` or
`1`.

### 3.2 Historical baseline features

The following features depend on historical observations:

- `historical_recipient_count_median`
- `historical_cc_count_median`
- `historical_attachment_usage_rate`

These values may legitimately be unavailable when there are insufficient
valid historical observations.

A missing historical baseline must not automatically be interpreted as
normal behavior or malicious behavior.

### 3.3 Derived ratio features

The following features depend on current observations and historical
baselines:

- `frequency_interval_ratio`
- `recipient_count_ratio`
- `cc_count_ratio`

These ratios may legitimately be unavailable when the required interval
or historical baseline is missing or unsuitable for the calculation.

A missing ratio must not be replaced with zero merely because zero is
numerically convenient. Zero can represent a real value and therefore
has a different meaning from an unavailable value.

## 4. Missing-Value Policy

The preprocessing layer must distinguish two conditions:

1. **Invalid or incomplete input:** A required current-message feature is
   missing or malformed. Reject the input.
2. **Legitimately unavailable historical information:** A baseline or
   derived ratio cannot be calculated from available observations. Preserve
   the missingness information and handle it through the fitted
   preprocessing pipeline.

The six features that may legitimately be unavailable are:

- `frequency_interval_ratio`
- `historical_recipient_count_median`
- `recipient_count_ratio`
- `historical_cc_count_median`
- `cc_count_ratio`
- `historical_attachment_usage_rate`

These six cases are supported by the current BEC-007 implementation.
The preprocessing layer must validate that missing values occur only in
these permitted features. A missing value in any other feature must be
rejected.

The existing feature extractor permits `None` for scalar features, and
`prepare_bec_007_vector()` rejects `None` values. These existing contracts
must remain unchanged. The new preprocessing layer is responsible for
applying the stricter missing-value policy before vector preparation.

## 5. Missingness Indicators

The ML feature representation must include a missingness indicator for
each of the six features that may legitimately be unavailable:

- `frequency_interval_ratio_missing`
- `historical_recipient_count_median_missing`
- `recipient_count_ratio_missing`
- `historical_cc_count_median_missing`
- `cc_count_ratio_missing`
- `historical_attachment_usage_rate_missing`

Each indicator records whether its corresponding feature was unavailable
in the original input, before imputation. A value of `1` means the
original feature was missing; a value of `0` means it was present.

The original numeric feature must be imputed separately from its
missingness indicator.

The six indicators must be generated in a fixed, documented order and
consistently during training, evaluation, and inference. Their values
must reflect the original input, not the imputed values.

## 6. Avoiding Inconsistent Features

Some scalar features are mathematically or operationally related.

For example, `recipient_count_ratio` depends on the current recipient count
and historical recipient-count baseline. The CC ratio has a similar
relationship. `frequency_interval_ratio` depends on interval observations.

Imputing these values independently can create combinations that would
not occur in genuine observations.

The preprocessing implementation must therefore document how it handles
these relationships. It must not silently recalculate a ratio from imputed
values unless that behavior is explicitly designed, tested, and documented.

Where a ratio is unavailable, its missingness indicator must remain
available even after the numeric value has been imputed.

## 7. Training-Aware Preprocessing

Any imputation or scaling parameters must be learned from the training
partition only.

The intended workflow is:

1. Validate the input feature schema.
2. Separate training, validation, and test data using the evaluation
   protocol.
3. Fit missingness handling and imputation parameters on training data.
4. Fit scaling parameters on training data when scaling is required.
5. Transform validation and test data using the fitted parameters.
6. Reuse the same fitted preprocessing parameters during inference.

Validation and test observations must not contribute to the estimation of
imputation values or scaling parameters.

This prevents information leakage and supports reproducible evaluation.

## 8. Model Compatibility

The preprocessing layer must provide a consistent numeric feature
representation for the planned anomaly-detection models:

- Isolation Forest
- Local Outlier Factor (LOF)
- One-Class Support Vector Machine (One-Class SVM)
- Gaussian Mixture Model (GMM)

Model-specific constraints, including scaling requirements and inference
behavior, must be handled in the model integration layer.

The shared feature schema must not change silently between models or
between training and inference.

## 9. Validation Requirements

Before the preprocessing implementation is considered complete, tests
must verify that:

- Required current-message features cannot be missing.
- Legitimately unavailable historical features are handled according to
  this policy.
- Missingness indicators accurately represent the original input.
- Unexpected feature names and missing required feature names are rejected.
- Non-numeric, non-finite, and invalid binary values are rejected.
- Feature ordering remains deterministic.
- Preprocessing parameters are fitted only on training data.
- Validation, test, and inference data use the fitted training parameters.
- The original BEC-007 detection behavior and result contract remain
  unchanged.
- Existing regression tests continue to pass.

## 10. Scope

This document establishes the preprocessing policy. It does not implement
imputation, scaling, model training, model inference, or model evaluation.

Those capabilities must be introduced in separate, tested changes.
