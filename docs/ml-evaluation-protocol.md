# ML Evaluation Protocol

## 1. Purpose

This document defines the evaluation protocol for the initial
unsupervised anomaly-detection models used by Email Conversation
Integrity Detection.

The initial models are:

- Isolation Forest
- Local Outlier Factor (LOF)
- One-Class Support Vector Machine (One-Class SVM)
- Gaussian Mixture Model (GMM)

The purpose is to compare these models using a consistent dataset,
feature schema, data-splitting policy, metric definitions, and
reproducibility procedure.

This document defines the evaluation policy and required safeguards
for comparing the experimental anomaly-detection models.

The repository includes dataset-splitting utilities, shared feature
preprocessing, a common anomaly-model interface, and four model
adapters: Isolation Forest, Local Outlier Factor, One-Class SVM, and
Gaussian Mixture Model.

These components provide ML infrastructure, but they do not by
themselves establish that a complete comparative evaluation workflow,
metric-reporting implementation, or reproducible experiment-reporting
process is available. Those capabilities must be verified separately
and implemented where they remain absent.

The deterministic BEC-007 detection behavior must remain unchanged.

## 2. Evaluation objectives

The evaluation must establish:

- Whether each model can identify synthetic anomalous email behaviour.
- How many anomalous observations are detected.
- How often normal observations are incorrectly flagged.
- How model performance differs across the selected algorithms.
- Whether results can be reproduced using the recorded configuration.

The evaluation must not assume that an unsupervised model will
achieve useful detection performance merely because it produces
anomaly scores.

Performance claims must be based on measured results.

## 3. Dataset contract

Each observation must contain:

1. An identifier used to track the observation.
2. The original BEC-007 feature dictionary.
3. Ground-truth evaluation metadata stored separately from features.

The ground-truth label must identify whether the observation represents
normal behaviour or a known synthetic anomaly.

The initial binary evaluation convention is:

- `0`: normal observation.
- `1`: anomalous observation.

Labels and metadata must never be included in the model feature dictionary.

The identifier and label must not be passed to the anomaly model.

Every original feature dictionary must conform to the established
24-feature BEC-007 schema. The shared preprocessor must produce the
established 30-feature representation, including six missingness
indicators.

The evaluation implementation must validate dataset schemas and labels
before fitting models.

### 3.1 Record representation

The implementation must keep observation identifiers, feature dictionaries,
and ground-truth labels in separate fields.

The dataset-splitting layer must preserve the association between each
observation and its label without inserting identifiers or labels into
the feature dictionary.

Model input must be constructed exclusively from the validated feature
dictionary after shared preprocessing.

The implementation must reject unsupported label values rather than
silently converting arbitrary values to binary labels.

## 4. Dataset splitting

The dataset must be partitioned before fitting any learned preprocessing,
model parameters, or threshold-calibration parameters.

The evaluation workflow must support separate:

- Training partition.
- Validation partition, when model selection is required.
- Test partition.

The test partition must remain isolated until final evaluation.

The split policy must document the random seed, partition proportions,
and any grouping or temporal constraints.

If multiple observations originate from the same email conversation,
user, or simulated attack campaign, the evaluation design must consider
whether splitting those related observations across partitions would
cause information leakage.

Where the research question concerns detection of previously unseen
conversations, users, or attack campaigns, an appropriate group-based
split must be used.

Where the research question concerns future observations, a temporal
split must be considered instead of relying only on random partitioning.

The selected split strategy must match the intended research question
and be recorded with the evaluation results.

## 5. Preprocessing and model fitting

The shared BEC007Preprocessor must be fitted using training features only.

Its learned imputation values must be reused unchanged for validation
and test observations.

Any model-specific scaler must also be fitted using training observations
only and reused unchanged during inference and evaluation.

Each anomaly model must be fitted using training features without
ground-truth labels.

Validation labels may be used to evaluate candidate configurations
or support documented model-selection decisions. They must not be used
to refit the final evaluation model or its preprocessing.

The test partition must not influence:

- Imputation values.
- Scaling parameters.
- Model fitting.
- Feature selection.
- Hyperparameter selection.
- Threshold selection or calibration.

No learned preprocessing operation may be fitted on the complete
dataset before splitting.

## 6. Threshold policy

Every model must use an explicit, documented decision threshold.

The evaluation output must record:

- Model name.
- Threshold value.
- Threshold-selection method.
- Relevant model configuration.
- Training-data identifier or version.

The existing adapters use model-specific threshold policies. The
evaluation runner must preserve those policies unless a separate,
reviewed change establishes a common calibration strategy.

The native decision boundary and any additional threshold calibration
must not be treated as interchangeable without justification.

If a common threshold-calibration strategy is introduced later, it
must be defined independently of the test partition and applied
consistently to the models being compared.

Thresholds must never be tuned to maximize performance on the test set.

Numeric thresholds must not be compared directly across different
algorithms as though they had equivalent meanings.

## 7. Score and prediction conventions

All adapters must follow the shared interface:

- Higher scores indicate greater anomalousness.
- `True` predictions indicate anomalies.
- `False` predictions indicate normal observations.
- A score greater than or equal to the fitted threshold predicts
  an anomaly.

The evaluation runner must validate that each model returns exactly
one finite score and one prediction for every evaluated observation.

The ordering of scores and predictions must match the ordering of
the input observations.

The runner must not silently reverse score directions or modify
model thresholds.

## 8. Evaluation metrics

The initial evaluation must calculate the following metrics.

### 8.1 Precision

The proportion of predicted anomalies that are truly anomalous.

Precision is undefined when no observations are predicted anomalous.
The implementation must document how this case is represented.

### 8.2 Recall

The proportion of truly anomalous observations correctly identified.

Recall is undefined when the evaluation partition contains no
anomalous observations. The implementation must document how this
case is represented.

### 8.3 F1 score

The harmonic mean of precision and recall, using a documented
zero-division policy.

### 8.4 False-positive rate

The proportion of normal observations incorrectly classified as
anomalous.

The implementation must document how the metric is represented
when the evaluation partition contains no normal observations.

### 8.5 Precision-recall area under the curve

Where the evaluation data contains both classes and continuous
anomaly scores are available, calculate average precision as the
initial precision-recall ranking metric.

The report must identify the exact metric implementation and must
not describe average precision as though it were necessarily the
trapezoidal area under a precision-recall curve.

Ranking metrics evaluate score ordering rather than a single
thresholded prediction.

### 8.6 Confusion matrix

Report true positives, false positives, true negatives, and
false negatives alongside the derived metrics.

Metrics must be calculated using ground-truth labels only after
model scores and predictions have been produced.

## 9. Model comparison

All models in a comparison must use the same evaluation observations
and ground-truth labels.

The comparison must record any differences in preprocessing,
threshold selection, algorithm configuration, or supported inference
semantics.

Results must not be presented as a controlled comparison if the
evaluation conditions differ materially.

Report the individual model results before drawing conclusions.

No model should be declared superior without reference to the
measured metrics, experimental conditions, and relevant limitations.

## 10. Reproducibility

Each evaluation run must record, where applicable:

- Dataset identifier or version.
- Dataset generation seed.
- Partitioning strategy and seed.
- Training, validation, and test counts.
- Number of normal and anomalous observations in each partition.
- Feature schema version.
- Shared preprocessing configuration and fitted state.
- Model name and library version.
- Model hyperparameters and random-state configuration.
- Threshold-selection method and fitted threshold.
- Evaluation metric values.
- Relevant warnings, errors, or convergence diagnostics.

Repeated runs should use the same dataset and configuration when
reproducibility is being tested.

Any nondeterministic behaviour or numerical variation must be documented.

## 11. Required evaluation safeguards

The implementation must ensure that:

- Labels never enter model feature inputs.
- Data is split before fitting preprocessing.
- Training-only learned state is reused during inference.
- Test data does not influence model or threshold selection.
- Empty or invalid datasets produce explicit errors where required.
- Undefined metrics are handled according to documented policies.
- Scores and predictions preserve observation ordering.
- Evaluation results identify the model and threshold policy used.

The evaluation pipeline must not modify the existing deterministic
BEC-007 rule contract or the shared 30-feature model schema.

## 12. Implementation status and remaining work

The following ML infrastructure is implemented:

1. Dataset-splitting utilities supporting stratified random and
   group-based splitting.
2. Shared preprocessing that validates the original 24-feature
   schema and produces the 30-feature representation.
3. A common anomaly-model interface with standardized score and
   prediction conventions.
4. Four model adapters: Isolation Forest, Local Outlier Factor,
   One-Class SVM, and Gaussian Mixture Model.

The following evaluation capabilities remain to be verified in the
repository and implemented where absent:

1. A validated evaluation-dataset loader and complete dataset contract.
2. An end-to-end evaluation runner that uses the existing utilities
   without data leakage.
3. Metric calculation and reporting for the metrics defined in Section 8.
4. Consistent comparison reports for all four models.
5. Experiment metadata and reproducibility reporting.
6. End-to-end tests covering leakage prevention, metric edge cases,
   observation ordering, and reproducibility.
7. A final full-suite test run before the evaluation milestone is
   considered complete.

The existence of individual utilities and adapters must not be
interpreted as evidence that the complete evaluation workflow has
been implemented or that the models have demonstrated useful
detection performance.

## 13. Scope

This protocol defines how the initial anomaly-detection models are
to be evaluated and what safeguards the evaluation must satisfy.

It documents the evaluation requirements; it is not itself an
evaluation runner and does not establish empirical model performance.

Final dataset generation, complete evaluation orchestration, metric
reporting, experiment tracking, and persistence must be implemented
or verified separately. Any performance claims must be supported
by measured results from a documented evaluation.
