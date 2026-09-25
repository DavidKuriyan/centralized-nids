#pragma once
#include <cstddef>
#include <string>
#include <vector>
namespace delta_nids::evaluation {
struct LabeledCase { std::string name; bool expected_alert = false; bool observed_alert = false; };
struct EvaluationMetrics { std::size_t true_positive=0, false_positive=0, true_negative=0, false_negative=0; double precision=0, recall=0, f1=0; };
[[nodiscard]] EvaluationMetrics evaluate(const std::vector<LabeledCase>& cases);
[[nodiscard]] std::string format(const EvaluationMetrics& metrics);
} // namespace delta_nids::evaluation
