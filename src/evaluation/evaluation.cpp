#include "evaluation/evaluation.h"
#include <iomanip>
#include <sstream>
namespace delta_nids::evaluation {
EvaluationMetrics evaluate(const std::vector<LabeledCase>& cases) {
    EvaluationMetrics result;
    for (const auto& item : cases) {
        if (item.expected_alert && item.observed_alert) ++result.true_positive;
        else if (!item.expected_alert && item.observed_alert) ++result.false_positive;
        else if (!item.expected_alert) ++result.true_negative;
        else ++result.false_negative;
    }
    const double positive = static_cast<double>(result.true_positive);
    const auto precision_denominator = result.true_positive + result.false_positive;
    const auto recall_denominator = result.true_positive + result.false_negative;
    result.precision = precision_denominator == 0 ? 0 : positive / static_cast<double>(precision_denominator);
    result.recall = recall_denominator == 0 ? 0 : positive / static_cast<double>(recall_denominator);
    result.f1 = (result.precision + result.recall) == 0 ? 0 : 2 * result.precision * result.recall / (result.precision + result.recall);
    return result;
}
std::string format(const EvaluationMetrics& metrics) {
    std::ostringstream output; output << std::fixed << std::setprecision(4)
        << "precision=" << metrics.precision << " recall=" << metrics.recall << " f1=" << metrics.f1;
    return output.str();
}
} // namespace delta_nids::evaluation
