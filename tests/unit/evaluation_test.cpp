#include "evaluation/evaluation.h"
#include <cassert>
int main() {
    using namespace delta_nids::evaluation;
    const auto result = evaluate({{"positive",true,true},{"false alarm",false,true},{"negative",false,false},{"miss",true,false}});
    assert(result.true_positive == 1 && result.false_positive == 1 && result.true_negative == 1 && result.false_negative == 1);
    assert(result.precision == 0.5 && result.recall == 0.5 && result.f1 == 0.5);
    const auto empty = evaluate({}); assert(empty.precision == 0 && empty.recall == 0 && empty.f1 == 0);
    return 0;
}
