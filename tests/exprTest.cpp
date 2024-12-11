#include "jinjaTemplating/my_expr/my_expr/my_expr.h"
#include <gtest/gtest.h>
#include <cmath>
#include <unordered_map>

// Helper functions
volatile double get_a() { return 3.1415926535; }
volatile double get_b() { return 2.7182818284; }
volatile double get_c() { return 1.6180339887; }

class ExpressionTest : public ::testing::Test {
protected:
    std::unordered_map<string_t, token_data_t> variables;

    void SetUp() override {
        variables = {
            {"a", get_a()},  // π
            {"b", get_b()},  // e
            {"c", get_c()},  // φ
            {"json_var", R"({
                "name": "John",
                "age": 30,
                "cars": [
                    {"name": "Ford", "models": ["Fiesta", "Focus"]},
                    {"name": "BMW", "models": ["320", "X3"]}
                ],
                "friends": ["Anna", "Peter", "Tom"]
            })"_json}
        };
    }
};

TEST_F(ExpressionTest, SimpleAddition) {
    expr e("1 + 2");
    e.set_variables(variables);
    e.compile();
    EXPECT_DOUBLE_EQ(e.eval().toNumber(), 3);
}

TEST_F(ExpressionTest, VariableArithmetic) {
    expr e("a * b + c");
    e.set_variables(variables);
    e.compile();
    double expected = get_a() * get_b() + get_c();
    EXPECT_DOUBLE_EQ(e.eval().toNumber(), expected);
}

TEST_F(ExpressionTest, SquareRootCalculation) {
    expr e("sqrt(a^2 + b^2)");
    e.set_variables(variables);
    e.compile();
    double expected = std::sqrt(get_a() * get_a() + get_b() * get_b());
    EXPECT_DOUBLE_EQ(e.eval().toNumber(), expected);
}

TEST_F(ExpressionTest, TrigonometricOperations) {
    expr e("sin(a) * cos(b)");
    e.set_variables(variables);
    e.compile();
    double expected = std::sin(get_a()) * std::cos(get_b());
    EXPECT_DOUBLE_EQ(e.eval().toNumber(), expected);
}

TEST_F(ExpressionTest, JSONAccess) {
    expr e("json_var.friends[2]");
    e.set_variables(variables);
    e.compile();
    EXPECT_EQ(e.eval().toString(true), "Tom");
}

TEST_F(ExpressionTest, JSONNestedAccess) {
    expr e("json_var.cars[0].models[1]");
    e.set_variables(variables);
    e.compile();
    EXPECT_EQ(e.eval().toString(true), "Focus");
}

TEST_F(ExpressionTest, StringConcatenation) {
    expr e("\"Hello, \" + \"World!\"");
    e.set_variables(variables);
    e.compile();
    EXPECT_EQ(e.eval().toString(true), "Hello, World!");
}

TEST_F(ExpressionTest, StringReplacement) {
    expr e("replace(\"The quick brown fox\", \"fox\", \"dog\")");
    e.set_variables(variables);
    e.compile();
    EXPECT_EQ(e.eval().toString(true), "The quick brown dog");
}

TEST_F(ExpressionTest, StringSplit) {
    expr e("split(\"apple,orange,banana\", \",\")");
    e.set_variables(variables);
    e.compile();
    auto result = e.eval().toJson().get<std::vector<std::string>>();
    std::vector<std::string> expected = {"apple", "orange", "banana"};
    EXPECT_EQ(result, expected);
}

TEST_F(ExpressionTest, JSONLength) {
    expr e("len(json_var.cars)");
    e.set_variables(variables);
    e.compile();
    EXPECT_DOUBLE_EQ(e.eval().toNumber(), 2);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
