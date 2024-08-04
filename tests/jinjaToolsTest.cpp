

#include <gtest/gtest.h>
#include "jinjaTemplating/tools.h"

// TESTS FOR ADITIONAL TOOLS FUNCTIONS REQUIRED FOR JINJA TEMPLATING

// Test for accessJsonValue function
TEST(accessJsonValue, accessJsonValueTest)
{
    nlohmann::json data = {
        {"name", "Manu"},
        {"age", 22},
        {"address", {
            {"city", "Berlin"},
            {"street", "Karl Marx Str."},
            {"details", {
                {"global", {"Europe", "Germany"}},
                {"zip", 12345}
            }}
        }},
        {"hobbies", {"coding", "reading", "gaming"}}
    };

    EXPECT_EQ(accessJsonValue(data, "name"), "Manu");
    EXPECT_EQ(accessJsonValue(data, "age"), 22);
    EXPECT_EQ(accessJsonValue(data, "address.city"), "Berlin");
    EXPECT_EQ(accessJsonValue(data, "address.street"), "Karl Marx Str.");
    EXPECT_EQ(accessJsonValue(data, "address.details.global[0]"), "Europe");
    EXPECT_EQ(accessJsonValue(data, "address.details.global[1]"), "Germany");
    EXPECT_EQ(accessJsonValue(data, "address.details.zip"), 12345);
    EXPECT_EQ(accessJsonValue(data, "hobbies[0]"), "coding");
    EXPECT_EQ(accessJsonValue(data, "hobbies[1]"), "reading");
    EXPECT_EQ(accessJsonValue(data, "hobbies[2]"), "gaming");
}

// Test for __preprocessExpression function
// check if the expression has something like (filters or functions)
// length|sum|length|capitalize|lower|upper|first|last|reverse|sort|str|join
TEST(preprocessExpression, preprocessExpressionTest)
{
    nlohmann::json data = {
        {"name", "Manu"},
        {"age", 22},
        {"address", {
            {"city", "Berlin"},
            {"street", "Karl Marx Str."},
            {"details", {
                {"global", {"Europe", "Germany"}},
                {"zip", 12345}
            }}
        }},
        {"hobbies", {"coding", "reading", "gaming"}}
    };

    std::string expression = "name|length";
    __preprocessExpression(expression, data);
    EXPECT_EQ(expression, "4");

    expression = "name|capitalize";
    __preprocessExpression(expression, data);
    EXPECT_EQ(expression, "Manu");

    expression = "name|lower";
    __preprocessExpression(expression, data);
    EXPECT_EQ(expression, "manu");

    expression = "name|upper";
    __preprocessExpression(expression, data);
    EXPECT_EQ(expression, "MANU");

    expression = "name|first";
    __preprocessExpression(expression, data);
    EXPECT_EQ(expression, "M");

    expression = "name|last";
    __preprocessExpression(expression, data);
    EXPECT_EQ(expression, "u");

    expression = "name|reverse";
    __preprocessExpression(expression, data);
    EXPECT_EQ(expression, "unaM");

    expression = "hobbies|sort";
    __preprocessExpression(expression, data);
    EXPECT_EQ(expression, "[\"coding\",\"gaming\",\"reading\"]");

    expression = "hobbies";
    __preprocessExpression(expression, data);
    EXPECT_EQ(expression, "[\"coding\",\"reading\",\"gaming\"]");

    expression = "address.details.global|join";
    __preprocessExpression(expression, data);
    EXPECT_EQ(expression, "Europe, Germany");
}

// Test for __evaluateExpression function
TEST(evaluateExpression, evaluateExpressionTest)
{
    nlohmann::json data = R"(
        {"data" : [
            {
                "name" : "Manu",
                "age" : 22
            },
            {
                "name" : "John",
                "age" : 25
            }
        ]}
    )"_json;

    std::string expression = "data[0].age + data[1].age";
    EXPECT_EQ(__evaluateExpression(expression, data), 47);

    expression = "data[0].age * data[1].age";
    EXPECT_EQ(__evaluateExpression(expression, data), 550);

    expression = "data[0].name|length + data[1].name|length";
}

// Test for process_range function
TEST(process_range, process_rangeTest)
{
    nlohmann::json data = R"(
        {"data" : [
            {
                "name" : "Manu",
                "age" : 22
            },
            {
                "name" : "John",
                "age" : 25
            }
        ]}
    )"_json;

    std::string iterable = "range(5)";
    auto [n, m] = process_range(iterable, data);
    EXPECT_EQ(n, 0);
    EXPECT_EQ(m, 5);

    iterable = "range(1, 5)";
    auto [n1, m1] = process_range(iterable, data);
    EXPECT_EQ(n1, 1);
    EXPECT_EQ(m1, 5);

    iterable = "range(1, data[0].age + data[1].age)";
    auto [n2, m2] = process_range(iterable, data);
    EXPECT_EQ(n2, 1);
    EXPECT_EQ(m2, 47);

    iterable = "range(data[0].age, data[1].age)";
    auto [n3, m3] = process_range(iterable, data);
    EXPECT_EQ(n3, 22);
    EXPECT_EQ(m3, 25);

}

// Test for convertToMap function
TEST(convertToMap, convertToMapTest)
{
    nlohmann::json data = R"(
        {
            "name" : "Manu",
            "age" : 22,
            "address" : {
                "city" : "Berlin",
                "street" : "Karl Marx Str.",
                "details" : {
                    "global" : ["Europe", "Germany"],
                    "zip" : 12345
                }
            },
            "hobbies" : ["coding", "reading", "gaming"]
        }
    )"_json;

    auto rmap = convertToMap(data);
    EXPECT_EQ(rmap["name"], "Manu");
    EXPECT_EQ(rmap["age"], 22);
    EXPECT_EQ(rmap["address"]["city"], "Berlin");
    EXPECT_EQ(rmap["address"]["street"], "Karl Marx Str.");
    EXPECT_EQ(rmap["address"]["details"]["global"][0], "Europe");
    EXPECT_EQ(rmap["address"]["details"]["global"][1], "Germany");
    EXPECT_EQ(rmap["address"]["details"]["zip"], 12345);
    EXPECT_EQ(rmap["hobbies"][0], "coding");
    EXPECT_EQ(rmap["hobbies"][1], "reading");
    EXPECT_EQ(rmap["hobbies"][2], "gaming");
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}