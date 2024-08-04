
#include <gtest/gtest.h>
#include "jinjaTemplating/templating.h"

const nlohmann::json dataJson = R"(
    {
        "users": [
            {
                "name": "Manu",
                "age": 22,
                "address": {
                    "city": "Berlin",
                    "street": "Karl Marx",
                    "details": {
                        "global": ["Europe", "Germany"]
                    }
                },
                "hobbies": ["coding", "reading", "gaming"]
            },
            {
                "name": "John",
                "age": 18,
                "address": {
                    "city": "London",
                    "street": "Baker",
                    "details": {
                        "global": ["Europe", "UK"]
                    }
                },
                "hobbies": ["swimming", "reading", "gaming"]
            }
        ]
    }
)"_json;

const std::string contentString = R"(
        <!DOCTYPE html>
        <html>
            <head>
                <title>Test</title>
            </head>
            <body>
                {% for user in users %}
                    <h1>{{ user.name }}</h1>
                    <p>{{ user.address.city }}, {{ user.address.details.global[1] }}</p>
                    <p>{{ user.hobbies | join }}</p>
                    {% if user.age >= 18 %}
                        <p>Adult</p>
                    {% endif %}
                {% endfor %}
            </body>
        </html>
    )";

const std::string expected = R"(
        <!DOCTYPE html>
        <html>
            <head>
                <title>Test</title>
            </head>
            <body>
                    <h1>Manu</h1>
                    <p>Berlin, Germany</p>
                    <p>coding, reading, gaming</p>
                        <p>Adult</p>
                    <h1>John</h1>
                    <p>London, UK</p>
                    <p>swimming, reading, gaming</p>
                        <p>Adult</p>
            </body>
        </html>
    
)";


TEST(renderString, renderStringTest)
{
    Templating templating;
    std::string result = templating.RenderString(contentString, dataJson);
    
    EXPECT_EQ(result, expected);
}




int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}