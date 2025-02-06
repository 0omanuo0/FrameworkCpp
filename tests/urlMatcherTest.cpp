#include <gtest/gtest.h>
#include <unordered_map>
#include <string>
#include <vector>
#include <stdexcept>
#include <regex>

#include "tools/complementary_server_functions.hpp"


// Define GTest cases

// ✅ Valid routes test
TEST(RouteMatchingTests, ValidRoutes) {
    std::vector<std::pair<std::string, std::string>> valid_routes = {
        {"/home/123/avatar/99.99", "/home/<id:int>/<img>/<price:float>"},
        {"/user/john/30", "/user/<name>/<age:int>"},
        {"/search/query_test", "/search/<query>"},
        {"/profile/etc/avatar", "/profile/<section>/<img>"},
        {"/product/45/details", "/product/<id:int>/details"},
        {"/data/true/45.67", "/data/<enabled:bool>/<value:float>"},
        {"/bool-test/false", "/bool-test/<flag:bool>"},
        {"/home/api", "/home/api"},
        {"/user/settings", "/user/settings"},
        {"/admin/dashboard", "/admin/dashboard"},
        {"/api/v1/data", "/api/v1/data"},
    };

    for (const auto &[testPath, route] : valid_routes) {
        std::unordered_map<std::string, server_tools::ParamValue> params;
        server_tools::routeRE compiledRoute = server_tools::_route_contains_params(route);
        EXPECT_TRUE(_match_path_with_route(testPath, compiledRoute, params));
    }
}

// ❌ Invalid routes test
TEST(RouteMatchingTests, InvalidRoutes) {
    std::vector<std::pair<std::string, std::string>> invalid_routes = {
        {"/home/api", "/home/apis"},
        {"/user/settings", "/user/setting"},
        {"/home/123/avatar/not-a-float", "/home/<id:int>/<img>/<price:float>"},
        {"/user//profile", "/user/<username>/<profile>"},
        {"/data/yes/123", "/data/<enabled:bool>/<id:int>"},
        {"/product/abc/details", "/product/<id:int>/details"},
    };

    for (const auto &[testPath, route] : invalid_routes) {
        std::unordered_map<std::string, server_tools::ParamValue> params;
        server_tools::routeRE compiledRoute = server_tools::_route_contains_params(route);
        EXPECT_FALSE(_match_path_with_route(testPath, compiledRoute, params));
    }
}

// ❌ Invalid route definitions (should throw exceptions)
TEST(RouteMatchingTests, InvalidRouteDefinitions) {
    std::vector<std::string> invalid_routes = {
        "/home/<name>/<section",        // Missing closing ">"
        "/profile/<user_id:int",        // Unclosed "<>"
        "/home/<id:int:float>",         // Double colons invalid
        "/test/<id:int>/<extra:>",      // Empty type
    };

    for (const auto &route : invalid_routes) {
        EXPECT_THROW(server_tools::_route_contains_params(route), std::runtime_error);
    }
}

// Main function for GTest
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}