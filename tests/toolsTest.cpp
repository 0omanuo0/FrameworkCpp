#include "gtest/gtest.h"
#include "tools/idGenerator.h"
#include "tools/url_encoding.h"

TEST(ToolsTest, generate_uuid_v4)
{
    std::string uuid = uuid::generate_uuid_v4();
    ASSERT_EQ(uuid.size(), 36);
}

TEST(ToolsTest, JWT)
{
    idGenerator idGen("test");
    std::string token = idGen.generateJWT("test");
    ASSERT_EQ(token.size(), 215);
    ASSERT_TRUE(idGen.verifyJWT(token));

    
}

TEST(ToolsTest, generateID)
{
    std::string idStr = idGenerator::generateIDstr();
    ASSERT_EQ(idStr.size(), 32);
}

TEST(ToolsTest, url_encoding)
{
    std::string encoded = UrlEncoding::encodeURIComponent("test test");
    ASSERT_EQ(encoded, "test+test");

    std::string decoded = UrlEncoding::decodeURIComponent("test+test");
    ASSERT_EQ(decoded, "test test");

    std::string base64 = UrlEncoding::encodeURIbase64("test");
    ASSERT_EQ(base64, "dGVzdA");

    std::string decoded_base64 = UrlEncoding::decodeURIbase64("dGVzdA==");
    ASSERT_EQ(decoded_base64, "test");
}

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
