"""
Quick test script to verify core functionality.
快速测试脚本，验证核心功能。
"""

from core.crypto import KeyPair, sign, verify
from core.token_manager import create_task_token, verify_task_token, TaskMCPToken
from services.registry import registry


def test_crypto():
    """测试加密功能。"""
    print("Testing crypto functions...")
    
    # 生成密钥对
    key_pair = KeyPair()
    
    # 测试签名和验签
    data = "test message"
    signature = sign(data, key_pair.private_key)
    is_valid = verify(data, signature, key_pair.public_key)
    
    assert is_valid, "Signature verification failed!"
    print("✅ Crypto functions working correctly")


def test_token_manager():
    """测试 Token Manager。"""
    print("\nTesting token manager...")
    
    key_pair = KeyPair()
    agent_did = "did:agent:test"
    user_id = "User_Test"
    tool_name = "urn:mcp:test"
    
    # 创建 Token
    token_data = create_task_token(agent_did, user_id, tool_name, key_pair.private_key)
    
    assert "payload" in token_data
    assert "signature" in token_data
    print("✅ Token creation successful")
    
    # 验证 Token
    is_valid, token = verify_task_token(
        token_data["payload"],
        token_data["signature"],
        key_pair.public_key
    )
    
    assert is_valid, "Token verification failed!"
    assert token.iss == agent_did
    assert token.sub == user_id
    assert token.target_tool == tool_name
    print("✅ Token verification successful")


def test_registry():
    """测试注册中心。"""
    print("\nTesting registry...")
    
    key_pair = KeyPair()
    agent_did = "did:agent:test"
    
    registry.register_agent(agent_did, key_pair.public_key)
    
    assert registry.is_registered(agent_did)
    assert registry.get_public_key(agent_did) == key_pair.public_key
    print("✅ Registry working correctly")


def test_token_structure():
    """测试 Token 结构。"""
    print("\nTesting token structure...")
    
    token = TaskMCPToken(
        iss="did:agent:test",
        sub="User_Test",
        target_tool="urn:mcp:audit"
    )
    
    token_dict = token.to_dict()
    assert token_dict["iss"] == "did:agent:test"
    assert token_dict["sub"] == "User_Test"
    assert token_dict["target_tool"] == "urn:mcp:audit"
    assert "nonce" in token_dict
    assert "timestamp" in token_dict
    
    # 测试序列化/反序列化
    json_str = token.to_json()
    token_restored = TaskMCPToken.from_json(json_str)
    
    assert token_restored.iss == token.iss
    assert token_restored.sub == token.sub
    assert token_restored.target_tool == token.target_tool
    print("✅ Token structure working correctly")


if __name__ == "__main__":
    print("="*60)
    print("Quick Test Suite")
    print("="*60)
    
    try:
        test_crypto()
        test_token_manager()
        test_registry()
        test_token_structure()
        
        print("\n" + "="*60)
        print("✅ All tests passed!")
        print("="*60)
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

