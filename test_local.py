#!/usr/bin/env python3
"""Quick local test of the Major agent — no Switch required."""
import json
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from agent import handle_message, format_audit_report, run_audit

# Test 1: Help command
print("=" * 60)
print("TEST 1: @Major help")
print("=" * 60)
for chunk in handle_message({"content": "@Major help", "sender": {"name": "tester"}}):
    data = json.loads(chunk.decode().split("data: ", 1)[-1].split("\n")[0]) if b"data:" in chunk else None
    if data and data.get("content"):
        print(data["content"], end="")
print("\n")

# Test 2: Status
print("=" * 60)
print("TEST 2: @Major status")
print("=" * 60)
for chunk in handle_message({"content": "@Major status", "sender": {"name": "tester"}}):
    data = json.loads(chunk.decode().split("data: ", 1)[-1].split("\n")[0]) if b"data:" in chunk else None
    if data and data.get("content"):
        print(data["content"], end="")
print("\n")

# Test 3: Audit a reentrancy-vulnerable contract
VULN_CONTRACT = """
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        // VULNERABILITY: Reentrancy - state not updated before external call
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;  // state updated AFTER call
    }
    
    function emergencyKill() public {
        // VULNERABILITY: No access control on selfdestruct
        selfdestruct(payable(tx.origin));
    }
}
"""

print("=" * 60)
print("TEST 3: Audit reentrancy + selfdestruct contract")
print("=" * 60)
result = run_audit(VULN_CONTRACT)
print(f"Risk Score: {result['risk_score']}/100")
print(f"Verdict: {result['verdict']}")
print(f"Findings: {len(result['findings'])}")
for f in result["findings"]:
    print(f"  [{f['severity']}] {f['description'][:60]}...")
print()

print("=" * 60)
print("TEST 4: Full formatted report")
print("=" * 60)
report = format_audit_report(VULN_CONTRACT, "TESTABCD1234")
print(report[:1200])
print("... [truncated for display]")
