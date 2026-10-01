TEST_CAPABILITIES = {
    "test_defensive_1": "UNLOCKED",
    "test_defensive_2": "UNLOCKED",
    "test_high_risk_1": "UNLOCKED",
    "test_high_risk_2": "UNLOCKED",
}

for name, status in TEST_CAPABILITIES.items():
    print("[{}] {}".format(status, name))

print()
print("All test capability states parsed successfully.")
