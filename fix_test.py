with open("internal/analysis/analysis_test.go", "r") as f:
    content = f.read()

# errorStorage was already declared in my last block, but it's not the same errorStorage. Wait.
# mockErrorStorage is in scanner_test.go. I should just use mockErrorStorage for dns.go!
