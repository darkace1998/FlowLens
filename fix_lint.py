import re

with open("internal/analysis/beaconing_test.go", "r") as f:
    content = f.read()

content = content.replace("var flows []model.Flow\n\t\tfor i := 0; i < 20; i++ {", "flows := make([]model.Flow, 0, 20)\n\t\tfor i := 0; i < 20; i++ {")
content = content.replace("var flows []model.Flow\n\t\tintervals := []int", "intervals := []int{10, 50, 10, 80, 20, 60, 5, 45, 90, 15, 75, 20, 100, 30}\n\t\tflows := make([]model.Flow, 0, len(intervals))\n")
content = content.replace("var flows []model.Flow\n\t\tcurrent := now\n\t\tfor i := 0; i < 15; i++ {\n\t\t\tfor j := 0; j < 3; j++ {", "flows := make([]model.Flow, 0, 45)\n\t\tcurrent := now\n\t\tfor i := 0; i < 15; i++ {\n\t\t\tfor j := 0; j < 3; j++ {")
content = content.replace("var flows []model.Flow\n\t\tfor i := 0; i < 50; i++ {", "flows := make([]model.Flow, 0, 50)\n\t\tfor i := 0; i < 50; i++ {")
content = content.replace("intervals := []int{10, 50, 10, 80, 20, 60, 5, 45, 90, 15, 75, 20, 100, 30}\n\t\tintervals := []int", "intervals := []int")

with open("internal/analysis/beaconing_test.go", "w") as f:
    f.write(content)
