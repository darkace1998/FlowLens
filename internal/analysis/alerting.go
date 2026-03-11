package analysis

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/darkace1998/FlowLens/internal/logging"
)

// webhookPayload is the JSON structure sent to the webhook URL.
type webhookPayload struct {
	Timestamp  time.Time         `json:"timestamp"`
	Advisories []webhookAdvisory `json:"advisories"`
}

type webhookAdvisory struct {
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Action      string `json:"action"`
}

// webhookClient is a shared HTTP client with conservative timeouts.
var webhookClient = &http.Client{
	Timeout: 10 * time.Second,
}

// sendWebhook sends new advisories to the configured webhook URL.
// It is a no-op if url is empty or advisories is empty.
func sendWebhook(url string, advisories []Advisory) {
	if url == "" || len(advisories) == 0 {
		return
	}

	payload := webhookPayload{
		Timestamp:  time.Now(),
		Advisories: make([]webhookAdvisory, len(advisories)),
	}
	for i, a := range advisories {
		payload.Advisories[i] = webhookAdvisory{
			Severity:    a.Severity.String(),
			Title:       a.Title,
			Description: a.Description,
			Action:      a.Action,
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		logging.Default().Error("Webhook: failed to marshal payload: %v", err)
		return
	}

	resp, err := webhookClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		logging.Default().Warn("Webhook: POST to %s failed: %v", url, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		logging.Default().Warn("Webhook: POST to %s returned status %d", url, resp.StatusCode)
	} else {
		logging.Default().Info("Webhook: sent %d advisory(ies) to %s (status %d)", len(advisories), url, resp.StatusCode)
	}
}
