package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	GHSA_URL = "https://api.github.com/advisories"
	logPath  = "log.jsonl"
)

var Headers = map[string]string{
	"accept":               "application/vnd.github+json",
	"cache-control":        "no-cache",
	"content-type":         "application/json",
	"X-GitHub-Api-Version": "2022-11-28",
	"User-Agent":           "Mozilla/5.0 (X11; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0", // must I not appear as "legit" ?
}

type advisory struct {
	GHSAID          string          `json:"ghsa_id"`
	Summary         string          `json:"summary"`
	Description     string          `json:"description"`
	Severity        string          `json:"severity"`
	CVSS            cvss            `json:"cvss"`
	References      []string        `json:"references"`
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
	SourceCodeURL   string          `json:"source_code_location"`
	HTMLURL         string          `json:"html_url"`
	CVEID           string          `json:"cve_id"`
}

type cvss struct {
	Score *float64 `json:"score"`
}

type vulnerability struct {
	Package                pkg    `json:"package"`
	VulnerableVersionRange string `json:"vulnerable_version_range"`
}

type pkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type discordPayload struct {
	Content     *string        `json:"content"`
	Embeds      []discordEmbed `json:"embeds"`
	Attachments []any          `json:"attachments"`
}

type discordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Color       int            `json:"color"`
	Fields      []discordField `json:"fields"`
	Author      discordAuthor  `json:"author"`
	URL         string         `json:"url"`
	Footer      discordFooter  `json:"footer"`
}

type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type discordAuthor struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	IconURL string `json:"icon_url"`
}

type discordFooter struct {
	Text    string `json:"text"`
	IconURL string `json:"icon_url"`
}

type logEntry struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
}

func main() {

	webhookURL := strings.TrimSpace(os.Getenv("DISCORD_WEBHOOK_URL"))
	if webhookURL == "" {
		fmt.Println("No Discord webhook url is set on env!")
		os.Exit(1)
	}

	seenIDs, err := loadLog(logPath)
	if err != nil {
		fmt.Printf("failed to read log: %v\n", err)
		os.Exit(1)
	}

	advisories, err := fetchAdvisories()
	if err != nil {
		fmt.Printf("Failed to fetch advisories: %v\n", err)
		os.Exit(1)
	}

	for _, data := range advisories {
		id := data.GHSAID
		if id == "" {
			continue
		}
		if seenIDs[id] {
			// skip
			continue
		}

		payload := generatePayload(data)
		if err := postWebhook(webhookURL, payload); err != nil {
			fmt.Printf("%s post failed: %v\n", id, err)
			continue
		}

		fmt.Printf("%s OK\n", id)
		if err := appendLog(logPath, id); err != nil {
			fmt.Printf("%s log append failed: %v\n", id, err)
		}
		time.Sleep(5 * time.Second)
	}

}

func fetchAdvisories() ([]advisory, error) {
	req, err := http.NewRequest("GET", GHSA_URL, nil)
	if err != nil {
		return nil, err
	}

	// apply the damn headers
	for k, v := range Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error making the request: %s\n", err)
	}

	defer resp.Body.Close()

	var out []advisory
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&out); err != nil {
		return nil, err
	}

	return out, nil
}

func generatePayload(data advisory) discordPayload {
	// this is intentional as I have no need to create + assign a custom Discord role, help yourself out if needed
	var mention = ""
	authorName := strings.TrimPrefix(data.SourceCodeURL, "https://github.com/")
	authorIcon := repoIconURL(data.SourceCodeURL)

	return discordPayload{
		Content: &mention,
		Embeds: []discordEmbed{
			{
				Title:       data.Summary,
				Description: data.Description,
				Color:       generateEmbedColor(data.Severity),
				Fields: []discordField{
					{
						Name:   "Vulnerable Packages",
						Value:  getVulnPkgs(data),
						Inline: false,
					},
					{
						Name:   "Severity",
						Value:  getSeverityIcon(data.Severity),
						Inline: true,
					},
					{
						Name: "CVSS Score",
						Value: func(score *float64) string {
							if score == nil {
								return "N/A"
							}
							return fmt.Sprintf("%g", *score)
						}(data.CVSS.Score),
						Inline: true,
					},
					{
						Name:   "References",
						Value:  getRefs(data),
						Inline: false,
					},
					{
						Name:   "GHSA ID",
						Value:  data.GHSAID,
						Inline: true,
					},
					{
						Name: "CVE ID",
						Value: func(value string) string {
							if strings.TrimSpace(value) == "" {
								return "N/A" // could be anything like "no CVE assigned"
							}
							return value
						}(data.CVEID),
						Inline: true,
					},
				},
				Author: discordAuthor{
					Name:    authorName,
					URL:     data.SourceCodeURL,
					IconURL: authorIcon,
				},
				URL: data.HTMLURL,
				Footer: discordFooter{
					Text:    "tr3nb0lone/ghsa-discord-bot",
					IconURL: "https://github.com/github.png",
				},
			},
		},
		Attachments: []any{},
	}
}

// Utils
func repoIconURL(sourceURL string) string {
	if sourceURL == "" {
		return ""
	}
	trimmed := strings.TrimRight(sourceURL, "/")
	if idx := strings.LastIndex(trimmed, "/"); idx != -1 {
		return trimmed[:idx] + ".png"
	}
	return ""
}

func postWebhook(url string, payload discordPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 20 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return nil
}

func getSeverityIcon(severity string) string {
	s := strings.ToLower(strings.TrimSpace(severity))
	switch s {
	case "low":
		return ":green_circle: Low"
	case "medium":
		return ":yellow_circle: Medium"
	case "high":
		return ":orange_circle: High"
	case "critical":
		return ":red_circle: Critical"
	default:
		return "-"
	}
}

func generateEmbedColor(severity string) int {
	switch strings.ToLower(severity) {
	case "low":
		return 7909721
	case "medium":
		return 16632664
	case "high":
		return 16027660
	case "critical":
		return 14495300
	default:
		return 15132648
	}
}

func getVulnPkgs(data advisory) string {
	if len(data.Vulnerabilities) == 0 {
		return "N/A"
	}
	var b strings.Builder
	for i, v := range data.Vulnerabilities {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString("* `")
		b.WriteString(v.Package.Name)
		b.WriteString("` (")
		b.WriteString(v.Package.Ecosystem)
		b.WriteString(") version `")
		b.WriteString(v.VulnerableVersionRange)
		b.WriteString("`")
	}
	return b.String()
}

func getRefs(data advisory) string {
	if len(data.References) == 0 {
		return "-"
	}
	var b strings.Builder
	for i, ref := range data.References {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString("* ")
		b.WriteString(ref)
	}
	return b.String()
}

// logs
func loadLog(path string) (map[string]bool, error) {
	entries := make(map[string]bool)
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return entries, nil
		}
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	for {
		var entry logEntry
		if err := decoder.Decode(&entry); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if entry.ID != "" {
			entries[entry.ID] = true
		}
	}
	return entries, nil
}

func appendLog(path, id string) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	entry := logEntry{
		ID:        id,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}
