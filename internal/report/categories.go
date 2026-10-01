package report

import (
	"sort"
	"strings"
)

// categoryOrder fixes the precedence when an app/title could match more than
// one default category, so classification is deterministic.
var categoryOrder = []string{"Development", "Communication", "Productivity", "Media", "Browsing"}

// categoryRules maps a category name to substrings that, if found in the app
// or window title (case-insensitive), classify usage into that category.
// This is a pragmatic default set; callers may extend via Categorize's
// custom map.
var categoryRules = map[string][]string{
	"Development":   {"code", "vscode", "goland", "intellij", "pycharm", "vim", "nvim", "emacs", "xcode", "android studio", "terminal", "iterm", "powershell", "cmd.exe", "docker", "git"},
	"Communication": {"slack", "teams", "zoom", "outlook", "mail", "gmail", "discord", "telegram", "whatsapp", "webex", "meet"},
	"Browsing":      {"chrome", "firefox", "safari", "edge", "brave", "opera", "arc"},
	"Productivity":  {"word", "excel", "powerpoint", "office", "notion", "obsidian", "docs", "sheets", "slides", "acrobat", "pdf", "jira", "confluence", "figma"},
	"Media":         {"spotify", "youtube", "vlc", "netflix", "music", "quicktime", "photos", "twitch"},
}

// Categorize returns the category for a given app/title. custom (optional)
// is merged over the defaults (same shape: category -> substrings). Unmatched
// usage is "Other"; the idle bucket is "Idle".
func Categorize(app, title string, custom map[string][]string) string {
	if app == "(idle)" {
		return "Idle"
	}
	hay := strings.ToLower(app + " " + title)

	// Custom rules take precedence (keys in sorted order for determinism).
	if cat := matchRules(hay, custom, sortedKeys(custom)); cat != "" {
		return cat
	}
	if cat := matchRules(hay, categoryRules, categoryOrder); cat != "" {
		return cat
	}
	return "Other"
}

func matchRules(hay string, rules map[string][]string, order []string) string {
	for _, cat := range order {
		for _, s := range rules[cat] {
			if s != "" && strings.Contains(hay, s) {
				return cat
			}
		}
	}
	return ""
}

func sortedKeys(m map[string][]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// CategoryTotal is seconds spent in one category.
type CategoryTotal struct {
	Category string  `json:"category"`
	Seconds  float64 `json:"seconds"`
}
