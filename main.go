package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/gin-gonic/gin"
)

type AnalysisResult struct {
	HTMLVersion               string
	Title                     string
	Headings                  map[string]int
	InternalLinks             int
	ExternalLinks             int
	InaccessibleInternalLinks int
	InaccessibleExternalLinks int
	HasLoginForm              bool
}

var loginKeywords = []string{
	"login", "sign in", "log in", "auth", "access", "anmelden", "connexion",
}

func main() {
	r := gin.Default()
	r.SetFuncMap(template.FuncMap{
		"add": func(a, b int) int {
			return a + b
		},
		"len": func(m map[string]int) int {
			return len(m)
		},
	})

	r.LoadHTMLGlob("templates/*")

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "form.html", nil)
	})

	r.POST("/analyze", handleAnalyze)

	r.Run(":8081")
}

func handleAnalyze(c *gin.Context) {
	urlInput := c.PostForm("url")
	result, httpStatus, err := AnalyzeURL(urlInput)
	if err != nil {
		c.HTML(httpStatus, "form.html", gin.H{"Error": err.Error()})
		return
	}
	c.HTML(http.StatusOK, "form.html", gin.H{"Result": result})
}

func AnalyzeURL(targetURL string) (*AnalysisResult, int, error) {
	targetURL = strings.TrimSpace(targetURL)
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}
	parsedBase, err := url.Parse(targetURL)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid URL")
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get(targetURL)
	if err != nil {
		return nil, http.StatusBadGateway, fmt.Errorf("failed to fetch URL: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("HTTP error: %d %s", resp.StatusCode, resp.Status)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to read response: %v", err)
	}
	bodyStr := string(bodyBytes)

	htmlVersion := detectHTMLVersion(bodyStr)

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(bodyStr))
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to parse HTML: %v", err)
	}

	title := strings.TrimSpace(doc.Find("title").Text())

	headings := make(map[string]int)
	for i := 1; i <= 6; i++ {
		tag := fmt.Sprintf("h%d", i)
		headings[strings.ToUpper(tag)] = doc.Find(tag).Length()
	}

	internal, external, inacInternal, inacExternal := 0, 0, 0, 0
	checked := make(map[string]bool)

	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		href, _ := s.Attr("href")
		href = strings.TrimSpace(href)

		if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") {
			return
		}
		absURL := href
		u, err := url.Parse(href)
		if err == nil && !u.IsAbs() {
			absURL = parsedBase.ResolveReference(u).String()
		}

		if checked[absURL] {
			return
		}
		checked[absURL] = true

		uu, err := url.Parse(absURL)
		if err != nil {
			return
		}

		if uu.Hostname() == parsedBase.Hostname() {
			internal++
			if !isLinkAccessible(absURL) {
				inacInternal++
			}
		} else {
			external++
			if !isLinkAccessible(absURL) {
				inacExternal++
			}
		}
	})

	hasLogin := false
	doc.Find("form").EachWithBreak(func(i int, s *goquery.Selection) bool {
		if isLoginForm(s) {
			hasLogin = true
			return false
		}
		return true
	})

	result := &AnalysisResult{
		HTMLVersion:               htmlVersion,
		Title:                     title,
		Headings:                  headings,
		InternalLinks:             internal,
		ExternalLinks:             external,
		InaccessibleInternalLinks: inacInternal,
		InaccessibleExternalLinks: inacExternal,
		HasLoginForm:              hasLogin,
	}
	return result, http.StatusOK, nil
}

func isLinkAccessible(link string) bool {
	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	req, err := http.NewRequest("HEAD", link, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Go-Webpage-Analyzer/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

func containsLoginKeyword(s string) bool {
	s = strings.ToLower(s)
	for _, kw := range loginKeywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

func detectHTMLVersion(rawHTML string) string {
	doctypeRe := regexp.MustCompile(`(?is)<!DOCTYPE\s+([^>]+)>`)
	match := doctypeRe.FindStringSubmatch(rawHTML)
	if len(match) < 2 {
		return "Unknown"
	}
	doctype := strings.ToLower(match[1])

	switch {
	case strings.TrimSpace(doctype) == "html":
		return "HTML5"
	case strings.HasPrefix(doctype, "html public \"-//w3c//dtd html 4.01 strict"):
		return "HTML 4.01 Strict"
	case strings.HasPrefix(doctype, "html public \"-//w3c//dtd html 4.01 transitional"):
		return "HTML 4.01 Transitional"
	case strings.HasPrefix(doctype, "html public \"-//w3c//dtd html 4.01 frameset"):
		return "HTML 4.01 Frameset"
	case strings.HasPrefix(doctype, "html public \"-//w3c//dtd html 4.0"):
		return "HTML 4.0"
	case strings.HasPrefix(doctype, "html public \"-//w3c//dtd html 3.2"):
		return "HTML 3.2"
	case strings.HasPrefix(doctype, "html public \"-//w3c//dtd html 2.0"):
		return "HTML 2.0"
	case strings.HasPrefix(doctype, "xhtml 1.0 strict"):
		return "XHTML 1.0 Strict"
	case strings.HasPrefix(doctype, "xhtml 1.0 transitional"):
		return "XHTML 1.0 Transitional"
	case strings.HasPrefix(doctype, "xhtml 1.0 frameset"):
		return "XHTML 1.0 Frameset"
	case strings.HasPrefix(doctype, "xhtml 1.1"):
		return "XHTML 1.1"
	case strings.Contains(doctype, "xhtml"):
		return "XHTML (unknown version)"
	case strings.Contains(doctype, "html"):
		return "Legacy HTML"
	default:
		return "Unknown/Custom"
	}
}

func isLoginForm(form *goquery.Selection) bool {
	if form.Find(`input[type="password"]`).Length() == 0 {
		return false
	}

	if action, exists := form.Attr("action"); exists && containsLoginKeyword(action) {
		return true
	}

	submitFound := false
	form.Find(`input[type="submit"], button[type="submit"], button`).EachWithBreak(func(i int, s *goquery.Selection) bool {
		val, _ := s.Attr("value")
		btnText := strings.ToLower(val + " " + s.Text())
		if containsLoginKeyword(btnText) {
			submitFound = true
			return false
		}
		return true
	})
	if submitFound {
		return true
	}

	loginFieldFound := false
	form.Find("input, label").EachWithBreak(func(i int, s *goquery.Selection) bool {
		for _, attr := range []string{"placeholder", "aria-label", "name", "id"} {
			val, ok := s.Attr(attr)
			if ok && containsLoginKeyword(val) {
				loginFieldFound = true
				return false
			}
		}

		if containsLoginKeyword(s.Text()) {
			loginFieldFound = true
			return false
		}
		return true
	})

	return loginFieldFound
}
