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

	htmlVersion := "Unknown"
	doctypeRE := regexp.MustCompile(`(?is)<!DOCTYPE\s+([a-zA-Z0-9 \/\.\-]*)>`)
	doctype := doctypeRE.FindString(bodyStr)
	if doctype != "" {
		if strings.Contains(strings.ToLower(doctype), "xhtml") {
			htmlVersion = "XHTML"
		} else if strings.Contains(strings.ToLower(doctype), "html 4.01") {
			htmlVersion = "HTML 4.01"
		} else if strings.ToLower(strings.TrimSpace(doctype)) == "<!doctype html>" {
			htmlVersion = "HTML5"
		} else if strings.Contains(strings.ToLower(doctype), "html") {
			htmlVersion = "HTML"
		}
	}

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
		if s.Find("input[type='password']").Length() > 0 {
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
