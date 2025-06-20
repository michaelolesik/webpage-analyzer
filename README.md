# Webpage Analyzer

## 1. Build & Deploy Steps

**Requirements:**  
- Go 1.22+ (https://go.dev/dl/)

**Clone and run:**

git clone (https://github.com/michaelolesik/webpage-analyzer
cd webpage-analyzer
go mod tidy
go run main.go
Visit http://localhost:8080 in your browser.

## 2. Assumptions & Decisions

- If the entered URL does not start with "http://" or "https://", the app assumes "http://".
- The app considers a form a login form if it contains a password field and login-related keywords in its action, button, or labels.
- Only the static HTML is analyzed; client-side JS (like dynamically generated forms or links) is not considered.
- Internal/external link distinction: Links with the same hostname as the analyzed URL are "internal", others are "external".
- To determine inaccessible links, a HEAD request is made to each link. Only HTTP codes 200–399 are considered accessible.
- Duplicate links at the HTML level are counted once.
- The app tries to detect the HTML version by looking for the doctype declaration in the raw HTML source.

## 3. Suggestions for Improvements

- Handle client-side rendered pages by integrating a headless browser, such as using Chrome's DevTools protocol.
- Perform link accessibility checks concurrently for improved performance on large pages.
- Add caching or rate limiting for repeated analyses of the same URL.
- Provide a RESTful API (JSON responses) for integration with other systems.
- Add unit and integration tests.
- Deploy as a Docker container for easy deployment.
