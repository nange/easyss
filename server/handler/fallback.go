package handler

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"hash/fnv"
	"html/template"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/nange/easyss/v3/stats"
)

var fallbackTmpl = template.Must(template.New("fallback").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>{{.CSS}}</style>
</head>
<body>
    <header>
        <h1>{{.SiteName}}</h1>
        <p>{{.Tagline}}</p>
    </header>
    <nav>
        <a href="/">{{.NavHome}}</a>
        <a href="/about">{{.NavAbout}}</a>
        <a href="/services">{{.NavServices}}</a>
        <a href="/contact">{{.NavContact}}</a>
    </nav>
    <main>
        <h2>{{.Heading}}</h2>
        {{range .Paragraphs}}<p>{{.}}</p>{{end}}
    </main>
    <footer>
        <p>{{.Footer}}</p>
    </footer>
</body>
</html>`))

// ---------------------------------------------------------------------------
// Theme definitions — each theme has CSS and site-level info.
// Themes are visually distinct: different color palettes, fonts, and layout
// parameters. One theme is randomly selected at startup per deployment.
// ---------------------------------------------------------------------------

type themeDef struct {
	CSS         template.CSS
	SiteName    string
	Tagline     string
	NavHome     string
	NavAbout    string
	NavServices string
	NavContact  string
}

var themes = []themeDef{
	// 1. Ocean Blue — corporate, clean, blue tones
	{
		CSS: `body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:0;padding:0;background:#edf2f7;color:#2d3748;line-height:1.6}
header{background:#1a365d;color:#fff;padding:32px 20px;text-align:center}
header h1{font-size:2rem;margin:0 0 8px 0;font-weight:700}
header p{font-size:1rem;margin:0;opacity:0.85}
nav{background:#2c5282;padding:12px 20px;text-align:center}
nav a{color:#bee3f8;text-decoration:none;margin:0 18px;font-size:.95rem;font-weight:500;transition:color .2s}
nav a:hover{color:#fff}
main{max-width:780px;margin:40px auto;padding:32px;background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.08)}
main h2{font-size:1.5rem;margin-top:0;color:#1a365d}
main p{margin:16px 0;font-size:1rem}
footer{text-align:center;padding:24px;color:#a0aec0;font-size:.85rem;border-top:1px solid #e2e8f0}`,
		SiteName:    "Acme Solutions",
		Tagline:     "Innovation delivered with integrity",
		NavHome:     "Home",
		NavAbout:    "About",
		NavServices: "Services",
		NavContact:  "Contact",
	},

	// 2. Forest Green — natural, friendly, rounded
	{
		CSS: `body{font-family:Georgia,"Times New Roman",serif;margin:0;padding:0;background:#f0f7f4;color:#2d3a2e;line-height:1.7}
header{background:#22543d;color:#f0fff4;padding:36px 24px;text-align:center}
header h1{font-size:2.1rem;margin:0 0 6px 0;letter-spacing:-0.5px}
header p{font-size:1.05rem;margin:0;font-style:italic;opacity:0.8}
nav{background:#38a169;padding:14px 20px;text-align:center;border-bottom:3px solid #22543d}
nav a{color:#f0fff4;text-decoration:none;margin:0 20px;font-size:.95rem;text-transform:uppercase;letter-spacing:.5px}
nav a:hover{text-decoration:underline}
main{max-width:760px;margin:36px auto;padding:28px 32px;background:#fff;border-radius:12px;border-left:6px solid #38a169;box-shadow:0 1px 4px rgba(0,0,0,.06)}
main h2{font-size:1.5rem;margin-top:0;color:#22543d}
main p{margin:14px 0;font-size:.98rem}
footer{text-align:center;padding:20px;color:#718096;font-size:.8rem;background:#e2e8e0}`,
		SiteName:    "Greenfield Partners",
		Tagline:     "Rooted in values, growing together",
		NavHome:     "Home",
		NavAbout:    "About Us",
		NavServices: "Solutions",
		NavContact:  "Get in Touch",
	},

	// 3. Dark Modern — tech-forward, dark mode, code-like accents
	{
		CSS: `body{font-family:ui-sans-serif,system-ui,-apple-system,sans-serif;margin:0;padding:0;background:#0d1117;color:#c9d1d9;line-height:1.65}
header{background:#010409;padding:28px 24px;border-bottom:1px solid #21262d;text-align:center}
header h1{font-size:1.8rem;margin:0;color:#58a6ff;font-weight:600}
header p{font-size:.9rem;margin:6px 0 0 0;color:#8b949e}
nav{background:#161b22;padding:10px 20px;text-align:center;border-bottom:1px solid #30363d}
nav a{color:#c9d1d9;text-decoration:none;margin:0 16px;font-size:.88rem}
nav a:hover{color:#58a6ff}
main{max-width:720px;margin:36px auto;padding:28px;background:#161b22;border:1px solid #30363d;border-radius:6px}
main h2{font-size:1.4rem;margin-top:0;color:#f0f6fc}
main p{margin:14px 0;font-size:.92rem;color:#8b949e}
footer{text-align:center;padding:20px;color:#484f58;font-size:.78rem;border-top:1px solid #21262d}`,
		SiteName:    "NexusCode",
		Tagline:     "Engineering the future, one line at a time",
		NavHome:     "Home",
		NavAbout:    "About",
		NavServices: "Platform",
		NavContact:  "Contact",
	},

	// 4. Sunset Amber — warm, traditional, serif-heavy
	{
		CSS: `body{font-family:Cambria,"Hoefler Text",Utopia,"Liberation Serif","Times New Roman",serif;margin:0;padding:0;background:#fef9f0;color:#3e2a1e;line-height:1.7}
header{background:#c05621;color:#fffaf0;padding:38px 20px 28px;text-align:center;border-bottom:4px solid #9c4221}
header h1{font-size:2.2rem;margin:0;font-weight:400;text-shadow:1px 1px 2px rgba(0,0,0,.2)}
header p{font-size:1rem;margin:8px 0 0;opacity:0.9;font-style:italic}
nav{background:#edf2f7;padding:16px 20px;text-align:center}
nav a{color:#9c4221;text-decoration:none;margin:0 22px;font-size:.95rem;font-variant:small-caps}
nav a:hover{color:#c05621;border-bottom:2px solid #c05621}
main{max-width:700px;margin:42px auto;padding:30px 36px;background:#fffaf0;border:1px solid #e2d5c0;box-shadow:0 2px 6px rgba(156,66,33,.08)}
main h2{font-size:1.6rem;margin-top:0;color:#9c4221;font-weight:400}
main p{margin:16px 0;font-size:1rem}
footer{text-align:center;padding:22px;color:#8b6f5e;font-size:.82rem;font-style:italic}`,
		SiteName:    "Crestwood Advisory",
		Tagline:     "Wisdom, trust, and the human touch",
		NavHome:     "Home",
		NavAbout:    "About",
		NavServices: "Expertise",
		NavContact:  "Contact",
	},

	// 5. Minimal Mono — grayscale, clean, modern
	{
		CSS: `body{font-family:"Helvetica Neue",Helvetica,Arial,sans-serif;margin:0;padding:0;background:#fff;color:#333;line-height:1.6}
header{background:transparent;padding:40px 20px 20px;text-align:center;border-bottom:1px solid #eaeaea}
header h1{font-size:1.6rem;margin:0;font-weight:300;color:#111;text-transform:uppercase;letter-spacing:2px}
header p{font-size:.85rem;margin:8px 0 0;color:#999}
nav{padding:16px 20px;text-align:center;border-bottom:1px solid #eaeaea}
nav a{color:#555;text-decoration:none;margin:0 24px;font-size:.8rem;text-transform:uppercase;letter-spacing:1.5px;font-weight:500}
nav a:hover{color:#111}
main{max-width:640px;margin:48px auto;padding:0 24px}
main h2{font-size:1.3rem;margin:0 0 24px;font-weight:400;color:#111}
main p{margin:0 0 20px;font-size:.95rem;color:#555}
footer{text-align:center;padding:28px 20px;color:#bbb;font-size:.75rem;border-top:1px solid #f0f0f0}`,
		SiteName:    "Mode Studio",
		Tagline:     "Crafting clarity through design",
		NavHome:     "Work",
		NavAbout:    "Studio",
		NavServices: "Capabilities",
		NavContact:  "Contact",
	},
}

// ---------------------------------------------------------------------------
// Content pools — realistic, varied text for each page type.
// Content is selected via deterministic hash of the request path,
// so the same URL always gets the same content.
// ---------------------------------------------------------------------------

type pageContent struct {
	Title      string
	Heading    string
	Paragraphs []string
	Footer     string
}

type contentPool map[string][]pageContent

var contentPools = contentPool{
	// ---------- Home ----------
	"home": {
		{
			Title:      "Welcome to Our Site",
			Heading:    "Delivering Results That Matter",
			Paragraphs: []string{"We help organizations navigate complexity and achieve measurable outcomes through strategic thinking and operational excellence.", "Our team brings decades of combined experience across multiple industries. Whether you are launching a new initiative or scaling an existing operation, we have the expertise to guide you."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Home \u2014 Trusted Partner for Growth",
			Heading:    "Your Vision, Our Commitment",
			Paragraphs: []string{"Every great achievement starts with a clear vision. We work alongside our clients to turn ambitious ideas into practical, sustainable results.", "From strategy through execution, our collaborative approach ensures alignment at every stage. We measure success by the impact we create together."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Leading the Way in Innovation",
			Heading:    "Transforming Challenges into Opportunities",
			Paragraphs: []string{"In a rapidly evolving landscape, staying ahead requires more than just keeping up. Our forward-thinking methodology helps organizations anticipate change and adapt proactively.", "We partner with leaders who are ready to challenge the status quo and build lasting competitive advantage."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Excellence in Every Engagement",
			Heading:    "Quality Without Compromise",
			Paragraphs: []string{"For over a decade, organizations have trusted us to deliver solutions that stand the test of time. Our commitment to quality is reflected in everything we do.", "We believe that exceptional outcomes require exceptional partnerships. That is why we invest deeply in understanding your unique context."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Welcome to the Future of Business",
			Heading:    "Built for What Is Next",
			Paragraphs: []string{"The pace of change has never been faster. We provide the clarity, tools, and support you need to thrive in an uncertain world.", "Our integrated approach combines deep industry knowledge with cutting-edge practices to deliver sustainable results."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
	},

	// ---------- About ----------
	"about": {
		{
			Title:      "About Us \u2014 Our Story",
			Heading:    "Who We Are",
			Paragraphs: []string{"Founded in 2010, we have grown from a small team of passionate individuals into a respected organization serving clients across the globe.", "Our mission is simple: deliver exceptional value through expertise, integrity, and relentless focus on our clients\u2019 success."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "About \u2014 Our Mission and Values",
			Heading:    "Driven by Purpose",
			Paragraphs: []string{"We believe that business can be a force for good. Every engagement is guided by our core values of transparency, collaboration, and continuous improvement.", "Our diverse team brings perspectives from technology, finance, operations, and creative disciplines\u2014united by a shared commitment to making a difference."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Our Team",
			Heading:    "Meet the People Behind the Work",
			Paragraphs: []string{"Our strength lies in our people. We have assembled a team of dedicated professionals who are experts in their respective fields.", "From seasoned consultants to emerging talent, everyone on our team shares a passion for solving complex problems and delivering meaningful impact."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Company Overview",
			Heading:    "A Legacy of Excellence",
			Paragraphs: []string{"With offices in three major cities and a growing remote workforce, we combine local expertise with global reach.", "Our track record speaks for itself: hundreds of successful engagements, long-term client relationships, and a reputation for delivering on our promises."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "About Our Approach",
			Heading:    "How We Think",
			Paragraphs: []string{"We take a first-principles approach to every challenge, questioning assumptions and exploring possibilities before committing to a path forward.", "This rigorous, thoughtful methodology has earned us the trust of some of the most demanding organizations in the world."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
	},

	// ---------- Contact ----------
	"contact": {
		{
			Title:      "Contact Us",
			Heading:    "Get in Touch",
			Paragraphs: []string{"We would love to hear from you. Whether you have a question about our services, want to explore a partnership, or simply want to learn more, our team is here to help.", "You can reach us by phone at +1 (555) 123-4567, by email at info@example.com, or by visiting our office at 123 Business Avenue, Suite 400, New York, NY 10001."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Contact \u2014 Let\u2019s Talk",
			Heading:    "We Are Ready to Help",
			Paragraphs: []string{"Our team is available Monday through Friday, 9 AM to 6 PM Eastern Time. We strive to respond to all inquiries within one business day.", "For general inquiries: contact@example.com. For support: support@example.com. Phone: +1 (555) 987-6543."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Find Us",
			Heading:    "Our Locations",
			Paragraphs: []string{"Headquarters: 456 Park Avenue, 12th Floor, San Francisco, CA 94102. Satellite office: 789 Innovation Drive, Austin, TX 78701.", "We also offer virtual consultations for clients around the world. Schedule a call at your convenience."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Contact Information",
			Heading:    "Reach Out Anytime",
			Paragraphs: []string{"We value open communication and are always happy to discuss how we can support your goals.", "Email: hello@example.com | Phone: +1 (555) 456-7890 | Follow us on LinkedIn and Twitter for the latest updates."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Support Center",
			Heading:    "How Can We Assist You?",
			Paragraphs: []string{"For existing clients, our support portal provides a knowledge base, ticket submission, and live chat during business hours.", "Not a client yet? Our sales team can walk you through our offerings and help identify the right solution for your needs."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
	},

	// ---------- Services ----------
	"services": {
		{
			Title:      "Our Services",
			Heading:    "What We Offer",
			Paragraphs: []string{"We provide a comprehensive suite of services designed to help organizations thrive in a competitive environment. Our core offerings include strategic consulting, technology implementation, and operational optimization.", "Each engagement is tailored to the specific needs of our clients. We do not believe in one-size-fits-all solutions."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Products and Solutions",
			Heading:    "Tools That Empower",
			Paragraphs: []string{"Our product portfolio spans data analytics, cloud infrastructure, workflow automation, and customer engagement platforms.", "Built on modern architecture with security and scalability at the core, our solutions integrate seamlessly with your existing technology stack."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Pricing",
			Heading:    "Transparent and Flexible",
			Paragraphs: []string{"We offer flexible pricing models designed to align with your budget and business needs. From project-based engagements to ongoing retainers, we work with you to find the right arrangement.", "Contact our team for a customized quote based on your specific requirements and scope."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Consulting Services",
			Heading:    "Expert Guidance, Tangible Results",
			Paragraphs: []string{"Our consulting practice helps organizations address their most pressing challenges: growth strategy, digital transformation, organizational design, and operational efficiency.", "We bring an outside perspective grounded in data, experience, and rigorous analysis."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Managed Services",
			Heading:    "Focus on Your Core Business",
			Paragraphs: []string{"Let us handle the complexity. Our managed services team provides ongoing support, monitoring, and optimization for your critical systems and processes.", "With 24/7 coverage and proactive issue resolution, you can focus on what matters most: serving your customers and growing your business."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
	},

	// ---------- Blog / News ----------
	"blog": {
		{
			Title:      "Industry Insights and Trends",
			Heading:    "What Is Shaping the Landscape",
			Paragraphs: []string{"The industry is undergoing significant transformation driven by advances in artificial intelligence, shifting regulatory frameworks, and evolving customer expectations.", "In this article, we explore the key trends that leaders should be paying attention to in the coming year."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Latest News and Announcements",
			Heading:    "What\u2019s New",
			Paragraphs: []string{"We are excited to share recent developments, including new partnerships, expanded capabilities, and recognition from industry analysts.", "Stay tuned for more updates as we continue to grow and evolve."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Best Practices Guide",
			Heading:    "A Practical Framework for Success",
			Paragraphs: []string{"After years of working with organizations of all sizes, we have distilled our learning into a practical guide for navigating complex initiatives.", "This guide covers planning, execution, measurement, and continuous improvement."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Case Study: Driving Operational Excellence",
			Heading:    "How One Organization Achieved a 40% Efficiency Gain",
			Paragraphs: []string{"We recently partnered with a mid-size manufacturing company to overhaul their supply chain operations. The results exceeded expectations.", "Read the full case study to learn about the approach, the challenges, and the lessons we learned along the way."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Technology Radar",
			Heading:    "Tools and Platforms Worth Watching",
			Paragraphs: []string{"Our team regularly evaluates emerging technologies to help clients make informed decisions about their technology investments.", "Here are the tools and platforms that have caught our attention this quarter."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
	},

	// ---------- Generic (any other path) ----------
	"generic": {
		{
			Title:      "\u00a0",
			Heading:    "Page Not Found",
			Paragraphs: []string{"The page you are looking for might have been moved or is temporarily unavailable. Please check the URL and try again, or navigate back to the homepage."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Resource Center",
			Heading:    "Explore Our Resources",
			Paragraphs: []string{"Our resource center provides a wealth of information including whitepapers, webinars, case studies, and industry reports.", "Browse by topic or use the search function to find what you need."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Knowledge Base",
			Heading:    "Find Answers Fast",
			Paragraphs: []string{"Our knowledge base contains hundreds of articles covering common questions, troubleshooting guides, and best practices.", "If you cannot find what you are looking for, our support team is ready to assist."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Documentation",
			Heading:    "Technical Documentation",
			Paragraphs: []string{"Comprehensive documentation for our products and services, including API references, integration guides, and release notes.", "Documentation is updated regularly to reflect the latest features and improvements."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "FAQ",
			Heading:    "Frequently Asked Questions",
			Paragraphs: []string{"We have compiled answers to the most common questions we receive from clients and partners.", "If your question is not addressed here, please do not hesitate to contact us directly."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
	},
}

// ---------------------------------------------------------------------------
// Types for rendering
// ---------------------------------------------------------------------------

type renderData struct {
	CSS         template.CSS
	SiteName    string
	Tagline     string
	NavHome     string
	NavAbout    string
	NavServices string
	NavContact  string
	Title       string
	Heading     string
	Paragraphs  []string
	Footer      string
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

// ctxKey is an unexported context key type used to pass the original client-
// facing Host and scheme from ServeFallback into the reverse proxy's
// ModifyResponse hook, so that Location headers pointing at the upstream host
// can be rewritten back to the client-facing host without leaking the upstream
// via X-Forwarded-Host.
type ctxKey int

const (
	ctxOrigHost ctxKey = iota
	ctxOrigScheme
	ctxOrigAcceptEncoding
)

var (
	initOnce       sync.Once
	selectedTheme  themeDef
	customFallback []byte
	htmlCache      sync.Map // path string → []byte
	htmlCacheCount atomic.Int32

	// Directory-based multi-file fallback.
	fallbackPages map[string][]byte // path → HTML bytes (e.g. "/about" → <html>...)
	fallback404   []byte            // optional 404 page

	// Reverse proxy to upstream HTTP service (e.g. local nginx).
	fallbackProxy *httputil.ReverseProxy
)

const maxCachedFallbackPages = 64

// SetFallbackHTML overrides the built-in fallback system with custom HTML.
// Must be called before the server starts accepting requests.
func SetFallbackHTML(html []byte) {
	if len(html) == 0 {
		return
	}
	customFallback = make([]byte, len(html))
	copy(customFallback, html)
}

// SetFallbackDir loads all .html files from a directory as multi-route fallback
// pages. File-to-path mapping:
//   - index.html         → "/"
//   - 404.html           → unmatched paths
//   - <name>.html        → "/<name>"
//   - <sub>/<name>.html  → "/<sub>/<name>"
//   - <sub>/index.html   → "/<sub>"
//
// Non-.html files are ignored. Must be called before the server starts
// accepting requests.
func SetFallbackDir(dir string) error {
	pages := make(map[string][]byte)
	var page404 []byte

	err := filepath.WalkDir(dir, func(fpath string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".html") {
			return nil
		}

		content, err := os.ReadFile(fpath)
		if err != nil {
			return fmt.Errorf("read %s: %w", fpath, err)
		}

		rel, err := filepath.Rel(dir, fpath)
		if err != nil {
			return fmt.Errorf("rel path %s: %w", fpath, err)
		}

		nameWithoutExt := strings.TrimSuffix(d.Name(), ".html")

		// 404.html is special: stored for unmatched paths, not as a regular page.
		if strings.EqualFold(nameWithoutExt, "404") {
			page404 = content
			return nil
		}

		// Build URL path from relative file path.
		urlPath := "/" + filepath.ToSlash(strings.TrimSuffix(rel, ".html"))

		// index.html maps to parent directory (or "/" for root).
		if strings.EqualFold(nameWithoutExt, "index") {
			if dir := filepath.Dir(rel); dir == "." {
				urlPath = "/"
			} else {
				urlPath = "/" + filepath.ToSlash(dir)
			}
		}

		pages[urlPath] = content
		return nil
	})
	if err != nil {
		return err
	}

	fallbackPages = pages
	fallback404 = page404
	return nil
}

// SetFallbackProxy configures a reverse proxy to forward non-proxy requests to
// an upstream HTTP service (e.g. a local nginx). When set, this takes the
// highest priority over all other fallback modes.
// Pass an empty string to disable.
//
// Unlike httputil.NewSingleHostReverseProxy, this uses Rewrite + SetURL so
// that req.Host is set to the upstream host (some upstreams — e.g. GitHub —
// return a 301 redirect to their canonical host when the Host header does not
// match). A ModifyResponse hook rewrites Location headers that point at the
// upstream host back to the client-facing host (read from the request
// context, injected by ServeFallback), so that 3xx redirects issued by the
// upstream do not cause the browser's address bar to jump to the upstream.
//
// If preserveHost is true, the client-facing Host header is forwarded to the
// upstream unchanged (i.e. SetURL is still called for scheme/host/path but
// Out.Host is restored to the original request Host). This is useful when
// proxying to a local nginx that uses server_name-based virtual host routing
// and expects to see the public-facing Host.
//
// HTML response bodies and the Content-Security-Policy header are always
// rewritten so that absolute URLs pointing at the upstream host (e.g.
// https://github.com/...) are replaced with the client-facing origin (e.g.
// https://my-site.com/...). This is needed for upstreams like GitHub that
// embed absolute URLs in turbo-frame src attributes or CSP directives, which
// otherwise cause CSP violations and direct browser connections to the
// upstream.
//
// Accept-Encoding negotiation: the proxy intersects the client's
// Accept-Encoding with the encodings it can handle (gzip and identity). If
// the client accepts gzip, the upstream request advertises "identity, gzip"
// so the upstream may compress large responses; gzip HTML is decompressed for
// rewriting and re-compressed before returning to the client. If the client
// does not accept gzip, the upstream request advertises "identity" only, so
// no decompression/recompression is needed.
func SetFallbackProxy(targetURL string, preserveHost bool) error {
	if targetURL == "" {
		fallbackProxy = nil
		return nil
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("parse fallback proxy url: %w", err)
	}
	targetHost := u.Host
	fallbackProxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// SetURL rewrites Scheme/Host/Path and, importantly, sets
			// pr.Out.Host = u.Host so the upstream receives the correct
			// Host header.
			pr.SetURL(u)
			if preserveHost {
				// Restore the client-facing Host so upstreams that rely on
				// server_name routing (e.g. a local nginx) still see the
				// public Host.
				pr.Out.Host = pr.In.Host
			}
			// Advertise only encodings we can handle, intersected with
			// what the client accepts. If the client accepts gzip, allow
			// the upstream to gzip (saves bandwidth on the proxy<->upstream
			// leg); we decompress before rewriting HTML and re-compress
			// before returning to the client. If the client does not accept
			// gzip, request identity only so we never need to decompress
			// non-HTML responses for a client that can't handle gzip.
			clientAE := pr.In.Header.Get("Accept-Encoding")
			if clientAcceptsGzip(clientAE) {
				pr.Out.Header.Set("Accept-Encoding", "identity, gzip")
			} else {
				pr.Out.Header.Set("Accept-Encoding", "identity")
			}
			// Rewrite Origin and Referer request headers so the upstream
			// sees its own origin. Without this, Rails CSRF protection
			// (e.g. GitHub) rejects POST requests because the Origin header
			// is "https://my-site.com" instead of "https://github.com",
			// resulting in HTTP 422.
			rewriteRequestOriginReferrer(pr.Out, pr.In.Host, u)
		},
		ModifyResponse: func(resp *http.Response) error {
			if err := rewriteLocationHeader(resp, targetHost); err != nil {
				return err
			}
			rewriteSetCookieHeaders(resp, targetHost)
			return rewriteResponseBody(resp, targetHost)
		},
	}
	return nil
}

// clientAcceptsGzip reports whether the given Accept-Encoding header value
// indicates that gzip is acceptable to the client (q-value > 0). The wildcard
// "*" is treated as accepting gzip.
func clientAcceptsGzip(acceptEncoding string) bool {
	if acceptEncoding == "" {
		return false
	}
	for _, part := range strings.Split(acceptEncoding, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		coding := part
		q := 1.0
		for i, p := range strings.Split(part, ";") {
			p = strings.TrimSpace(p)
			if i == 0 {
				coding = p
				continue
			}
			if strings.HasPrefix(p, "q=") {
				if v, err := strconv.ParseFloat(p[2:], 64); err == nil {
					q = v
				}
			}
		}
		if (coding == "gzip" || coding == "*") && q > 0 {
			return true
		}
	}
	return false
}

// rewriteRequestOriginReferrer rewrites the Origin and Referer headers on the
// outbound request so the upstream sees its own origin instead of the
// proxy's client-facing host. This is required for upstreams that validate
// the Origin header as part of CSRF protection (e.g. Rails/GitHub return HTTP
// 422 when the Origin doesn't match). Only headers whose host equals the
// client-facing host are rewritten; headers pointing at other hosts are left
// untouched.
func rewriteRequestOriginReferrer(out *http.Request, clientHost string, upstream *url.URL) {
	for _, hdr := range []string{"Origin", "Referer"} {
		val := out.Header.Get(hdr)
		if val == "" {
			continue
		}
		parsed, err := url.Parse(val)
		if err != nil {
			continue
		}
		if parsed.Host != clientHost {
			continue
		}
		parsed.Scheme = upstream.Scheme
		parsed.Host = upstream.Host
		out.Header.Set(hdr, parsed.String())
	}
}

// rewriteLocationHeader rewrites a 3xx Location header that points at the
// upstream target host back to the client-facing host, so that browser
// redirects stay on the proxy's address. Relative-path Locations (e.g.
// "/login") and Locations pointing at other hosts are left untouched.
func rewriteLocationHeader(resp *http.Response, targetHost string) error {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil
	}
	locURL, err := url.Parse(loc)
	if err != nil {
		// Malformed Location — leave it untouched and let the client decide.
		return nil
	}
	// Only rewrite absolute redirects that point at the upstream host.
	if locURL.Host == "" || locURL.Host != targetHost {
		return nil
	}
	ctx := resp.Request.Context()
	origHost, _ := ctx.Value(ctxOrigHost).(string)
	if origHost == "" {
		return nil
	}
	origScheme, _ := ctx.Value(ctxOrigScheme).(string)
	if origScheme == "" {
		origScheme = "https"
	}
	locURL.Scheme = origScheme
	locURL.Host = origHost
	resp.Header.Set("Location", locURL.String())
	return nil
}

// rewriteSetCookieHeaders rewrites Set-Cookie response headers so that cookies
// set by the upstream for its own domain are accepted by the browser visiting
// the proxy's host. Without this, an upstream like GitHub that sets
// "Domain=github.com" on its session cookies would be rejected by the browser
// (the page origin is my-site.com, not a subdomain of github.com), causing
// features that depend on session cookies — such as CSRF tokens in the login
// form — to fail with HTTP 422.
//
// For each Set-Cookie header whose Domain attribute equals the upstream host
// (case-insensitive, leading dot ignored), the Domain attribute is removed
// entirely so the cookie becomes a host-only cookie bound to the proxy's host.
// Cookies with a Domain pointing at a different host are left untouched.
func rewriteSetCookieHeaders(resp *http.Response, targetHost string) {
	cookies := resp.Header["Set-Cookie"]
	if len(cookies) == 0 {
		return
	}

	targetHostLower := strings.ToLower(strings.TrimPrefix(targetHost, "."))

	rewritten := make([]string, 0, len(cookies))
	for _, raw := range cookies {
		parts := strings.Split(raw, ";")
		for i, part := range parts {
			p := strings.TrimSpace(part)
			if len(p) <= 7 { // len("Domain=") == 7
				continue
			}
			if !strings.EqualFold(p[:7], "Domain=") {
				continue
			}
			domain := strings.TrimSpace(p[7:])
			domain = strings.TrimPrefix(domain, ".")
			if strings.EqualFold(domain, targetHostLower) {
				// Remove the Domain attribute so the cookie becomes a
				// host-only cookie for the proxy's host.
				rewrittenParts := append(append([]string{}, parts[:i]...), parts[i+1:]...)
				raw = strings.Join(rewrittenParts, ";")
				break
			}
		}
		rewritten = append(rewritten, raw)
	}
	resp.Header["Set-Cookie"] = rewritten
}

// rewriteResponseBody reads an HTML response body and replaces absolute URLs
// pointing at the upstream host (both http and https variants) with the
// client-facing origin, so that browser-initiated requests (e.g. Turbo frame
// fetches, <a> links, <form> actions) stay on the proxy instead of going
// directly to the upstream. The Content-Security-Policy response header is
// similarly rewritten. Non-HTML responses are passed through unchanged.
//
// The upstream request's Accept-Encoding is set to "identity, gzip" (when the
// client accepts gzip) or "identity" (otherwise), so the upstream may return
// either plain text or gzip-compressed content; gzip is transparently
// decompressed before rewriting. After rewriting, if the client accepts gzip,
// the response is re-compressed with gzip before being returned; otherwise it
// is sent uncompressed.
func rewriteResponseBody(resp *http.Response, targetHost string) error {
	// Only rewrite HTML responses.
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		return nil
	}

	// Read the body, decompressing gzip if necessary.
	enc := resp.Header.Get("Content-Encoding")
	var body []byte
	var err error

	switch enc {
	case "", "identity":
		body, err = io.ReadAll(resp.Body)
		resp.Body.Close() //nolint:errcheck
	case "gzip":
		gr, gerr := gzip.NewReader(resp.Body)
		if gerr != nil {
			resp.Body.Close() //nolint:errcheck
			return nil        // skip rewriting on decompress error
		}
		body, err = io.ReadAll(gr)
		gr.Close()        //nolint:errcheck
		resp.Body.Close() //nolint:errcheck
	default:
		// Unsupported encoding (br, deflate, etc.) — skip rewriting.
		return nil
	}
	if err != nil {
		return nil
	}

	// Get the client-facing host/scheme from the request context.
	ctx := resp.Request.Context()
	origHost, _ := ctx.Value(ctxOrigHost).(string)
	if origHost == "" {
		// No client-facing host available — return body as-is.
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}
	origScheme, _ := ctx.Value(ctxOrigScheme).(string)
	if origScheme == "" {
		origScheme = "https"
	}

	// Replace absolute URLs: both http and https variants of the upstream
	// host are replaced with the client-facing origin.
	origOrigin := origScheme + "://" + origHost
	replaced := body
	replaced = bytes.ReplaceAll(replaced, []byte("http://"+targetHost), []byte(origOrigin))
	replaced = bytes.ReplaceAll(replaced, []byte("https://"+targetHost), []byte(origOrigin))

	// Rewrite the Content-Security-Policy header similarly so that
	// connect-src / form-action / etc. entries referencing the upstream
	// origin allow the client-facing origin instead.
	if csp := resp.Header.Get("Content-Security-Policy"); csp != "" {
		csp = strings.ReplaceAll(csp, "http://"+targetHost, origOrigin)
		csp = strings.ReplaceAll(csp, "https://"+targetHost, origOrigin)
		resp.Header.Set("Content-Security-Policy", csp)
	}

	// Re-compress with gzip if the client accepts it, so we don't waste
	// bandwidth on the client<->proxy leg. Otherwise send uncompressed.
	origAE, _ := ctx.Value(ctxOrigAcceptEncoding).(string)
	if clientAcceptsGzip(origAE) {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		if _, werr := gw.Write(replaced); werr != nil {
			gw.Close() //nolint:errcheck
			// Fall back to uncompressed on error.
			resp.Body = io.NopCloser(bytes.NewReader(replaced))
			resp.ContentLength = int64(len(replaced))
			resp.Header.Set("Content-Length", strconv.Itoa(len(replaced)))
			resp.Header.Del("Content-Encoding")
			return nil
		}
		gw.Close() //nolint:errcheck
		resp.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
		resp.ContentLength = int64(buf.Len())
		resp.Header.Set("Content-Length", strconv.Itoa(buf.Len()))
		resp.Header.Set("Content-Encoding", "gzip")
		return nil
	}

	resp.Body = io.NopCloser(bytes.NewReader(replaced))
	resp.ContentLength = int64(len(replaced))
	resp.Header.Set("Content-Length", strconv.Itoa(len(replaced)))
	resp.Header.Del("Content-Encoding")
	return nil
}

// SetFallbackTarget resolves a single fallback target string and configures the
// appropriate fallback mode. The target is interpreted as:
//   - ""                        → built-in themed auto-generated pages
//   - "http://..." / "https://..." → reverse proxy to an upstream HTTP service
//   - a directory path             → multi-file HTML fallback (SetFallbackDir)
//   - a regular file path          → single-file custom HTML (SetFallbackHTML)
//
// preserveHost only affects the reverse-proxy mode (see SetFallbackProxy);
// it is ignored for the directory/file/built-in modes.
func SetFallbackTarget(target string, preserveHost bool) error {
	// Reset all fallback state.
	fallbackProxy = nil
	fallbackPages = nil
	fallback404 = nil
	customFallback = nil

	if target == "" {
		return nil
	}

	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return SetFallbackProxy(target, preserveHost)
	}

	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("stat fallback target: %w", err)
	}

	if info.IsDir() {
		return SetFallbackDir(target)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		return fmt.Errorf("read fallback target: %w", err)
	}
	SetFallbackHTML(data)
	return nil
}

// ServeFallback writes a fallback HTML page to the response.
// Priority (highest first):
//  0. Reverse proxy to upstream HTTP service (SetFallbackProxy)
//  1. Directory-based multi-file fallback (SetFallbackDir)
//  2. Single-file custom fallback (SetFallbackHTML)
//  3. Auto-generated themed pages
func ServeFallback(w http.ResponseWriter, r *http.Request) {
	stats.RecordServerFallbackPage()
	initOnce.Do(func() {
		selectedTheme = themes[rand.IntN(len(themes))]
	})

	// Priority 0 (highest): reverse proxy to upstream HTTP service.
	if fallbackProxy != nil {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		ctx := context.WithValue(r.Context(), ctxOrigHost, r.Host)
		ctx = context.WithValue(ctx, ctxOrigScheme, scheme)
		ctx = context.WithValue(ctx, ctxOrigAcceptEncoding, r.Header.Get("Accept-Encoding"))
		fallbackProxy.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Server", "nginx")
	w.WriteHeader(http.StatusOK)

	// Priority 1: directory-based multi-file fallback.
	if len(fallbackPages) > 0 {
		content, ok := fallbackPages[cleanPath(r.URL.Path)]
		if !ok {
			content = fallback404
		}
		if !ok && len(content) == 0 {
			// No matching page and no 404.html — fall back to index.
			content = fallbackPages["/"]
		}
		if len(content) > 0 {
			w.Write(content) //nolint:errcheck
			return
		}
	}

	// Priority 2: single-file custom fallback.
	if len(customFallback) > 0 {
		w.Write(customFallback) //nolint:errcheck
		return
	}

	// Priority 3: auto-generated themed pages.
	w.Write(getOrRenderHTML(r.URL.Path)) //nolint:errcheck
}

// cleanPath normalizes a URL path for lookup: "/" stays "/", everything else
// gets its trailing slash removed.
func cleanPath(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	return strings.TrimRight(p, "/")
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func getOrRenderHTML(path string) []byte {
	path = cleanPath(path)
	if cached, ok := htmlCache.Load(path); ok {
		return cached.([]byte)
	}

	html := renderHTML(path)
	if shouldCacheGeneratedPath(path) && htmlCacheCount.Load() < maxCachedFallbackPages {
		if _, loaded := htmlCache.LoadOrStore(path, html); !loaded {
			htmlCacheCount.Add(1)
		}
	}
	return html
}

func shouldCacheGeneratedPath(path string) bool {
	switch path {
	case "/", "/about", "/contact", "/support", "/help", "/services", "/products", "/solutions", "/pricing":
		return true
	default:
		return false
	}
}

func renderHTML(path string) []byte {
	pageType := detectPageType(path)
	pool := contentPools[pageType]
	idx := hashIndex(path, len(pool))
	content := pool[idx]

	data := renderData{
		CSS:         selectedTheme.CSS,
		SiteName:    selectedTheme.SiteName,
		Tagline:     selectedTheme.Tagline,
		NavHome:     selectedTheme.NavHome,
		NavAbout:    selectedTheme.NavAbout,
		NavServices: selectedTheme.NavServices,
		NavContact:  selectedTheme.NavContact,
		Title:       resolveTitle(content.Title, selectedTheme.SiteName),
		Heading:     content.Heading,
		Paragraphs:  content.Paragraphs,
		Footer:      content.Footer,
	}

	var buf bytes.Buffer
	if err := fallbackTmpl.Execute(&buf, data); err != nil {
		return []byte("Internal Server Error")
	}
	return buf.Bytes()
}

func detectPageType(path string) string {
	path = strings.ToLower(strings.Trim(path, "/"))
	switch {
	case path == "":
		return "home"
	case path == "about", strings.HasPrefix(path, "about/"):
		return "about"
	case path == "contact" || path == "support" || strings.HasPrefix(path, "contact/"),
		path == "help":
		return "contact"
	case path == "services" || path == "products" || path == "solutions" ||
		path == "pricing", strings.HasPrefix(path, "services/"),
		strings.HasPrefix(path, "products/"), strings.HasPrefix(path, "solutions/"):
		return "services"
	case path == "blog" || path == "news" || path == "articles" ||
		strings.HasPrefix(path, "blog/") || strings.HasPrefix(path, "news/") ||
		strings.HasPrefix(path, "articles/"):
		return "blog"
	default:
		return "generic"
	}
}

func hashIndex(input string, n int) int {
	h := fnv.New32a()
	h.Write([]byte(input))
	return int(h.Sum32()) % n
}

// resolveTitle returns the page title. If the content title is empty or just a
// space, the site name is used as a fallback.
func resolveTitle(title, siteName string) string {
	title = strings.TrimSpace(title)
	if title == "" {
		return siteName
	}
	return title
}
